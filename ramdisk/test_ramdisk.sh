#!/usr/bin/env bash
set -euo pipefail

MOD="ramdisk"
DEV="/dev/myblock"
MNT="/tmp/myramdisk-mnt"
IMG_SIZE_MB="${IMG_SIZE_MB:-256}"

cleanup() {
  set +e
  if mountpoint -q "$MNT"; then
    sudo umount "$MNT"
  fi
  sudo rmmod "$MOD" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[1] build module"
make modules

echo "[2] load module (disk_mb=$IMG_SIZE_MB)"
sudo insmod "./${MOD}.ko" disk_mb="$IMG_SIZE_MB" verbose=0

echo "[3] ensure block node exists"
if [[ ! -b "$DEV" ]]; then
  MAJOR="$(awk '$2=="mybdev"{print $1}' /proc/devices)"
  if [[ -z "$MAJOR" ]]; then
    echo "mybdev major not found in /proc/devices"
    exit 1
  fi
  sudo mknod "$DEV" b "$MAJOR" 0
fi

echo "[4] ext4: mkfs, mount, write, sync, remount, verify"
sudo mkfs.ext4 -F "$DEV" >/dev/null
sudo mkdir -p "$MNT"
sudo mount "$DEV" "$MNT"
echo "hello ext4 $(date -Is)" | sudo tee "$MNT/hello.txt" >/dev/null
sudo dd if=/dev/urandom of="$MNT/blob.bin" bs=1M count=8 conv=fdatasync status=none
sudo sync
SUM1="$(sudo sha256sum "$MNT/blob.bin" | awk '{print $1}')"
sudo umount "$MNT"
sudo mount "$DEV" "$MNT"
SUM2="$(sudo sha256sum "$MNT/blob.bin" | awk '{print $1}')"
[[ "$SUM1" == "$SUM2" ]] || { echo "ext4 checksum mismatch"; exit 1; }
sudo umount "$MNT"

echo "[5] btrfs: mkfs, mount, write, sync, remount, verify"
sudo mkfs.btrfs -f "$DEV" >/dev/null
sudo mount "$DEV" "$MNT"
sudo dd if=/dev/urandom of="$MNT/blob2.bin" bs=4K count=8192 oflag=direct conv=fdatasync status=none
sudo sync
SUM3="$(sudo sha256sum "$MNT/blob2.bin" | awk '{print $1}')"
sudo umount "$MNT"
sudo mount "$DEV" "$MNT"
SUM4="$(sudo sha256sum "$MNT/blob2.bin" | awk '{print $1}')"
[[ "$SUM3" == "$SUM4" ]] || { echo "btrfs checksum mismatch"; exit 1; }
sudo umount "$MNT"

echo "[6] raw block I/O test with dd (direct+sync)"
sudo dd if=/dev/zero of="$DEV" bs=1M count=8 oflag=direct,sync status=progress
sudo dd if="$DEV" of=/tmp/myramdisk.raw bs=1M count=8 iflag=direct status=none

echo "[7] badblocks write-read pass (destructive)"
sudo badblocks -wsv "$DEV"

echo "[8] kernel log tail"
sudo dmesg | tail -n 80

echo "OK: ramdisk tests passed"
