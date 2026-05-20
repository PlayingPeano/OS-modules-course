CLANG ?= clang
CC ?= cc
BPFTOOL ?= bpftool

BPF_CFLAGS := -O2 -g -Wall -Wno-error -Wno-missing-declarations -target bpf -D__TARGET_ARCH_x86
USER_CFLAGS := -O2 -g -Wall -Wextra
USER_LDLIBS := -lbpf -lelf -lz

.PHONY: all clean

all: vmlinux.h bpf_lsm_fw.bpf.o bpf_lsm_fw_loader

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

bpf_lsm_fw.bpf.o: bpf_lsm_fw.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

bpf_lsm_fw_loader: bpf_lsm_fw_loader.c
	$(CC) $(USER_CFLAGS) $< -o $@ $(USER_LDLIBS)

clean:
	rm -f bpf_lsm_fw.bpf.o bpf_lsm_fw_loader vmlinux.h
