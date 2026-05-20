#include <arpa/inet.h>
#include <errno.h>
#include <linux/limits.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define OBJ_FILE "bpf_lsm_fw.bpf.o"
#define PROG_NAME "lsm_socket_connect"
#define MAP_NAME "blocked_rules"
#define BPFFS_DIR "/sys/fs/bpf/bpf_lsm_fw"
#define MAP_PIN_PATH BPFFS_DIR "/" MAP_NAME
#define LINK_PIN_PATH BPFFS_DIR "/socket_connect_link"
#define EXE_PATH_MAX 4096

struct rule_key {
	__u64 exe_ino;
	__u64 exe_dev;
	__u32 dst_ip;
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s load\n"
		"  %s unload\n"
		"  %s deny <exe_path> <ipv4>\n"
		"  %s allow <exe_path> <ipv4>\n"
		"  %s list\n",
		prog, prog, prog, prog, prog);
}

static int ensure_bpffs_dir(void)
{
	if (mkdir(BPFFS_DIR, 0755) == 0)
		return 0;
	if (errno == EEXIST)
		return 0;
	perror("mkdir BPFFS_DIR");
	return -errno;
}

static int cmd_load(void)
{
	struct bpf_object *obj = NULL;
	struct bpf_program *prog;
	struct bpf_map *rules_map;
	struct bpf_link *link = NULL;
	int map_fd;
	int err;

	err = ensure_bpffs_dir();
	if (err)
		return err;

	if (access(LINK_PIN_PATH, F_OK) == 0) {
		fprintf(stderr, "LSM firewall appears already loaded (%s exists)\n", LINK_PIN_PATH);
		return -EEXIST;
	}

	unlink(MAP_PIN_PATH);

	obj = bpf_object__open_file(OBJ_FILE, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "bpf_object__open_file(%s) failed\n", OBJ_FILE);
		return -EINVAL;
	}

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "bpf_object__load failed: %d\n", err);
		goto out;
	}

	rules_map = bpf_object__find_map_by_name(obj, MAP_NAME);
	if (!rules_map) {
		err = -ENOENT;
		fprintf(stderr, "map %s not found\n", MAP_NAME);
		goto out;
	}
	map_fd = bpf_map__fd(rules_map);
	if (map_fd < 0) {
		err = map_fd;
		fprintf(stderr, "bpf_map__fd(%s) failed: %d\n", MAP_NAME, err);
		goto out;
	}

	err = bpf_obj_pin(map_fd, MAP_PIN_PATH);
	if (err == -EEXIST) {
		unlink(MAP_PIN_PATH);
		err = bpf_obj_pin(map_fd, MAP_PIN_PATH);
	}
	if (err) {
		fprintf(stderr, "pin map %s failed: %d\n", MAP_NAME, err);
		goto out;
	}

	prog = bpf_object__find_program_by_name(obj, PROG_NAME);
	if (!prog) {
		err = -ENOENT;
		fprintf(stderr, "program %s not found\n", PROG_NAME);
		goto out;
	}

	link = bpf_program__attach_lsm(prog);
	if (libbpf_get_error(link)) {
		err = -EINVAL;
		link = NULL;
		fprintf(stderr, "bpf_program__attach_lsm failed\n");
		goto out;
	}

	err = bpf_link__pin(link, LINK_PIN_PATH);
	if (err) {
		fprintf(stderr, "bpf_link__pin failed: %d\n", err);
		goto out;
	}

	printf("LSM firewall loaded and pinned in %s\n", BPFFS_DIR);

out:
	bpf_link__destroy(link);
	bpf_object__close(obj);
	return err;
}

static int cmd_unload(void)
{
	struct bpf_link *link;
	int err;

	link = bpf_link__open(LINK_PIN_PATH);
	if (libbpf_get_error(link)) {
		fprintf(stderr, "bpf_link__open failed. Is program loaded?\n");
		return -ENOENT;
	}

	err = bpf_link__detach(link);
	if (err && err != -EOPNOTSUPP)
		fprintf(stderr, "bpf_link__detach failed: %d\n", err);

	bpf_link__destroy(link);
	unlink(LINK_PIN_PATH);
	unlink(MAP_PIN_PATH);
	rmdir(BPFFS_DIR);
	printf("LSM firewall unloaded\n");
	if (err == -EOPNOTSUPP)
		return 0;
	return err;
}

static int open_map(void)
{
	int map_fd = bpf_obj_get(MAP_PIN_PATH);

	if (map_fd < 0)
		fprintf(stderr, "bpf_obj_get(%s) failed: %s\n", MAP_PIN_PATH, strerror(errno));
	return map_fd;
}

static int parse_rule_key(const char *exe_path, const char *ipv4, struct rule_key *key)
{
	struct in_addr addr = {};
	struct stat st = {};
	char resolved[EXE_PATH_MAX] = {};
	size_t exe_path_len;

	exe_path_len = strnlen(exe_path, EXE_PATH_MAX + 1);
	if (exe_path_len == 0) {
		fprintf(stderr, "empty executable path is not allowed\n");
		return -EINVAL;
	}
	if (exe_path_len > EXE_PATH_MAX) {
		fprintf(stderr, "executable path is too long (max %d bytes)\n", EXE_PATH_MAX);
		return -ENAMETOOLONG;
	}

	if (!realpath(exe_path, resolved)) {
		fprintf(stderr, "realpath(%s) failed: %s\n", exe_path, strerror(errno));
		return -EINVAL;
	}

	if (inet_pton(AF_INET, ipv4, &addr) != 1) {
		fprintf(stderr, "invalid IPv4 address: %s\n", ipv4);
		return -EINVAL;
	}

	if (stat(resolved, &st) != 0) {
		fprintf(stderr, "stat(%s) failed: %s\n", resolved, strerror(errno));
		return -EINVAL;
	}

	memset(key, 0, sizeof(*key));
	key->exe_ino = st.st_ino;
	key->exe_dev = ((__u64)major(st.st_dev) << 20) | (__u64)minor(st.st_dev);
	key->dst_ip = addr.s_addr;
	return 0;
}

static int cmd_deny(const char *exe_path, const char *ipv4)
{
	struct rule_key key;
	__u8 value = 1;
	int map_fd, err;

	err = parse_rule_key(exe_path, ipv4, &key);
	if (err)
		return err;

	map_fd = open_map();
	if (map_fd < 0)
		return -errno;

	err = bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
	close(map_fd);
	if (err) {
		fprintf(stderr, "bpf_map_update_elem failed: %s\n", strerror(errno));
		return -errno;
	}

	printf("Rule added: deny exe='%s' -> %s (dev=%llu ino=%llu)\n",
	       exe_path, ipv4, key.exe_dev, key.exe_ino);
	return 0;
}

static int cmd_allow(const char *exe_path, const char *ipv4)
{
	struct rule_key key;
	int map_fd, err;

	err = parse_rule_key(exe_path, ipv4, &key);
	if (err)
		return err;

	map_fd = open_map();
	if (map_fd < 0)
		return -errno;

	err = bpf_map_delete_elem(map_fd, &key);
	close(map_fd);
	if (err) {
		fprintf(stderr, "bpf_map_delete_elem failed: %s\n", strerror(errno));
		return -errno;
	}

	printf("Rule removed: allow exe='%s' -> %s (dev=%llu ino=%llu)\n",
	       exe_path, ipv4, key.exe_dev, key.exe_ino);
	return 0;
}

static int cmd_list(void)
{
	struct rule_key cur = {};
	struct rule_key next = {};
	struct rule_key *key_ptr = NULL;
	__u8 value;
	int map_fd;
	char ip_buf[INET_ADDRSTRLEN];
	struct in_addr addr;
	int has_any = 0;

	map_fd = open_map();
	if (map_fd < 0)
		return -errno;

	printf("Blocked rules (exe_dev:exe_ino -> ipv4):\n");
	while (bpf_map_get_next_key(map_fd, key_ptr, &next) == 0) {
		if (bpf_map_lookup_elem(map_fd, &next, &value) == 0 && value) {
			addr.s_addr = next.dst_ip;
			if (!inet_ntop(AF_INET, &addr, ip_buf, sizeof(ip_buf)))
				snprintf(ip_buf, sizeof(ip_buf), "invalid");
			printf("  %llu:%llu -> %s\n", next.exe_dev, next.exe_ino, ip_buf);
			has_any = 1;
		}
		cur = next;
		key_ptr = &cur;
	}

	if (!has_any)
		printf("  (none)\n");

	close(map_fd);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	if (!strcmp(argv[1], "load")) {
		if (argc != 2) {
			usage(argv[0]);
			return 1;
		}
		return cmd_load() ? 1 : 0;
	}

	if (!strcmp(argv[1], "unload")) {
		if (argc != 2) {
			usage(argv[0]);
			return 1;
		}
		return cmd_unload() ? 1 : 0;
	}

	if (!strcmp(argv[1], "deny")) {
		if (argc != 4) {
			usage(argv[0]);
			return 1;
		}
		return cmd_deny(argv[2], argv[3]) ? 1 : 0;
	}

	if (!strcmp(argv[1], "allow")) {
		if (argc != 4) {
			usage(argv[0]);
			return 1;
		}
		return cmd_allow(argv[2], argv[3]) ? 1 : 0;
	}

	if (!strcmp(argv[1], "list")) {
		if (argc != 2) {
			usage(argv[0]);
			return 1;
		}
		return cmd_list() ? 1 : 0;
	}

	usage(argv[0]);
	return 1;
}
