#include <errno.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define OBJ_FILE "xdp_firewall.bpf.o"
#define MAP_NAME "blocked_ports"
#define BPFFS_DIR "/sys/fs/bpf/xdp_fw"
#define MAP_PIN_PATH BPFFS_DIR "/" MAP_NAME

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s load <iface>\n"
		"  %s unload <iface>\n"
		"  %s block <port>\n"
		"  %s unblock <port>\n"
		"  %s list\n",
		prog, prog, prog, prog, prog);
}

static int parse_port(const char *s, __u16 *port)
{
	char *end = NULL;
	long value;

	errno = 0;
	value = strtol(s, &end, 10);
	if (errno || !end || *end != '\0' || value < 0 || value > 65535)
		return -EINVAL;

	*port = (__u16)value;
	return 0;
}

static int pin_maps(struct bpf_object *obj)
{
	int err;

	err = mkdir(BPFFS_DIR, 0755);
	if (err && errno != EEXIST)
		return -errno;

	err = bpf_object__pin_maps(obj, BPFFS_DIR);
	if (err && err != -EEXIST)
		return err;

	return 0;
}

static int cmd_load(const char *iface)
{
	struct bpf_object *obj = NULL;
	struct bpf_program *prog;
	__u32 xdp_flags = 0;
	int ifindex;
	int prog_fd;
	int err;

	ifindex = if_nametoindex(iface);
	if (!ifindex) {
		fprintf(stderr, "Unknown iface: %s\n", iface);
		return -ENOENT;
	}

	obj = bpf_object__open_file(OBJ_FILE, NULL);
	if (libbpf_get_error(obj))
		return -EINVAL;

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "bpf_object__load failed: %d\n", err);
		goto out;
	}

	err = pin_maps(obj);
	if (err) {
		fprintf(stderr, "pin maps failed: %d\n", err);
		goto out;
	}

	prog = bpf_object__find_program_by_name(obj, "xdp_firewall");
	if (!prog) {
		err = -ENOENT;
		fprintf(stderr, "Program xdp_firewall not found\n");
		goto out;
	}

	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		err = prog_fd;
		fprintf(stderr, "bpf_program__fd failed: %d\n", err);
		goto out;
	}

	err = bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL);
	if (err) {
		fprintf(stderr, "bpf_xdp_attach failed: %d\n", err);
		goto out;
	}

	printf("XDP firewall attached to %s\n", iface);

out:
	bpf_object__close(obj);
	return err;
}

static int cmd_unload(const char *iface)
{
	int ifindex;
	int err;

	ifindex = if_nametoindex(iface);
	if (!ifindex) {
		fprintf(stderr, "Unknown iface: %s\n", iface);
		return -ENOENT;
	}

	err = bpf_xdp_detach(ifindex, 0, NULL);
	if (err) {
		fprintf(stderr, "bpf_xdp_detach failed: %d\n", err);
		return err;
	}

	unlink(MAP_PIN_PATH);
	rmdir(BPFFS_DIR);
	printf("XDP firewall detached from %s\n", iface);
	return 0;
}

static int update_port(__u16 port, __u8 value)
{
	__u32 key = port;
	int map_fd;
	int err;

	map_fd = bpf_obj_get(MAP_PIN_PATH);
	if (map_fd < 0) {
		fprintf(stderr, "bpf_obj_get(%s) failed: %s\n", MAP_PIN_PATH, strerror(errno));
		return -errno;
	}

	err = bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
	close(map_fd);
	if (err) {
		fprintf(stderr, "bpf_map_update_elem failed: %s\n", strerror(errno));
		return -errno;
	}

	return 0;
}

static int cmd_block(__u16 port)
{
	int err = update_port(port, 1);

	if (!err)
		printf("Blocked destination port %u\n", port);
	return err;
}

static int cmd_unblock(__u16 port)
{
	int err = update_port(port, 0);

	if (!err)
		printf("Unblocked destination port %u\n", port);
	return err;
}

static int cmd_list(void)
{
	int map_fd;
	__u32 key;
	__u8 value;
	bool any = false;

	map_fd = bpf_obj_get(MAP_PIN_PATH);
	if (map_fd < 0) {
		fprintf(stderr, "bpf_obj_get(%s) failed: %s\n", MAP_PIN_PATH, strerror(errno));
		return -errno;
	}

	printf("Blocked destination ports:\n");
	for (key = 0; key <= 65535; key++) {
		if (bpf_map_lookup_elem(map_fd, &key, &value) == 0 && value) {
			printf("  %u\n", key);
			any = true;
		}
	}
	if (!any)
		printf("  (none)\n");

	close(map_fd);
	return 0;
}

int main(int argc, char **argv)
{
	__u16 port;
	int err = 0;

	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	if (!strcmp(argv[1], "load")) {
		if (argc != 3) {
			usage(argv[0]);
			return 1;
		}
		err = cmd_load(argv[2]);
	} else if (!strcmp(argv[1], "unload")) {
		if (argc != 3) {
			usage(argv[0]);
			return 1;
		}
		err = cmd_unload(argv[2]);
	} else if (!strcmp(argv[1], "block")) {
		if (argc != 3 || parse_port(argv[2], &port)) {
			usage(argv[0]);
			return 1;
		}
		err = cmd_block(port);
	} else if (!strcmp(argv[1], "unblock")) {
		if (argc != 3 || parse_port(argv[2], &port)) {
			usage(argv[0]);
			return 1;
		}
		err = cmd_unblock(port);
	} else if (!strcmp(argv[1], "list")) {
		if (argc != 2) {
			usage(argv[0]);
			return 1;
		}
		err = cmd_list();
	} else {
		usage(argv[0]);
		return 1;
	}

	if (err)
		return 1;
	return 0;
}