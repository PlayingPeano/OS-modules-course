CLANG ?= clang
CC ?= cc

BPF_CFLAGS := -O2 -g -Wall -Werror -target bpf -D__TARGET_ARCH_x86
USER_CFLAGS := -O2 -g -Wall -Wextra
USER_LDLIBS := -lbpf -lelf -lz

.PHONY: all clean

all: xdp_firewall.bpf.o xdp_firewall_loader

xdp_firewall.bpf.o: xdp_firewall.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

xdp_firewall_loader: xdp_firewall_loader.c
	$(CC) $(USER_CFLAGS) $< -o $@ $(USER_LDLIBS)

clean:
	rm -f xdp_firewall.bpf.o xdp_firewall_loader
