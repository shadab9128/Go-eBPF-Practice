#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "xdp_drop_port.skel.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <iface> [port]\n", argv[0]);
        return 1;
    }

    const char *ifname = argv[1];
    int drop_port = argc > 2 ? atoi(argv[2]) : 4040;

    struct xdp_drop_port_bpf *skel;
    int err;

    skel = xdp_drop_port_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF skeleton\n");
        return 1;
    }

    // Correct: key is __u32, value is __u16
    __u32 key = 0;
    __u16 val = drop_port;

    err = bpf_map__update_elem(
        bpf_object__find_map_by_name(skel->obj, "drop_port_map"),
        &key, sizeof(key),
        &val, sizeof(val),
        BPF_ANY
    );
    if (err) {
        fprintf(stderr, "Failed to update map: %d\n", err);
        xdp_drop_port_bpf__destroy(skel);
        return 1;
    }

    err = xdp_drop_port_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach XDP program: %d\n", err);
        xdp_drop_port_bpf__destroy(skel);
        return 1;
    }

    printf("XDP program loaded, dropping port %d\n", drop_port);

    while (1) sleep(1);

    xdp_drop_port_bpf__detach(skel);
    xdp_drop_port_bpf__destroy(skel);
    return 0;
}

