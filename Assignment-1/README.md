# XDP eBPF TCP Port Dropper

This project implements an **eBPF XDP program** that drops TCP packets on a specified port. By default, it drops port `4040`, but the port can also be **configured from userspace** when loading the program.

---

## Features

- Drops TCP packets on a configurable port using XDP.
- Userspace program (`load_xdp`) allows dynamic selection of the port.
- Uses `libbpf` and BPF skeletons for clean, modern eBPF workflow.
- Works on AWS EC2 or Linux systems with kernel 6.14+.

---
## Prerequisites

- Linux kernel >= 5.7 (tested on 6.14)
- `clang` and `llvm` toolchain
- `libbpf` installed (`/usr/local/include/bpf` and `/usr/local/lib64`)
- `bpftool` installed and accessible
- `gcc` for compiling userspace program

---

## Build Instructions

1.  Compile the eBPF program, generate skeleton, and build userspace loader:

```bash
make clean && make
```
2. Load XDP program on interface
```bash
sudo ./load_xdp <Interface_name>
```
3. Load XDP program on interface with custome port(usersapce)
```bash
sudo ./load_xdp <Interface_name> <port>
```
- Like your Interface name is eth0 and port is 8080
    then it will be sudo ./load_xdp eth0 8080
## Verification

1. Check XDP program attachment:
```bash
sudo ip link show dev etho
sudo bpftool net show dev etho
```

2. Check BPF maps:
```bash
sudo bpftool map show
```
3. Test blocked TCP port using curl and tcpdump:
```bash
sudo tcpdump -i eth0 tcp port 4040
curl http://<SERVER_IP>:4040
```
-Connection should fail (dropped by XDP).
4. Test allowed port (e.g., 80):
```bash
curl http://<SERVER_IP>:80
```
- Connection should succeed.
## Cleanup
```bash
sudo ip link set dev eth0 xdp off
```



