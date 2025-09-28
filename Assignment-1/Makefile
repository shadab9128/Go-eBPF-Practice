BPF_OBJ = xdp_drop_port.bpf.o
BPF_SRC = xdp_drop_port.bpf.c
BPF_SKEL = xdp_drop_port.skel.h

USER_SRC = load_xdp.c
USER_BIN = load_xdp

CLANG = clang
LIBBPF_INCLUDE = /usr/local/include/bpf
LIBBPF_LIB = /usr/local/lib64

all: $(BPF_OBJ) $(BPF_SKEL) $(USER_BIN)

$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) -O2 -g -target bpf -c $< -o $@

$(BPF_SKEL): $(BPF_OBJ)
	/usr/local/bin/bpftool gen skeleton $< > $@

$(USER_BIN): $(USER_SRC) $(BPF_SKEL)
	gcc -O2 -I$(LIBBPF_INCLUDE) -L$(LIBBPF_LIB) -Wl,-rpath=$(LIBBPF_LIB) \
	-o $@ $(USER_SRC) -lbpf -lelf -lz

clean:
	rm -f $(BPF_OBJ) $(USER_BIN) $(BPF_SKEL)

