BPF_CLANG ?= clang
BPF_CFLAGS ?= -O2 -g -Wall -target bpf

all: ebpf_guard.bpf.o

ebpf_guard.bpf.o: ebpf_guard.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f ebpf_guard.bpf.o
