## Running VM
### Install limactl
`brew install lima`

### Running lima VM
`limactl start --name=ebpf-lima-vm ./ubuntu-lts-ebpf.yaml`

## Running actual eBPF program

### Building userspace
`cargo build` (you'll most likely need extra dependencies such as `build-essentials`. Unfortunately there was too many of them so I didn't list them in one place.)

### Running userspace program
`RUST_LOG=info cargo xtask run`

## Useful resources:

### [lima](https://github.com/lima-vm/)

Makes it easier to set up linux VM for playing with eBPF/XDP. Attached to this repo there is `ubuntu-lts-ebpf.yaml` which contains the most basic toolchain for ebpf

### [bpf-linker](https://github.com/aya-rs/bpf-linker)

BPF static linker, uses llvm. If using aarch64 (e.g. Linux VM on M-series Apple devices), you need external LLVM.
Recommended way of obtaining external LLVM is via https://apt.llvm.org/.

### [aya](https://aya-rs.dev/book/)

Library to build eBPF programs (and attach them to an interface).

### [bpftool](https://github.com/libbpf/bpftool)

Allows to list currently attached bpf programs (`sudo bpftool prog list`). Needs to be built from src, as there is no pre-built version in apt.
