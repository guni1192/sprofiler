# Sprofiler

[![CircleCI](https://circleci.com/gh/guni1192/sprofiler/tree/main.svg?style=svg)](https://circleci.com/gh/guni1192/sprofiler/tree/main)

Sprofiler generate seccomp profiles for OCI Container

## Requirement

**sprofiler-bpf**
- Ubuntu >= 20.10
- Podman >= 3.0
- Cgroup v2
- `CONFIG_DEBUG_INFO_BTF=y`

## Getting Started

### Build

```
sudo apt install libelf-dev libgcc-s1 libbpf-dev clang curl linux-tools-generic linux-tools-common make pkg-config podman
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./sprofiler/src/bpf/vmlinux.h
cargo libbpf make
```

### Run

```
# Run container with dynamic analyzer
sudo podman run \
    --annotation "io.sprofiler.output_seccomp_profile_path=$(pwd)/seccomp-profile.json" \
    ghcr.io/sai-lab/hello-c:latest

# Run container enable no-new-privileges with dynamic analyzer 
sudo podman run --security-opt=no-new-privileges \
    --annotation "io.sprofiler.output_seccomp_profile_path=$(pwd)/seccomp-profile.json" \
    ghcr.io/sai-lab/hello-c:latest

# check
sudo podman run --rm --security-opt seccomp=$(pwd)/seccomp-profile.json ghcr.io/sai-lab/hello-c:latest
```

## Testing

```
cargo libbpf make
sudo -E ./target/debug/sprofiler-test ./integration_test/sprofiler-test.yaml
```

## Vagrant for develop environment

```
vagrant up --provider=libvirt
```

## License

Apache License Version 2.0
