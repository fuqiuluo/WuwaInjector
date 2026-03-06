# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Android aarch64 process injector written in Rust. Monitors process launches via `liblog.so` event logs (`am_proc_start`), then uses ptrace to inject shared libraries into target processes. Requires root on Android 10+ (API 29).

## Build Commands

```bash
# Full build + push to device (requires ANDROID_NDK_PATH env var)
bash scripts/build.sh

# Compile only (release, aarch64)
cargo build --target aarch64-linux-android --release

# Check/lint without building
cargo check --target aarch64-linux-android
```

The build requires:
- `ANDROID_NDK_PATH` pointing to the NDK root
- `mold` linker (set via RUSTFLAGS in `scripts/build.sh`)
- Rust target `aarch64-linux-android` installed

RUSTFLAGS used: `-C link-arg=-fuse-ld=mold -C target-feature=+neon`

There are no tests in this project.

## Architecture

### Injection Pipeline (orchestrated in `src/injector/mod.rs`)

1. **Process monitoring** (`src/proc_monitor.rs`) — Reads Android event logs from `liblog.so` (loaded dynamically via xdl-rs) to detect `am_proc_start` events. Blocks until a matching package name is found.

2. **ptrace attach** (`src/ptrace_ext.rs`) — `RemoteProcess` wraps ptrace attach/detach, register get/set (via `PTRACE_GETREGSET`/`SETREGSET`), remote memory read/write (via `process_vm_readv`/`writev` and `/proc/pid/mem`), and remote function calling (manipulates aarch64 registers, sets LR to a `default_caller` address for controlled return via SIGSEGV/SIGILL).

3. **Remote function helpers** (`src/ptrace_ex.rs`) — Higher-level operations built on `RemoteProcess`: `remote_mmap`, `remote_munmap`, `remote_dlsym`, `remote_syscall`, `remote_close`. Uses local-to-remote address translation (local_func - local_base + remote_base).

4. **Library loading** — Two strategies implementing the `Injector` trait:
   - `src/injector/dlopen.rs` — Standard `dlopen` injection
   - `src/injector/memfd.rs` — `memfd_create` + `android_dlopen_ext`, bypasses path restrictions

5. **Trace hiding** (`src/hider/`) — Stackable hiders implementing the `Hider` trait, applied after injection:
   - `maps.rs` — Userspace remap to anonymous mappings, hides from `/proc/pid/maps`
   - `solist.rs` — Unlinks soinfo from linker's linked list (offsets vary by Android version)
   - `kernel_maps.rs` — VFS-level maps filtering via WuWa kernel driver
   - `kernel_signal.rs` — SIGPROF filtering via WuWa kernel driver

6. **JNI_OnLoad call** — After injection + hiding, calls the payload's `JNI_OnLoad(base_addr, key)` remotely, then detaches and resumes the target.

### Workspace Crates

- **`xdl-rs/`** — Rust bindings for [xDL](https://github.com/nicedayzhu/xDL) (Android dynamic linker enhancement). Uses bindgen + cc for C bindings. Used by `proc_monitor` to load `liblog.so`.
- **`android-properties/`** — Android system property access. Used to clear log tag filters before monitoring.

### WuWa Driver SDK (`src/wuwa.rs`)

Userspace SDK for the [WuWa kernel module](https://github.com/fuqiuluo/android-wuwa). Communicates via a hijacked socket protocol family discovered by probing AF_* families. Provides physical memory read/write, DMA buffer operations, page table manipulation, and process-level maps/signal filtering. Used by the kernel-level hiders.

## Code Conventions

- Rust edition 2024 (main crate), 2021 (xdl-rs)
- rustfmt: `max_width = 120`, `use_try_shorthand = true`, `use_field_init_shorthand = true`
- Comments and user-facing strings are in Chinese
- Logging via `env_logger` / `log` crate; run with `RUST_LOG=debug` for verbose output
- Error handling uses `anyhow` throughout
- CLI parsing via `clap` derive API
