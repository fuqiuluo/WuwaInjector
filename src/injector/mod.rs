mod dlopen;
mod memfd;

use crate::hider::{HideTarget, Hider};
use crate::ptrace_ex::{find_remote_lib_base, find_remote_symbol, remote_close, remote_dlsym};
use crate::ptrace_ext::RemoteProcess;
use anyhow::{Result, bail};
use log::{debug, info, warn};
use proc_maps::get_process_maps;
use std::path::Path;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

/// 注入库的内存映射区域
#[derive(Debug, Clone, serde::Serialize)]
pub struct LibMemoryRegion {
    #[serde(serialize_with = "serialize_hex")]
    pub start: usize,
    #[serde(serialize_with = "serialize_hex")]
    pub end: usize,
    pub perms: String,
    #[serde(serialize_with = "serialize_hex")]
    pub offset: usize,
    pub path: String,
}

/// 注入结果
#[derive(Debug, serde::Serialize)]
pub struct InjectedInfo {
    #[serde(serialize_with = "serialize_hex")]
    pub dl_handle: usize,
    #[serde(serialize_with = "serialize_hex")]
    pub base_addr: usize,
    pub lib_size: u64,
    pub memory_regions: Vec<LibMemoryRegion>,
    #[serde(skip)]
    pub hider_results: Vec<(String, bool)>,
}

fn serialize_hex<S>(val: &usize, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    s.serialize_str(&format!("0x{:x}", val))
}

impl InjectedInfo {
    pub fn is_valid(&self) -> bool {
        self.dl_handle != 0 && self.base_addr != 0
    }
}

/// 加载结果（dlopen 返回的信息）
pub struct LoadResult {
    pub handle: usize,
    pub base_addr: usize,
    pub maps_search_name: String,
    pub memfd_fd: Option<i32>,
}

/// 注入器 trait：不同的加载方式（dlopen / memfd）
pub trait Injector {
    fn load(&self, proc: &RemoteProcess, lib_path: &str) -> Result<LoadResult>;
}

/// 注入 so 到目标进程
pub fn inject(
    pid: i32,
    lib_path: &str,
    use_memfd: bool,
    hiders: &[Box<dyn Hider>],
    jni_key: Option<usize>,
) -> Result<InjectedInfo> {
    info!("Injecting {} into pid {}", lib_path, pid);

    if !Path::new(lib_path).exists() {
        bail!("Library not found: {lib_path}");
    }

    let stop_result = kill(Pid::from_raw(pid), Signal::SIGSTOP);
    let stopped = stop_result.is_ok();
    if stopped {
        debug!("Stopped target process");
    } else {
        warn!("Failed to stop target process, continuing anyway");
    }

    let mut proc = RemoteProcess::attach(pid)?;
    info!("Attached to pid {}", pid);

    let caller = find_remote_lib_base(pid, "libRS.so")?
        .unwrap_or(0);
    if caller != 0 {
        debug!("default_caller set to {:#x}", caller);
        proc.set_default_caller(caller);
    } else {
        warn!("Could not find a suitable default_caller, remote calls may fail");
    }

    // Patch __cxa_atexit 为立即返回 0，防止注入库的全局对象析构函数被注册
    let cxa_patch = patch_cxa_atexit(&proc, pid);
    if let Err(ref e) = cxa_patch {
        warn!("Failed to patch __cxa_atexit: {e:#}, continuing without patch");
    }

    let result = do_inject(&proc, pid, lib_path, use_memfd, hiders);

    if let Ok(ref info) = result {
        if info.is_valid() {
            match remote_dlsym(&proc, info.dl_handle, "JNI_OnLoad") {
                Ok(ep) if ep != 0 => {
                    let key = jni_key.unwrap_or(0);
                    info!("Calling JNI_OnLoad at {:#x} (base={:#x}, key={:#x})", ep, info.base_addr, key);
                    if let Err(e) = proc.call_function(ep, &[info.base_addr, key]) {
                        warn!("JNI_OnLoad call failed: {e:#}");
                    }
                }
                _ => debug!("No JNI_OnLoad symbol found, skipping"),
            }
        }
    }

    // 恢复 __cxa_atexit 原始字节
    if let Ok((addr, original)) = cxa_patch {
        if let Err(e) = proc.write_mem_io(addr, &original) {
            warn!("Failed to restore __cxa_atexit: {e:#}");
        } else {
            debug!("Restored __cxa_atexit at {:#x}", addr);
        }
    }

    proc.detach()?;
    info!("Detached from pid {}", pid);

    if stopped {
        let _ = kill(Pid::from_raw(pid), Signal::SIGCONT);
        debug!("Resumed target process");
    }

    result
}

fn do_inject(
    proc: &RemoteProcess,
    pid: i32,
    lib_path: &str,
    use_memfd: bool,
    hiders: &[Box<dyn Hider>],
) -> Result<InjectedInfo> {
    let injector: Box<dyn Injector> = if use_memfd {
        info!("Using memfd injection");
        Box::new(memfd::MemfdInjector)
    } else {
        info!("Using dlopen injection");
        Box::new(dlopen::DlopenInjector)
    };

    let load = injector.load(proc, lib_path)?;
    info!("dlopen returned handle: {:#x}", load.handle);

    if load.base_addr != 0 {
        info!("Library loaded at base: {:#x}", load.base_addr);
    } else {
        warn!("Could not find library base address in maps");
    }

    let (memory_regions, lib_size) = collect_lib_regions(pid, &load.maps_search_name);

    let mut hider_results = Vec::new();
    if load.base_addr != 0 {
        let target = HideTarget::new(proc, pid, load.base_addr, &load.maps_search_name)?;
        for hider in hiders {
            let name = hider.name().to_string();
            match hider.apply(&target) {
                Ok(true) => {
                    info!("{name}: succeeded");
                    hider_results.push((name, true));
                }
                Ok(false) => {
                    warn!("{name}: failed");
                    hider_results.push((name, false));
                }
                Err(e) => {
                    warn!("{name} error: {e:#}");
                    hider_results.push((name, false));
                }
            }
        }
    }

    if let Some(fd) = load.memfd_fd {
        if let Err(e) = remote_close(proc, fd) {
            warn!("Failed to close memfd fd: {e:#}");
        }
    }

    Ok(InjectedInfo {
        dl_handle: load.handle,
        base_addr: load.base_addr,
        lib_size,
        memory_regions,
        hider_results,
    })
}

fn collect_lib_regions(pid: i32, search_name: &str) -> (Vec<LibMemoryRegion>, u64) {
    let maps = match get_process_maps(pid) {
        Ok(m) => m,
        Err(_) => return (Vec::new(), 0),
    };

    let mut regions = Vec::new();
    let mut total_size: u64 = 0;

    for map in &maps {
        let path = match map.filename() {
            Some(p) => p.to_string_lossy(),
            None => continue,
        };
        if !path.contains(search_name) {
            continue;
        }

        let perms = format!(
            "{}{}{}",
            if map.is_read() { "r" } else { "-" },
            if map.is_write() { "w" } else { "-" },
            if map.is_exec() { "x" } else { "-" },
        );

        total_size += map.size() as u64;
        regions.push(LibMemoryRegion {
            start: map.start(),
            end: map.start() + map.size(),
            perms,
            offset: map.offset,
            path: path.to_string(),
        });
    }

    (regions, total_size)
}

/// Patch __cxa_atexit 为立即返回 0（MOV W0, WZR + RET），返回地址和原始字节用于后续恢复
fn patch_cxa_atexit(proc: &RemoteProcess, pid: i32) -> Result<(usize, Vec<u8>)> {
    unsafe extern "C" {
        safe fn __cxa_atexit(
            f: unsafe extern "C" fn(*mut libc::c_void),
            arg: *mut libc::c_void,
            dso: *mut libc::c_void,
        ) -> libc::c_int;
    }
    let local_cxa = __cxa_atexit as usize;
    let remote_cxa = find_remote_symbol(pid, "libc.so", local_cxa)?;

    let original = proc.read_mem(remote_cxa, 8)?;

    // MOV W0, WZR (0x2A1F03E0) + RET (0xD65F03C0)
    let patch: [u8; 8] = [0xE0, 0x03, 0x1F, 0x2A, 0xC0, 0x03, 0x5F, 0xD6];
    proc.write_mem_io(remote_cxa, &patch)?;

    info!("Patched __cxa_atexit at {:#x}", remote_cxa);
    Ok((remote_cxa, original))
}
