pub mod kernel_maps;
pub mod kernel_signal;
pub mod kernel_signal_deny;
pub mod maps;
pub mod solist;

use crate::ptrace_ext::RemoteProcess;
use anyhow::{Context, Result};
use proc_maps::get_process_maps;

/// 库在目标进程中的一个内存段
pub struct LibSegment {
    pub start: usize,
    pub size: usize,
    pub prot: i32,
}

pub struct HideTarget<'a> {
    pub proc: &'a RemoteProcess,
    pub pid: i32,
    pub base_addr: usize,
    pub maps_search_name: &'a str,
    /// 注入库在目标进程 maps 中的所有段，在 hider 执行前统一收集
    pub segments: Vec<LibSegment>,
}

impl<'a> HideTarget<'a> {
    pub fn new(proc: &'a RemoteProcess, pid: i32, base_addr: usize, maps_search_name: &'a str) -> Result<Self> {
        let segments = collect_lib_segments(pid, maps_search_name)?;
        Ok(Self {
            proc,
            pid,
            base_addr,
            maps_search_name,
            segments,
        })
    }
}

pub trait Hider {
    fn name(&self) -> &'static str;
    fn apply(&self, target: &HideTarget) -> Result<bool>;
}

fn collect_lib_segments(pid: i32, lib_name: &str) -> Result<Vec<LibSegment>> {
    let maps = get_process_maps(pid).context("Failed to read remote maps")?;
    let mut segments = Vec::new();

    for map in &maps {
        let path = match map.filename() {
            Some(p) => p.to_string_lossy(),
            None => continue,
        };

        if !path.contains(lib_name) {
            continue;
        }

        let prot = {
            let mut p = 0i32;
            if map.is_read() {
                p |= libc::PROT_READ;
            }
            if map.is_write() {
                p |= libc::PROT_WRITE;
            }
            if map.is_exec() {
                p |= libc::PROT_EXEC;
            }
            p
        };

        segments.push(LibSegment {
            start: map.start(),
            size: map.size(),
            prot,
        });
    }

    Ok(segments)
}
