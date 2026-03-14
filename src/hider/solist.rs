use crate::ptrace_ext::RemoteProcess;
use anyhow::{Context, Result, bail, anyhow};
use log::{debug, info, warn};
use proc_maps::get_process_maps;
use xdl_rs::safe::{XdlLibrary, XdlOpenFlags};

use super::{HideTarget, Hider};

/// 修改 linker soinfo 链表隐藏库在 linker 内部的加载痕迹
pub struct SolistHider;

impl Hider for SolistHider {
    fn name(&self) -> &'static str {
        "solist"
    }

    fn apply(&self, target: &HideTarget) -> Result<bool> {
        let maps = get_process_maps(target.pid).context("Failed to read maps")?;
        let linker_info = maps
            .iter()
            .find(|m| {
                m.filename()
                    .map(|p| p.to_string_lossy().contains("/linker"))
                    .unwrap_or(false)
            })
            .context("linker not found in remote maps")?;

        let remote_linker_base = linker_info.start();
        let linker_path = linker_info
            .filename()
            .context("linker has no path")?
            .to_string_lossy()
            .to_string();

        debug!("hide_solist: remote linker at {:#x} path={}", remote_linker_base, linker_path);

        let solist_sym_offset = find_linker_symbol_offset(&linker_path, "__dl__ZL6solist")?;
        let sonext_sym_offset = find_linker_symbol_offset(&linker_path, "__dl__ZL6sonext")?;
        debug!("hide_solist: solist_offset={:#x} sonext_offset={:#x}", solist_sym_offset, sonext_sym_offset);

        let solist_addr = remote_linker_base + solist_sym_offset;
        let sonext_addr = remote_linker_base + sonext_sym_offset;

        let solist_buf = target.proc.read_mem(solist_addr, 8)?;
        let solist: usize = usize::from_ne_bytes(solist_buf.try_into().unwrap());

        let sonext_buf = target.proc.read_mem(sonext_addr, 8)?;
        let sonext: usize = usize::from_ne_bytes(sonext_buf.try_into().unwrap());

        debug!("hide_solist: solist={:#x} sonext={:#x}", solist, sonext);

        let (si_base_offset, si_next_offset) = get_soinfo_offsets(target.proc, solist, sonext)?;
        info!("hide_solist: soinfo offsets: base={:#x} next={:#x}", si_base_offset, si_next_offset);

        let mut trav = solist;
        let mut prev = 0usize;
        let mut count = 0;

        while trav != 0 {
            let base_buf = target.proc.read_mem(trav + si_base_offset, 8)?;
            let base: usize = usize::from_ne_bytes(base_buf.try_into().unwrap());
            count += 1;

            if base == target.base_addr {
                debug!("hide_solist: found target at soinfo {:#x} (#{count})", trav);
                break;
            }

            prev = trav;
            let next_buf = target.proc.read_mem(trav + si_next_offset, 8)?;
            trav = usize::from_ne_bytes(next_buf.try_into().unwrap());
        }

        debug!("hide_solist: traversed {count} soinfo nodes");

        if trav == 0 {
            warn!("hide_solist: target base {:#x} not found in solist", target.base_addr);
            return Ok(false);
        }

        let next_buf = target.proc.read_mem(trav + si_next_offset, 8)?;
        let next: usize = usize::from_ne_bytes(next_buf.try_into().unwrap());

        if prev == 0 {
            // android_dlopen_ext 通常把新库插到 solist 头部，直接更新头指针
            target.proc.write_mem_io(solist_addr, &next.to_ne_bytes())?;
            info!("hide_solist: target is solist head, updated solist to {:#x}", next);
        } else {
            target.proc.write_mem_io(prev + si_next_offset, &next.to_ne_bytes())?;
            info!("hide_solist: unlinked soinfo {:#x} (base={:#x}) from solist", trav, target.base_addr);
        }

        if trav == sonext {
            // sonext 是 tail 指针，目标在头时新 tail = next，否则新 tail = prev
            let new_sonext = if prev == 0 { next } else { prev };
            target.proc.write_mem_io(sonext_addr, &new_sonext.to_ne_bytes())?;
            info!("hide_solist: updated sonext to {:#x}", new_sonext);
        }

        // 清零 soinfo 识别字段，防止 ACE 直接扫描 linker 堆找到残留 soinfo：
        //   phdr @ +0x00，phnum @ +0x08，base_ @ +si_base_offset，size_ @ +0x18
        // dynamic_/fini_array_ 等函数指针保留，避免进程退出时 linker 解引用崩溃
        let zero = 0usize.to_ne_bytes();
        for &off in &[0x00usize, 0x08, si_base_offset, 0x18] {
            if let Err(e) = target.proc.write_mem_io(trav + off, &zero) {
                warn!("hide_solist: failed to zero soinfo+{:#x}: {e:#}", off);
            }
        }
        info!("hide_solist: zeroed soinfo phdr/base/size at {:#x}", trav);

        Ok(true)
    }
}

fn find_linker_symbol_offset(linker_path: &str, symbol: &str) -> Result<usize> {
    let lib = XdlLibrary::open(linker_path, XdlOpenFlags::TryForceLoad)
        .map_err(|e| anyhow!("xdl_open({linker_path}) failed: {e}"))?;

    let info = lib.info().map_err(|e| anyhow!("xdl_info failed: {e}"))?;
    let base = info.base_addr as usize;

    let sym = lib
        .dsym(symbol)
        .map_err(|e| anyhow!("xdl_dsym({symbol}) failed: {e}"))?
        .context(format!("Symbol {symbol} not found in {linker_path}"))?;

    let addr = sym.addr as usize;
    Ok(addr - base)
}

struct RemoteElfInfo {
    base: usize,
    load_size: usize,
    dynamic: usize,
    strtab: usize,
    symtab: usize,
}

fn parse_remote_elf(proc: &RemoteProcess, base: usize) -> Result<RemoteElfInfo> {
    let ehdr_buf = proc.read_mem(base, 64)?;
    if ehdr_buf[..4] != [0x7f, b'E', b'L', b'F'] {
        bail!("Not a valid ELF at {:#x}", base);
    }

    let e_phoff = u64::from_ne_bytes(
        ehdr_buf[32..40].try_into().context("ELF ehdr e_phoff slice mismatch")?,
    ) as usize;
    let e_phentsize = u16::from_ne_bytes(
        ehdr_buf[54..56].try_into().context("ELF ehdr e_phentsize slice mismatch")?,
    ) as usize;
    let e_phnum = u16::from_ne_bytes(
        ehdr_buf[56..58].try_into().context("ELF ehdr e_phnum slice mismatch")?,
    ) as usize;

    let phdr_buf = proc.read_mem(base + e_phoff, e_phentsize * e_phnum)?;

    let mut dynamic = 0usize;
    let mut load_end = 0usize;

    for i in 0..e_phnum {
        let off = i * e_phentsize;
        if off + 56 > phdr_buf.len() {
            break;
        }
        let p_type = u32::from_ne_bytes(
            phdr_buf[off..off + 4].try_into().context(format!("ELF phdr[{i}] p_type slice mismatch"))?,
        );
        let p_vaddr = u64::from_ne_bytes(
            phdr_buf[off + 16..off + 24].try_into().context(format!("ELF phdr[{i}] p_vaddr slice mismatch"))?,
        ) as usize;
        let p_memsz = u64::from_ne_bytes(
            phdr_buf[off + 40..off + 48].try_into().context(format!("ELF phdr[{i}] p_memsz slice mismatch"))?,
        ) as usize;

        if p_type == 1 {
            let seg_end = p_vaddr + p_memsz;
            if seg_end > load_end {
                load_end = seg_end;
            }
        } else if p_type == 2 {
            dynamic = base + p_vaddr;
        }
    }

    let load_size = (load_end + 0xFFF) & !0xFFF;

    let mut strtab = 0usize;
    let mut symtab = 0usize;
    if dynamic != 0 {
        let dyn_buf = proc.read_mem(dynamic, 16 * 128)?;
        for j in 0..128 {
            let doff = j * 16;
            if doff + 16 > dyn_buf.len() {
                break;
            }
            let d_tag = i64::from_ne_bytes(
                dyn_buf[doff..doff + 8].try_into().context(format!("ELF dyn[{j}] d_tag slice mismatch"))?,
            );
            let d_val = u64::from_ne_bytes(
                dyn_buf[doff + 8..doff + 16].try_into().context(format!("ELF dyn[{j}] d_val slice mismatch"))?,
            ) as usize;
            match d_tag {
                0 => break,
                5 => strtab = d_val,
                6 => symtab = d_val,
                _ => {}
            }
        }
    }

    debug!(
        "parse_remote_elf: base={:#x} load_size={:#x} dynamic={:#x} strtab={:#x} symtab={:#x}",
        base, load_size, dynamic, strtab, symtab
    );

    Ok(RemoteElfInfo { base, load_size, dynamic, strtab, symtab })
}

fn is_valid_elf_base(proc: &RemoteProcess, addr: usize) -> bool {
    if addr == 0 || addr == usize::MAX {
        return false;
    }
    match proc.read_mem(addr, 4) {
        Ok(buf) => buf == [0x7f, b'E', b'L', b'F'],
        Err(_) => false,
    }
}

/// aarch64 LP64 下各 Android 版本 soinfo 的 base 和 next 字段偏移
/// 参考 AOSP bionic/linker/linker_soinfo.h 和 fake-linker 项目
///
/// Android 8.0 (API 26) 起去掉了 entry 字段，LP64 布局稳定至今：
///   +0x00 phdr, +0x08 phnum, +0x10 base, +0x18 size, +0x20 dynamic, +0x28 next
fn get_soinfo_offsets_hardcoded(api_level: i32) -> Option<(usize, usize)> {
    if (29..=36).contains(&api_level) {
        Some((0x10, 0x28))
    } else {
        None
    }
}

/// 验证硬编码偏移是否正确
/// 从 solist 遍历若干节点，检查链表是否可遍历且至少有一个有效 ELF base
/// 注意：solist 头节点（vdso/linker）的 base 可能为 0，需要跳过
fn verify_soinfo_offsets(proc: &RemoteProcess, solist: usize, base_offset: usize, next_offset: usize) -> bool {
    let mut trav = solist;
    let mut valid_elf_count = 0;

    for _ in 0..5 {
        if trav == 0 {
            break;
        }
        let base = match proc.read_mem(trav + base_offset, 8) {
            Ok(buf) => usize::from_ne_bytes(buf.try_into().unwrap()),
            Err(_) => return false,
        };
        if is_valid_elf_base(proc, base) {
            valid_elf_count += 1;
        }
        trav = match proc.read_mem(trav + next_offset, 8) {
            Ok(buf) => usize::from_ne_bytes(buf.try_into().unwrap()),
            Err(_) => return false,
        };
    }

    valid_elf_count >= 1
}

/// 动态探测 soinfo 结构体中 base 和 next 字段的偏移
///
/// 参考 AndKittyInjector SoInfoPatch.hpp find_soinfo_offsets_with_si：
/// 1. 扫描 soinfo 每个指针，用 parse_remote_elf 找到第一个有效 ELF
/// 2. 用该 ELF 的 base/loadSize/dynamic/strtab/symtab 精确匹配后续字段
/// 3. 第一次匹配到 base 值时锁定 base_offset（不再更新，避免 load_bias 干扰）
/// 4. strtab 字段 → next_offset = strtab_offset - 16
fn probe_soinfo_field_offsets(proc: &RemoteProcess, si_addr: usize) -> Result<(usize, usize)> {
    let scan_size = 0x200;
    let buf = proc.read_mem(si_addr, scan_size)?;

    let mut base_offset = 0usize;
    let mut next_offset = 0usize;
    let mut elf: Option<RemoteElfInfo> = None;

    for i in (0..buf.len()).step_by(8) {
        if i + 8 > buf.len() {
            break;
        }
        let value = usize::from_ne_bytes(buf[i..i + 8].try_into().unwrap());

        if value == 0 {
            continue;
        }

        if elf.is_none() {
            if is_valid_elf_base(proc, value) {
                if let Ok(info) = parse_remote_elf(proc, value) {
                    debug!("soinfo probe: found ELF at {:#x}, offset {:#x}", value, i);
                    elf = Some(info);
                }
            }
            if elf.is_none() {
                continue;
            }
        }

        let e = elf.as_ref().unwrap();

        if value == e.base && base_offset == 0 {
            base_offset = i;
            debug!("soinfo probe: base={:#x} at offset {:#x}", value, i);
        } else if value == e.load_size || value == e.dynamic || value == e.base {
            continue;
        } else if value == e.strtab {
            next_offset = i - (8 * 2);
            debug!("soinfo probe: strtab={:#x} at offset {:#x}, next at offset {:#x}", value, i, next_offset);
            break;
        } else if value == e.symtab {
            debug!("soinfo probe: symtab={:#x} at offset {:#x}, stopping", value, i);
            break;
        }
    }

    if base_offset == 0 || next_offset == 0 || next_offset <= base_offset {
        bail!(
            "Failed to probe soinfo offsets: base_offset={:#x} next_offset={:#x}",
            base_offset,
            next_offset
        );
    }

    Ok((base_offset, next_offset))
}

fn get_soinfo_offsets(proc: &RemoteProcess, solist: usize, sonext: usize) -> Result<(usize, usize)> {
    let api_level: i32 = android_properties::get_or("ro.build.version.sdk", 0);
    debug!("hide_solist: device API level = {api_level}");

    if let Some((base_off, next_off)) = get_soinfo_offsets_hardcoded(api_level) {
        if verify_soinfo_offsets(proc, solist, base_off, next_off) {
            info!(
                "hide_solist: using hardcoded offsets for API {api_level}: base={:#x} next={:#x}",
                base_off, next_off
            );
            return Ok((base_off, next_off));
        }
        warn!("hide_solist: hardcoded offsets verification failed for API {api_level}, falling back to probe");
    } else {
        debug!("hide_solist: no hardcoded offsets for API {api_level}, using probe");
    }

    if sonext == 0 {
        bail!("sonext is null, cannot probe soinfo offsets");
    }
    probe_soinfo_field_offsets(proc, sonext)
}
