use anyhow::{Result, bail};
use log::{debug, info, warn};

use super::{HideTarget, Hider};

/// 从 r_debug 的 link_map 双向链表中解链注入库，隐藏 ELF 标准调试接口的加载痕迹
pub struct LinkMapHider;

/// aarch64 link_map 结构体布局（LP64）:
///   +0x00  l_addr   (ElfW(Addr))   基址
///   +0x08  l_name   (char*)        路径字符串指针
///   +0x10  l_ld     (ElfW(Dyn)*)   .dynamic 段指针
///   +0x18  l_next   (link_map*)    下一个节点
///   +0x20  l_prev   (link_map*)    上一个节点
const LM_ADDR_OFF: usize = 0x00;
const LM_NAME_OFF: usize = 0x08;
const LM_NEXT_OFF: usize = 0x18;
const LM_PREV_OFF: usize = 0x20;

impl Hider for LinkMapHider {
    fn name(&self) -> &'static str {
        "link-map"
    }

    fn apply(&self, target: &HideTarget) -> Result<bool> {
        let r_debug_addr = find_r_debug(target)?;
        if r_debug_addr == 0 {
            warn!("hide_link_map: r_debug not found (DT_DEBUG missing)");
            return Ok(false);
        }
        debug!("hide_link_map: r_debug at {:#x}", r_debug_addr);

        // r_debug.r_map 在偏移 +0x08（跳过 r_version int32 + padding）
        let r_map_buf = target.proc.read_mem(r_debug_addr + 0x08, 8)?;
        let r_map: usize = usize::from_ne_bytes(r_map_buf.try_into().unwrap());

        if r_map == 0 {
            warn!("hide_link_map: r_map is null");
            return Ok(false);
        }

        // 验证 link_map 布局：前几个节点的 l_name 应该能读到合法字符串
        if !verify_link_map_layout(target, r_map) {
            warn!("hide_link_map: link_map layout verification failed, offsets may be wrong");
            return Ok(false);
        }

        // 遍历 link_map 链表找到目标
        let mut curr = r_map;
        let mut count = 0u32;

        while curr != 0 {
            count += 1;
            let addr_buf = target.proc.read_mem(curr + LM_ADDR_OFF, 8)?;
            let l_addr: usize = usize::from_ne_bytes(addr_buf.try_into().unwrap());

            if l_addr == target.base_addr {
                debug!("hide_link_map: found target at link_map {:#x} (#{count}), l_addr={:#x}", curr, l_addr);

                // 读取 prev 和 next
                let prev_buf = target.proc.read_mem(curr + LM_PREV_OFF, 8)?;
                let prev: usize = usize::from_ne_bytes(prev_buf.try_into().unwrap());
                let next_buf = target.proc.read_mem(curr + LM_NEXT_OFF, 8)?;
                let next: usize = usize::from_ne_bytes(next_buf.try_into().unwrap());

                // prev->next = next
                if prev != 0 {
                    target.proc.write_mem_io(prev + LM_NEXT_OFF, &next.to_ne_bytes())?;
                } else {
                    // 目标是链表头，更新 r_debug.r_map
                    target.proc.write_mem_io(r_debug_addr + 0x08, &next.to_ne_bytes())?;
                }

                // next->prev = prev
                if next != 0 {
                    target.proc.write_mem_io(next + LM_PREV_OFF, &prev.to_ne_bytes())?;
                }

                info!(
                    "hide_link_map: unlinked link_map {:#x} (base={:#x}) from r_debug, prev={:#x} next={:#x}",
                    curr, l_addr, prev, next
                );
                return Ok(true);
            }

            let next_buf = target.proc.read_mem(curr + LM_NEXT_OFF, 8)?;
            curr = usize::from_ne_bytes(next_buf.try_into().unwrap());

            if count > 2000 {
                bail!("hide_link_map: link_map chain too long (>2000), aborting");
            }
        }

        warn!("hide_link_map: target base {:#x} not found in link_map chain ({count} nodes)", target.base_addr);
        Ok(false)
    }
}

/// 从远程进程的主程序 ELF PT_DYNAMIC 段中读取 DT_DEBUG，获取 r_debug 地址
fn find_r_debug(target: &HideTarget) -> Result<usize> {
    use proc_maps::get_process_maps;

    let maps = get_process_maps(target.pid)?;

    // 找主程序（app_process64）的可执行段
    let main_map = maps.iter().find(|m| {
        if !m.is_exec() {
            return false;
        }
        match m.filename() {
            Some(p) => {
                let s = p.to_string_lossy();
                s.contains("app_process")
            }
            None => false,
        }
    });

    let main_base = match main_map {
        Some(m) => m.start(),
        None => {
            // 退而求其次：用第一个有 r 权限的映射作为 ELF base
            debug!("hide_link_map: app_process not found in maps, trying first executable mapping");
            return Ok(0);
        }
    };

    // 找 app_process 的最低映射地址作为 ELF base
    let main_path = main_map.unwrap().filename().unwrap().to_string_lossy().to_string();
    let elf_base = maps
        .iter()
        .filter(|m| {
            m.filename()
                .map(|p| p.to_string_lossy() == main_path)
                .unwrap_or(false)
        })
        .map(|m| m.start())
        .min()
        .unwrap_or(main_base);

    debug!("hide_link_map: app_process base={:#x} path={}", elf_base, main_path);

    // 读 ELF header
    let ehdr = target.proc.read_mem(elf_base, 64)?;
    if ehdr[..4] != [0x7f, b'E', b'L', b'F'] {
        bail!("hide_link_map: app_process at {:#x} is not a valid ELF", elf_base);
    }

    let e_phoff = u64::from_ne_bytes(ehdr[32..40].try_into().unwrap()) as usize;
    let e_phentsize = u16::from_ne_bytes(ehdr[54..56].try_into().unwrap()) as usize;
    let e_phnum = u16::from_ne_bytes(ehdr[56..58].try_into().unwrap()) as usize;

    let phdr_buf = target.proc.read_mem(elf_base + e_phoff, e_phentsize * e_phnum)?;

    // 找 PT_DYNAMIC (type = 2)
    for i in 0..e_phnum {
        let off = i * e_phentsize;
        if off + 56 > phdr_buf.len() {
            break;
        }
        let p_type = u32::from_ne_bytes(phdr_buf[off..off + 4].try_into().unwrap());
        if p_type != 2 {
            continue;
        }

        let p_vaddr = u64::from_ne_bytes(phdr_buf[off + 16..off + 24].try_into().unwrap()) as usize;
        let p_memsz = u64::from_ne_bytes(phdr_buf[off + 40..off + 48].try_into().unwrap()) as usize;
        let dyn_addr = elf_base + p_vaddr;
        let dyn_count = p_memsz / 16;

        let dyn_buf = target.proc.read_mem(dyn_addr, p_memsz)?;

        for j in 0..dyn_count {
            let doff = j * 16;
            if doff + 16 > dyn_buf.len() {
                break;
            }
            let d_tag = i64::from_ne_bytes(dyn_buf[doff..doff + 8].try_into().unwrap());
            let d_val = u64::from_ne_bytes(dyn_buf[doff + 8..doff + 16].try_into().unwrap()) as usize;

            if d_tag == 0 {
                break;
            }
            // DT_DEBUG = 21
            if d_tag == 21 && d_val != 0 {
                debug!("hide_link_map: DT_DEBUG found at dyn[{j}], r_debug={:#x}", d_val);
                return Ok(d_val);
            }
        }
    }

    Ok(0)
}

/// 验证 link_map 结构体布局是否正确
/// 检查前几个节点的 l_name 指针是否指向可读的字符串，以及双向链表的 prev/next 是否自洽
fn verify_link_map_layout(target: &HideTarget, r_map: usize) -> bool {
    let mut curr = r_map;
    let mut valid_name_count = 0;

    for i in 0..5 {
        if curr == 0 {
            break;
        }

        // 读 l_name 指针
        let name_ptr = match target.proc.read_mem(curr + LM_NAME_OFF, 8) {
            Ok(buf) => usize::from_ne_bytes(buf.try_into().unwrap()),
            Err(_) => return false,
        };

        // l_name 应该是一个有效指针，读取前 128 字节看是否是合法路径字符串
        if name_ptr != 0 {
            match target.proc.read_mem(name_ptr, 128) {
                Ok(buf) => {
                    // 找第一个 \0，前面应该是可打印的 ASCII（路径字符）
                    if let Some(nul) = buf.iter().position(|&b| b == 0) {
                        let is_valid = nul == 0 || buf[..nul].iter().all(|&b| b >= 0x20 && b < 0x7F);
                        if is_valid {
                            valid_name_count += 1;
                        }
                    }
                }
                Err(_) => return false,
            }
        } else {
            // l_name == NULL 也是合法的（主程序可能如此）
            valid_name_count += 1;
        }

        // 验证双向链表自洽：next->prev == curr
        let next = match target.proc.read_mem(curr + LM_NEXT_OFF, 8) {
            Ok(buf) => usize::from_ne_bytes(buf.try_into().unwrap()),
            Err(_) => return false,
        };
        if next != 0 {
            let prev_of_next = match target.proc.read_mem(next + LM_PREV_OFF, 8) {
                Ok(buf) => usize::from_ne_bytes(buf.try_into().unwrap()),
                Err(_) => return false,
            };
            if prev_of_next != curr {
                debug!(
                    "hide_link_map: verify failed at node #{i}: next({:#x})->prev={:#x} != curr={:#x}",
                    next, prev_of_next, curr
                );
                return false;
            }
        }

        curr = next;
    }

    debug!("hide_link_map: layout verification passed ({valid_name_count}/5 valid names)");
    valid_name_count >= 2
}
