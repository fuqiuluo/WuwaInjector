use anyhow::{Context, Result};
use log::{info, warn};

use crate::wuwa::{WuWaDriver, WuwaMapsFilterRegion};

use super::{HideTarget, Hider};

/// 通过 WuWa 内核驱动在内核层面隐藏 /proc/pid/maps 中的库映射
///
/// 与 MapsHider（用户态 remap）不同，KernelMapsHider 直接在内核 VFS 层拦截 maps 读取，
/// 完全隐藏指定区域，不需要修改进程内存布局。
pub struct KernelMapsHider;

impl Hider for KernelMapsHider {
    fn name(&self) -> &'static str {
        "kernel-maps"
    }

    fn apply(&self, target: &HideTarget) -> Result<bool> {
        if target.segments.is_empty() {
            warn!("kernel-maps: no segments found for {}", target.maps_search_name);
            return Ok(false);
        }

        let regions: Vec<WuwaMapsFilterRegion> = target
            .segments
            .iter()
            .map(|seg| WuwaMapsFilterRegion {
                start: seg.start as u64,
                end: (seg.start + seg.size) as u64,
            })
            .collect();

        info!("kernel-maps: hiding {} regions for {}", regions.len(), target.maps_search_name);

        let driver = WuWaDriver::new().context("kernel-maps: failed to connect to WuWa driver")?;
        let result = driver
            .add_maps_filter(target.pid, &regions, 4)
            .context("kernel-maps: add_maps_filter failed")?;

        if result != 0 {
            warn!("kernel-maps: driver returned error code {}", result);
            return Ok(false);
        }

        info!("kernel-maps: successfully hidden {} regions", regions.len());
        Ok(true)
    }
}
