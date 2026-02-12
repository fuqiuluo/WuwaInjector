use anyhow::{Context, Result};
use log::{info, warn};

use crate::wuwa::{WuWaDriver, WuwaSignalFilterRegion};

use super::{HideTarget, Hider};

/// 通过 WuWa 内核驱动过滤注入库内存区域内的 SIGPROF 信号
///
/// profiler 采样会向进程发送 SIGPROF，采样时记录的 PC 地址如果落在注入库范围内，
/// 就会泄漏注入痕迹。此 hider 在内核层拦截 PC 位于注入库区域时的 SIGPROF 投递。
pub struct KernelSignalHider;

const SIGPROF: u32 = 27;

fn sigmask(sig: u32) -> u64 {
    1u64 << (sig - 1)
}

impl Hider for KernelSignalHider {
    fn name(&self) -> &'static str {
        "kernel-signal"
    }

    fn apply(&self, target: &HideTarget) -> Result<bool> {
        if target.segments.is_empty() {
            warn!("kernel-signal: no segments found for {}", target.maps_search_name);
            return Ok(false);
        }

        let regions: Vec<WuwaSignalFilterRegion> = target
            .segments
            .iter()
            .map(|seg| WuwaSignalFilterRegion {
                start: seg.start as u64,
                end: (seg.start + seg.size) as u64,
            })
            .collect();

        let mask = sigmask(SIGPROF);

        info!(
            "kernel-signal: filtering SIGPROF for {} regions of {}",
            regions.len(),
            target.maps_search_name
        );

        let driver = WuWaDriver::new().context("kernel-signal: failed to connect to WuWa driver")?;
        let result = driver
            .add_signal_filter(target.pid, mask, 0, &regions)
            .context("kernel-signal: add_signal_filter failed")?;

        if result != 0 {
            warn!("kernel-signal: driver returned error code {}", result);
            return Ok(false);
        }

        info!("kernel-signal: successfully installed signal filter for {} regions", regions.len());
        Ok(true)
    }
}
