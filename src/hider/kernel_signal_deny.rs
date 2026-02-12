use anyhow::{Context, Result};
use log::info;

use crate::wuwa::WuWaDriver;

use super::{HideTarget, Hider};

/// 通过 WuWa 内核驱动以 DENY 模式无条件拦截崩溃类信号
///
/// 注入库崩溃时 Android 会生成 tombstone，暴露注入痕迹。
/// DENY 模式在内核层拦截 SIGSEGV/SIGILL，将崩溃信息写入 dmesg 后直接 SIGKILL 进程，
/// 避免产生可被取证的 tombstone 文件。
pub struct KernelSignalDenyHider;

const SIGSEGV: u32 = 11;
const SIGILL: u32 = 4;

fn sigmask(sig: u32) -> u64 {
    1u64 << (sig - 1)
}

impl Hider for KernelSignalDenyHider {
    fn name(&self) -> &'static str {
        "kernel-signal-deny"
    }

    fn apply(&self, target: &HideTarget) -> Result<bool> {
        let deny_mask = sigmask(SIGSEGV) | sigmask(SIGILL);

        info!(
            "kernel-signal-deny: installing DENY filter for SIGSEGV|SIGILL on pid {}",
            target.pid
        );

        let driver = WuWaDriver::new().context("kernel-signal-deny: failed to connect to WuWa driver")?;
        let result = driver
            .add_signal_filter(target.pid, 0, deny_mask, &[])
            .context("kernel-signal-deny: add_signal_filter failed")?;

        if result != 0 {
            log::warn!("kernel-signal-deny: driver returned error code {}", result);
            return Ok(false);
        }

        info!("kernel-signal-deny: successfully installed DENY signal filter");
        Ok(true)
    }
}
