mod hider;
mod injector;
mod proc_monitor;
mod ptrace_ex;
mod ptrace_ext;
pub(crate) mod wuwa;

use std::fs;
use std::os::fd::AsFd;
use std::os::unix::prelude::OsStrExt;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use log::{debug, info, warn};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify};

#[derive(Clone, ValueEnum)]
enum HiderKind {
    Maps,
    Solist,
    KernelMaps,
    KernelSignal,
}

#[derive(Parser)]
#[command(name = "injector", about = "Android process injector")]
struct Cli {
    /// 目标包名
    #[arg(short, long)]
    package: String,

    /// 要注入的 so 路径
    #[arg(short, long)]
    lib: String,

    /// 等待进程就绪的超时时间（秒）
    #[arg(short, long, default_value_t = 5)]
    timeout: u64,

    /// 启用的隐藏器，可多次指定
    #[arg(long = "hider", value_enum)]
    hiders: Vec<HiderKind>,

    /// JNI_OnLoad 验证 key，payload 端可通过 reserved 参数校验
    /// 支持十六进制（0x1337）或十进制
    #[arg(long)]
    jni_key: Option<String>,

    #[command(subcommand)]
    method: InjectMethod,
}

#[derive(Subcommand)]
enum InjectMethod {
    /// 使用标准 dlopen 注入
    Dlopen,
    /// 使用 memfd_create + android_dlopen_ext 注入，绕过路径限制
    Memfd,
}

fn build_hiders(kinds: &[HiderKind]) -> Vec<Box<dyn hider::Hider>> {
    kinds
        .iter()
        .map(|k| -> Box<dyn hider::Hider> {
            match k {
                HiderKind::Maps => Box::new(hider::maps::MapsHider),
                HiderKind::Solist => Box::new(hider::solist::SolistHider),
                HiderKind::KernelMaps => Box::new(hider::kernel_maps::KernelMapsHider),
                HiderKind::KernelSignal => Box::new(hider::kernel_signal::KernelSignalHider),
            }
        })
        .collect()
}

fn parse_jni_key(s: &str) -> Result<usize> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        usize::from_str_radix(hex, 16).context("Invalid hex jni-key")
    } else {
        s.parse::<usize>().context("Invalid jni-key")
    }
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    let use_memfd = matches!(cli.method, InjectMethod::Memfd);
    let hiders = build_hiders(&cli.hiders);
    let jni_key = cli
        .jni_key
        .as_deref()
        .map(parse_jni_key)
        .transpose()
        .context("Failed to parse --jni-key")?;

    info!("Waiting for {} to start...", cli.package);

    proc_monitor::monitor_proc_start(|event| {
        debug!(
            "proc_start: pid={} uid={} name={}",
            event.pid, event.uid, event.process_name
        );

        if event.process_name != cli.package {
            return false;
        }

        info!(
            "Target found: pid={} uid={} name={}",
            event.pid, event.uid, event.process_name
        );

        match wait_for_proc_ready(event.pid, Duration::from_secs(cli.timeout)) {
            Ok(true) => {
                info!("pid {} ready, injecting...", event.pid);
                match injector::inject(event.pid, &cli.lib, use_memfd, &hiders, jni_key) {
                    Ok(info) => {
                        let hider_summary: String = info
                            .hider_results
                            .iter()
                            .map(|(name, ok)| format!("{name}={ok}"))
                            .collect::<Vec<_>>()
                            .join(" ");
                        info!(
                            "Injection succeeded! handle={:#x} base={:#x} {hider_summary}",
                            info.dl_handle, info.base_addr
                        );
                        if let Err(e) = write_injection_result(&event, &cli.lib, &info) {
                            warn!("Failed to write injection result: {e:#}");
                        }
                    },
                    Err(e) => warn!("Injection failed: {e:#}"),
                }
            },
            Ok(false) => warn!("pid {} exited or timeout", event.pid),
            Err(e) => warn!("wait_for_proc_ready failed: {e:#}"),
        }

        true
    })
}

fn wait_for_proc_ready(pid: i32, timeout: Duration) -> Result<bool> {
    let proc_dir = format!("/proc/{pid}");

    if !Path::new(&proc_dir).exists() {
        return Ok(false);
    }

    let inotify = Inotify::init(InitFlags::IN_NONBLOCK).context("inotify_init failed")?;

    inotify
        .add_watch(proc_dir.as_str(), AddWatchFlags::IN_ALL_EVENTS)
        .context("inotify add_watch failed")?;

    let start = Instant::now();
    let mut poll_fds = [PollFd::new(inotify.as_fd(), PollFlags::POLLIN)];

    loop {
        if start.elapsed() >= timeout {
            return Ok(false);
        }

        let remaining = timeout.saturating_sub(start.elapsed());
        let timeout_ms = remaining.as_millis().min(i32::MAX as u128) as i32;

        let timeout = PollTimeout::try_from(timeout_ms).context("Failed to convert timeout to PollTimeout")?;
        match poll(&mut poll_fds, timeout) {
            Ok(0) => return Ok(false),
            Err(e) => return Err(e).context("poll failed"),
            _ => {},
        }

        let events = inotify.read_events().context("inotify read failed")?;

        for event in &events {
            let name = match &event.name {
                Some(n) => n.as_bytes(),
                None => continue,
            };

            if name.len() >= 2 && u16::from_le_bytes([name[0], name[1]]) == 0x6466 {
                continue;
            }

            if name.len() >= 4 && u32::from_le_bytes([name[0], name[1], name[2], name[3]]) == 0x656d6974 {
                continue;
            }

            return Ok(true);
        }
    }
}

use serde::Serialize;

#[derive(Serialize)]
struct InjectionResult<'a> {
    process_name: &'a str,
    pid: i32,
    uid: i32,
    lib_path: &'a str,
    #[serde(flatten)]
    info: &'a injector::InjectedInfo,
}

fn write_injection_result(
    event: &proc_monitor::ProcStartEvent,
    lib_path: &str,
    info: &injector::InjectedInfo,
) -> Result<()> {
    let exe_dir = fs::read_link("/proc/self/exe").context("Failed to readlink /proc/self/exe")?;
    let exe_dir = exe_dir.parent().unwrap_or(Path::new("/data/local/tmp"));
    let toml_path = exe_dir.join("injection_result.toml");
    info!("Writing injection result to {}", toml_path.display());

    let result = InjectionResult {
        process_name: &event.process_name,
        pid: event.pid,
        uid: event.uid,
        lib_path,
        info,
    };

    let content = toml::to_string_pretty(&result).context("Failed to serialize to toml")?;
    fs::write(&toml_path, content).context("Failed to write toml file")?;

    info!("Injection result written to {}", toml_path.display());
    Ok(())
}
