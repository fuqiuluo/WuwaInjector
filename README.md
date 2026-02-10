# Injector

Android 平台进程注入工具，使用 Rust 编写，通过 NDK 交叉编译。

## 功能

- 监控 Android 进程启动事件（通过读取 `liblog.so` 的 event log，监听 `am_proc_start`）
- 基于 `ptrace` 的进程注入，支持两种注入方式：
  - `dlopen`：标准 dlopen 注入
  - `memfd`：memfd_create + android_dlopen_ext，绕过路径限制
- 可叠加的注入痕迹隐藏器：
  - `maps`：用户态 remap 匿名映射，隐藏 `/proc/pid/maps` 中的库路径
  - `solist`：修改 linker soinfo 链表，从动态链接器中 unlink 目标库
  - `kernel-maps`：通过 WuWa 内核驱动在 VFS 层完全隐藏 maps 条目
  - `kernel-signal`：通过 WuWa 内核驱动过滤 SIGPROF，防止 profiler 采样泄漏注入库 PC 地址
- 注入完成后自动调用 `JNI_OnLoad` 并恢复目标进程状态
- 支持 `--jni-key` 验证机制，防止 payload 被系统或其他加载器误触发

## 环境要求

- Android API 29+ (Android 10)
- root 权限
- Rust toolchain + Android NDK
- 链接器：mold

## 构建

设置环境变量 `ANDROID_NDK_PATH` 指向 NDK 根目录，然后：

```bash
# 完整构建 + 推送到设备
bash scripts/build.sh

# 仅编译
cargo build --target aarch64-linux-android --release
```

## 使用

```bash
# dlopen 注入 + maps/solist 隐藏
injector -p <包名> -l <so路径> --hider maps --hider solist dlopen

# memfd 注入 + 全部隐藏器
injector -p <包名> -l <so路径> \
  --hider kernel-maps --hider kernel-signal \
  --hider maps --hider solist \
  memfd

# 带 JNI_OnLoad key 验证（支持十六进制和十进制）
injector -p <包名> -l <so路径> --jni-key 0x1337 memfd
```

参数说明：
- `-p`：目标应用包名
- `-l`：要注入的 so 文件路径
- `-t`：等待进程就绪的超时时间（秒，默认 5）
- `--hider`：启用的隐藏器，可多次指定
- `--jni-key`：JNI_OnLoad 验证 key，通过 `reserved` 参数传递给 payload，payload 端校验不通过则跳过初始化
- 子命令 `dlopen` / `memfd`：选择注入方式

## 项目结构

```
src/
├── main.rs              # CLI 入口
├── proc_monitor.rs      # 进程启动监控
├── ptrace_ext.rs        # ptrace 底层封装
├── ptrace_ex.rs         # ptrace 扩展操作（远程 mmap/dlsym 等）
├── wuwa.rs              # WuWa 内核驱动 SDK
├── injector/
│   ├── mod.rs           # Injector trait + 注入流程编排
│   ├── dlopen.rs        # 标准 dlopen 注入
│   └── memfd.rs         # memfd 注入
└── hider/
    ├── mod.rs           # Hider trait + HideTarget
    ├── maps.rs          # 用户态 maps 隐藏
    ├── solist.rs        # soinfo 链表隐藏
    ├── kernel_maps.rs   # 内核层 maps 过滤
    └── kernel_signal.rs # 内核层 SIGPROF 过滤
```

## 致谢

- 进程监控（`proc_monitor`）的实现参考了 [vvb2060](https://github.com/vvb2060) 提供的代码：[am_proc_start.cpp](https://gist.github.com/vvb2060/a3d40084cd9273b65a15f8a351b4eb0e#file-am_proc_start-cpp)
- [xDL](https://github.com/nicedayzhu/xDL) — Android 动态链接器增强库
- [KittyMemoryEx](https://github.com/MJx0/KittyMemoryEx) — Android 内存工具库
- [AndKittyInjector](https://github.com/MJx0/AndKittyInjector) — soinfo 动态探测技术参考
- [fake-linker](https://github.com/sanfengAndroid/fake-linker) — soinfo 硬编码偏移参考（各 Android 版本）
- [Riru](https://github.com/RikkaApps/Riru) — maps 隐藏（remap 匿名映射）技术参考
- [android-wuwa](https://github.com/fuqiuluo/android-wuwa) — WuWa 内核驱动，提供内核层 maps/signal 过滤能力
- [fadeevab](https://fadeevab.com/shared-library-injection-on-android-8/) — default_caller / LR 远程函数调用技术参考

## License

MIT
