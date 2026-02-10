#!/bin/bash
HOST_TAG="linux-x86_64"
LLVM_BIN="$ANDROID_NDK_PATH/toolchains/llvm/prebuilt/$HOST_TAG/bin"

# 如果是 RustRover/CLion 请把以下环境变量添加到 IDE 的项目环境变量中

# aarch64
export CC_aarch64_linux_android="$LLVM_BIN/aarch64-linux-android29-clang"
export CXX_aarch64_linux_android="$LLVM_BIN/aarch64-linux-android29-clang++"
export AR_aarch64_linux_android="$LLVM_BIN/llvm-ar"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$LLVM_BIN/aarch64-linux-android29-clang"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_AR="$LLVM_BIN/llvm-ar"

# armv7
export CC_armv7_linux_androideabi="$LLVM_BIN/armv7a-linux-androideabi21-clang"
export CXX_armv7_linux_androideabi="$LLVM_BIN/armv7a-linux-androideabi21-clang++"
export AR_armv7_linux_androideabi="$LLVM_BIN/llvm-ar"
export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="$LLVM_BIN/armv7a-linux-androideabi21-clang"
export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_AR="$LLVM_BIN/llvm-ar"

# i686
export CC_i686_linux_android="$LLVM_BIN/i686-linux-android21-clang"
export CXX_i686_linux_android="$LLVM_BIN/i686-linux-android21-clang++"
export AR_i686_linux_android="$LLVM_BIN/llvm-ar"
export CARGO_TARGET_I686_LINUX_ANDROID_LINKER="$LLVM_BIN/i686-linux-android21-clang"
export CARGO_TARGET_I686_LINUX_ANDROID_AR="$LLVM_BIN/llvm-ar"

# x86_64
export CC_x86_64_linux_android="$LLVM_BIN/x86_64-linux-android29-clang"
export CXX_x86_64_linux_android="$LLVM_BIN/x86_64-linux-android29-clang++"
export AR_x86_64_linux_android="$LLVM_BIN/llvm-ar"
export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$LLVM_BIN/x86_64-linux-android29-clang"
export CARGO_TARGET_X86_64_LINUX_ANDROID_AR="$LLVM_BIN/llvm-ar"
export ANDROID_NDK_HOME="$ANDROID_NDK_PATH"
echo "Android NDK environment set up for Rust"

export ANDROID_API_LEVEL=29
export RUSTFLAGS="-C link-arg=-fuse-ld=mold -C target-feature=+neon"

rm target/aarch64-linux-android/release/injector
#rm target/armv7-linux-androideabi/release/injector
#rm target/i686-linux-android/release/injector
#rm target/x86_64-linux-android/release/injector

cargo build --target aarch64-linux-android --release
#cargo build --target armv7-linux-androideabi --release
#cargo build --target i686-linux-android --release
#cargo build --target x86_64-linux-android --release

adb shell su -c "rm /data/adb/injector"
adb push target/aarch64-linux-android/release/injector /data/local/tmp
adb shell su -c "mv /data/local/tmp/injector /data/adb/injector"
adb shell su -c "chmod 755 /data/adb/injector"
adb shell su -c "kill -9 \$(pidof injector)"
adb shell su -c "RUST_LOG=debug /data/adb/injector -p moe.fuqiuluo.mamu -l /data/local/tmp/libpayload.so --jni-key 0x1337 --hider kernel-maps --hider kernel-signal --hider maps --hider solist memfd"
