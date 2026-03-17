#include <android/log.h>
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define TAG "InjectTest"

// 产生 __cxa_atexit 注册
struct NontrivialGlobal {
    int id;
    char name[32];
    NontrivialGlobal(int i, const char *n) : id(i) {
        strncpy(name, n, sizeof(name) - 1);
        name[sizeof(name) - 1] = '\0';
    }
    ~NontrivialGlobal() {
        // 析构函数非平凡，编译器会自动注册 __cxa_atexit
        __android_log_print(ANDROID_LOG_INFO, TAG, "~NontrivialGlobal(%d, \"%s\")", id, name);
    }
};

static NontrivialGlobal g_obj_alpha(1, "alpha");
static NontrivialGlobal g_obj_beta(2, "beta");
static NontrivialGlobal g_obj_gamma(3, "gamma");

static int g_counter = 0;

static void *counter_thread(void *arg) {
    (void)arg;
    while (1) {
        g_counter++;
        __android_log_print(ANDROID_LOG_INFO, TAG,
            "counter=%d pid=%d", g_counter, getpid());
        sleep(2);
    }
    return NULL;
}

static void dump_self_maps(void) {
    char line[512];
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "Failed to open /proc/self/maps");
        return;
    }

    int found = 0;
    while (fgets(line, sizeof(line), fp)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        if (strstr(line, "payload") ||
            (strstr(line, "memfd:") && !strstr(line, "jit-"))) {
            __android_log_print(ANDROID_LOG_WARN, TAG, "VISIBLE: %s", line);
            found++;
        }
    }
    fclose(fp);

    if (found == 0) {
        __android_log_print(ANDROID_LOG_INFO, TAG, "maps check: payload NOT found in maps (hidden OK)");
    } else {
        __android_log_print(ANDROID_LOG_WARN, TAG, "maps check: found %d entries (NOT hidden)", found);
    }
}

struct solist_ctx {
    int found;
    int total;
};

static int solist_callback(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    struct solist_ctx *ctx = (struct solist_ctx *)data;
    const char *name = info->dlpi_name;

    if (!name || name[0] == '\0') {
        ctx->total++;
        return 0;
    }

    ctx->total++;

    if (strstr(name, "payload") || strstr(name, "memfd:")) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "solist VISIBLE: %s (base=%p)", name, (void *)info->dlpi_addr);
        ctx->found++;
    }

    return 0;
}

static void dump_solist(void) {
    struct solist_ctx ctx = { 0, 0 };
    dl_iterate_phdr(solist_callback, &ctx);

    if (ctx.found == 0) {
        __android_log_print(ANDROID_LOG_INFO, TAG, "solist check: payload NOT found in solist (hidden OK), total=%d", ctx.total);
    } else {
        __android_log_print(ANDROID_LOG_WARN, TAG, "solist check: found %d entries in solist (NOT hidden), total=%d", ctx.found, ctx.total);
    }
}

// 通过 dl_iterate_phdr 找到主程序的 PT_DYNAMIC，从 DT_DEBUG 获取 r_debug
static struct r_debug *find_r_debug(void) {
    struct r_debug *result = NULL;
    dl_iterate_phdr([](struct dl_phdr_info *info, size_t, void *data) -> int {
        for (int i = 0; i < info->dlpi_phnum; i++) {
            if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
                ElfW(Dyn) *dyn = (ElfW(Dyn) *)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
                for (; dyn->d_tag != DT_NULL; dyn++) {
                    if (dyn->d_tag == DT_DEBUG && dyn->d_un.d_ptr != 0) {
                        *(struct r_debug **)data = (struct r_debug *)dyn->d_un.d_ptr;
                        return 1;
                    }
                }
            }
        }
        return 0;
    }, &result);
    return result;
}

static void dump_r_debug(void) {
    struct r_debug *dbg = find_r_debug();
    if (!dbg) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "r_debug check: DT_DEBUG not found");
        return;
    }

    int total = 0, suspicious = 0;
    for (struct link_map *lm = dbg->r_map; lm != NULL; lm = lm->l_next) {
        total++;
        const char *name = lm->l_name;
        if (!name || name[0] == '\0') continue;

        int is_suspicious = 0;
        if (strstr(name, "payload") || strstr(name, "memfd:")) {
            is_suspicious = 1;
        }

        if (is_suspicious) {
            __android_log_print(ANDROID_LOG_WARN, TAG,
                "r_debug VISIBLE: %s (base=%p)", name, (void *)lm->l_addr);
            suspicious++;
        }
    }

    if (suspicious == 0) {
        __android_log_print(ANDROID_LOG_INFO, TAG,
            "r_debug check: payload NOT found in link_map (hidden OK), total=%d", total);
    } else {
        __android_log_print(ANDROID_LOG_WARN, TAG,
            "r_debug check: found %d entries in link_map (NOT hidden), total=%d", suspicious, total);
    }
}

static void dump_anon_exec(void) {
    char line[512];
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return;

    int found = 0;
    while (fgets(line, sizeof(line), fp)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        // 解析权限字段: "addr1-addr2 perms ..."
        char *perms = strchr(line, ' ');
        if (!perms) continue;
        perms++;

        // 需要有 x 权限
        if (strlen(perms) < 4 || perms[2] != 'x') continue;

        // 匿名映射：没有路径，或者路径部分为空
        // 跳过有文件路径的（包含 / 的）
        char *last_field = strrchr(line, ' ');
        if (!last_field) continue;
        last_field++;

        // 有路径的跳过（正常 so、vdso 等）
        if (last_field[0] == '/' || last_field[0] == '[') continue;

        // 跳过 jit 相关的
        if (strstr(line, "jit-")) continue;

        __android_log_print(ANDROID_LOG_WARN, TAG, "anon_exec: %s", line);
        found++;
    }
    fclose(fp);

    if (found == 0) {
        __android_log_print(ANDROID_LOG_INFO, TAG, "anon_exec check: no suspicious anonymous executable regions");
    } else {
        __android_log_print(ANDROID_LOG_WARN, TAG, "anon_exec check: found %d anonymous executable regions", found);
    }
}

static void dump_suspicious_fds(void) {
    DIR *dir = opendir("/proc/self/fd");
    if (!dir) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "fd check: failed to open /proc/self/fd");
        return;
    }

    int found = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        char link_path[128];
        char target[512];
        snprintf(link_path, sizeof(link_path), "/proc/self/fd/%s", entry->d_name);

        ssize_t len = readlink(link_path, target, sizeof(target) - 1);
        if (len <= 0) continue;
        target[len] = '\0';

        // 检查 memfd（排除 jit）或 payload 相关
        if ((strstr(target, "memfd:") && !strstr(target, "jit-")) ||
            strstr(target, "payload")) {
            __android_log_print(ANDROID_LOG_WARN, TAG, "fd VISIBLE: fd=%s -> %s", entry->d_name, target);
            found++;
        }
    }
    closedir(dir);

    if (found == 0) {
        __android_log_print(ANDROID_LOG_INFO, TAG, "fd check: no suspicious fds found (OK)");
    } else {
        __android_log_print(ANDROID_LOG_WARN, TAG, "fd check: found %d suspicious fds", found);
    }
}

static void dump_suspicious_threads(void) {
    DIR *dir = opendir("/proc/self/task");
    if (!dir) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "thread check: failed to open /proc/self/task");
        return;
    }

    int total = 0;
    int suspicious = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        total++;

        char comm_path[128];
        snprintf(comm_path, sizeof(comm_path), "/proc/self/task/%s/comm", entry->d_name);

        FILE *fp = fopen(comm_path, "r");
        if (!fp) continue;

        char comm[64] = {0};
        if (fgets(comm, sizeof(comm), fp)) {
            char *nl = strchr(comm, '\n');
            if (nl) *nl = '\0';
        }
        fclose(fp);

        // 检查异常线程名
        if (strstr(comm, "inject") || strstr(comm, "payload") || strstr(comm, "ptrace")) {
            __android_log_print(ANDROID_LOG_WARN, TAG, "thread SUSPICIOUS: tid=%s comm=%s", entry->d_name, comm);
            suspicious++;
        }
    }
    closedir(dir);

    __android_log_print(ANDROID_LOG_INFO, TAG, "thread check: %d threads total, %d suspicious", total, suspicious);
}

// ==================== atexit 链表检测 ====================
// Android 11+ bionic 将 __cxa_atexit entry 存在 [anon:atexit handlers] mmap 区域
// 遍历所有 entry，用 dladdr 查 fn 所属 so，不在 /system /apex /vendor 下即为可疑

struct AtexitEntry {
    void (*fn)(void *);   // +0,  8 bytes
    void *arg;            // +8,  8 bytes
    void *dso;            // +16, 8 bytes
};

static void dump_atexit(void) {
    // 在 /proc/self/maps 中查找 [anon:atexit handlers]
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return;

    unsigned long region_start = 0, region_end = 0;
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "[anon:atexit handlers]")) {
            sscanf(line, "%lx-%lx", &region_start, &region_end);
            break;
        }
    }
    fclose(fp);

    if (!region_start) {
        __android_log_print(ANDROID_LOG_WARN, TAG,
            "atexit check: [anon:atexit handlers] not found (Android < 11?)");
        return;
    }

    __android_log_print(ANDROID_LOG_INFO, TAG,
        "atexit check: handlers region %lx-%lx (%lu bytes)",
        region_start, region_end, region_end - region_start);

    AtexitEntry *entries = (AtexitEntry *)region_start;
    size_t capacity = (region_end - region_start) / sizeof(AtexitEntry);

    int total = 0, suspicious = 0;
    for (size_t i = 0; i < capacity; i++) {
        if (!entries[i].fn) continue;
        total++;

        Dl_info info;
        memset(&info, 0, sizeof(info));
        int found = dladdr((void *)entries[i].fn, &info);

        const char *lib = "(unknown)";
        if (found && info.dli_fname) {
            lib = info.dli_fname;
        }

        int is_suspicious = 0;
        if (!found || !info.dli_fname) {
            // dladdr 查不到 -> 函数在匿名内存中（maps hider 重映射后）
            is_suspicious = 1;
        } else if (strncmp(info.dli_fname, "/system/", 8) != 0 &&
                   strncmp(info.dli_fname, "/system_ext/", 12) != 0 &&
                   strncmp(info.dli_fname, "/apex/", 6) != 0 &&
                   strncmp(info.dli_fname, "/vendor/", 8) != 0) {
            // 不在系统路径下 -> 第三方注入
            is_suspicious = 1;
        }

        if (is_suspicious) {
            __android_log_print(ANDROID_LOG_WARN, TAG,
                "atexit SUSPICIOUS [%zu]: fn=%p arg=%p dso=%p -> %s",
                i, (void *)entries[i].fn, entries[i].arg, entries[i].dso, lib);
            suspicious++;
        }
    }

    if (suspicious > 0) {
        __android_log_print(ANDROID_LOG_WARN, TAG,
            "atexit check: %d/%d entries suspicious - INJECTION DETECTED!", suspicious, total);
    } else {
        __android_log_print(ANDROID_LOG_INFO, TAG,
            "atexit check: %d entries, all clean (OK)", total);
    }
}

static void dump_elf_in_anon(void) {
    static const unsigned char elf_magic[4] = { 0x7f, 'E', 'L', 'F' };

    char line[512];
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return;

    int found = 0;
    while (fgets(line, sizeof(line), fp)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        // 解析地址范围
        unsigned long start, end;
        char perms[8] = {0};
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3) continue;

        // 只检查可读的匿名映射
        if (perms[0] != 'r') continue;

        // 跳过有文件路径的
        char *last_field = strrchr(line, ' ');
        if (last_field) {
            last_field++;
            if (last_field[0] == '/' || last_field[0] == '[') continue;
        }

        // 跳过 jit
        if (strstr(line, "jit-")) continue;

        // 跳过太大的区域（避免扫描耗时过长）
        unsigned long size = end - start;
        if (size > 64 * 1024 * 1024) continue;

        // 检查开头是否是 ELF magic
        const unsigned char *mem = (const unsigned char *)start;
        if (size >= 4 && memcmp(mem, elf_magic, 4) == 0) {
            __android_log_print(ANDROID_LOG_WARN, TAG,
                "elf_in_anon: ELF header at %lx-%lx (%s) size=%lu", start, end, perms, size);
            found++;
        }
    }
    fclose(fp);

    if (found == 0) {
        __android_log_print(ANDROID_LOG_INFO, TAG, "elf_in_anon check: no ELF in anonymous memory (OK)");
    } else {
        __android_log_print(ANDROID_LOG_WARN, TAG, "elf_in_anon check: found %d ELF headers in anonymous memory", found);
    }
}

__attribute__((constructor))
static void init(void) {
    __android_log_print(ANDROID_LOG_INFO, TAG,
        "Payload loaded (constructor)! pid=%d uid=%d", getpid(), getuid());
}

/// 注入器在 hide_maps 完成后远程调用此函数
/// reserved 参数用于传递验证 key，防止被系统或其他加载器误触发
/// 使用方式: injector --jni-key 0x1337 ...
#define INJECTOR_KEY 0x1337

extern "C" __attribute__((visibility("default")))
int JNI_OnLoad(void *vm, void *reserved) {
    if (reserved != (void *)INJECTOR_KEY) {
        __android_log_print(ANDROID_LOG_WARN, TAG,
            "JNI_OnLoad: key mismatch (got %p, expected %p), ignoring",
            reserved, (void *)INJECTOR_KEY);
        return 0x10006;
    }

    __android_log_print(ANDROID_LOG_INFO, TAG,
        "JNI_OnLoad called by injector! pid=%d uid=%d", getpid(), getuid());

    if (vm) {
        static const unsigned char elf_magic[4] = { 0x7f, 'E', 'L', 'F' };
        const unsigned char *base = (const unsigned char *)vm;
        if (memcmp(base, elf_magic, 4) == 0) {
            __android_log_print(ANDROID_LOG_INFO, TAG,
                "base=%p is valid ELF (magic: %02x %02x %02x %02x)",
                vm, base[0], base[1], base[2], base[3]);
        } else {
            __android_log_print(ANDROID_LOG_WARN, TAG,
                "base=%p is NOT ELF (got: %02x %02x %02x %02x)",
                vm, base[0], base[1], base[2], base[3]);
        }
    } else {
        __android_log_print(ANDROID_LOG_WARN, TAG, "base is NULL");
    }

    dump_self_maps();
    dump_solist();
    dump_r_debug();
    dump_anon_exec();
    dump_suspicious_fds();
    dump_suspicious_threads();
    dump_elf_in_anon();
    dump_atexit();

    pthread_t tid;
    pthread_create(&tid, NULL, counter_thread, NULL);
    pthread_detach(tid);

    return 0x10006; // JNI_VERSION_1_6
}
