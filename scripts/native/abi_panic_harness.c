#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <dlfcn.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    void *ptr;
    size_t len;
} cliproxy_buffer;

typedef int (*cliproxy_host_call_fn)(void *, const char *, const uint8_t *, size_t, cliproxy_buffer *);
typedef void (*cliproxy_host_free_fn)(void *, size_t);

typedef struct {
    uint32_t abi_version;
    void *host_ctx;
    cliproxy_host_call_fn call;
    cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;

typedef int (*cliproxy_plugin_call_fn)(char *, uint8_t *, size_t, cliproxy_buffer *);
typedef void (*cliproxy_plugin_free_fn)(void *, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
    uint32_t abi_version;
    cliproxy_plugin_call_fn call;
    cliproxy_plugin_free_fn free_buffer;
    cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

typedef int (*plugin_init_fn)(cliproxy_host_api *, cliproxy_plugin_api *);
typedef void (*set_panic_point_fn)(uint32_t);

enum {
    PANIC_INIT = 1,
    PANIC_CALL = 2,
    PANIC_FREE = 3,
    PANIC_SHUTDOWN_BOUNDARY = 4,
    PANIC_SHUTDOWN_SUMMARY_MAINTENANCE = 12,
    PANIC_INIT_AFTER_PUBLISH = 17,
    PANIC_CALL_AFTER_RESPONSE = 18,
};

static void fail(const char *message) {
    fprintf(stderr, "ABI panic harness failed: %s\n", message);
    exit(1);
}

static void *required_symbol(void *library, const char *name) {
    dlerror();
    void *symbol = dlsym(library, name);
    const char *error = dlerror();
    if (error != NULL || symbol == NULL) {
        fprintf(stderr, "ABI panic harness missing symbol %s: %s\n", name, error == NULL ? "unknown" : error);
        exit(1);
    }
    return symbol;
}

static int buffer_contains(const cliproxy_buffer *buffer, const char *needle) {
    size_t needle_len = strlen(needle);
    if (buffer == NULL || buffer->ptr == NULL || needle_len == 0 || buffer->len < needle_len) {
        return 0;
    }
    const unsigned char *payload = (const unsigned char *)buffer->ptr;
    for (size_t offset = 0; offset + needle_len <= buffer->len; offset++) {
        if (memcmp(payload + offset, needle, needle_len) == 0) {
            return 1;
        }
    }
    return 0;
}

static void require_safe_panic_response(const cliproxy_buffer *response) {
    if (response == NULL || response->ptr == NULL || response->len == 0) {
        fail("panic response is empty");
    }
    if (!buffer_contains(response, "\"code\":\"plugin_panic\"")) {
        fail("panic response does not contain plugin_panic");
    }
    if (!buffer_contains(response, "plugin encountered an internal failure")) {
        fail("panic response does not contain the generic message");
    }
    if (buffer_contains(response, "ABI_PANIC_HARNESS_SECRET") || buffer_contains(response, "goroutine") || buffer_contains(response, "stack")) {
        fail("panic response leaked panic details or a stack");
    }
}

static long resident_bytes(void) {
    FILE *file = fopen("/proc/self/statm", "r");
    if (file == NULL) {
        return -1;
    }
    unsigned long total_pages = 0;
    unsigned long resident_pages = 0;
    int scanned = fscanf(file, "%lu %lu", &total_pages, &resident_pages);
    fclose(file);
    (void)total_pages;
    long page_size = sysconf(_SC_PAGESIZE);
    if (scanned != 2 || page_size <= 0) {
        return -1;
    }
    return (long)resident_pages * page_size;
}

static int open_fd_count(void) {
    DIR *directory = opendir("/proc/self/fd");
    if (directory == NULL) {
        return -1;
    }
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            count++;
        }
    }
    closedir(directory);
    return count;
}

static void dump_open_fds(void) {
    DIR *directory = opendir("/proc/self/fd");
    if (directory == NULL) {
        return;
    }
    struct dirent *entry;
    char path[PATH_MAX];
    char target[PATH_MAX];
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        int written = snprintf(path, sizeof(path), "/proc/self/fd/%s", entry->d_name);
        if (written < 0 || (size_t)written >= sizeof(path)) {
            continue;
        }
        ssize_t length = readlink(path, target, sizeof(target) - 1);
        if (length < 0) {
            continue;
        }
        target[length] = '\0';
        fprintf(stderr, "open fd %s -> %s\n", entry->d_name, target);
    }
    closedir(directory);
}

static void normal_call_and_free(cliproxy_plugin_call_fn plugin_call, cliproxy_plugin_free_fn plugin_free) {
    cliproxy_buffer response = {0};
    if (plugin_call("management.register", NULL, 0, &response) != 0 || response.ptr == NULL) {
        fail("repeated normal ABI call failed");
    }
    plugin_free(response.ptr, response.len);
}

static void json_call_and_free(cliproxy_plugin_call_fn plugin_call, cliproxy_plugin_free_fn plugin_free,
                               const char *method, const char *request) {
    cliproxy_buffer response = {0};
    if (plugin_call((char *)method, (uint8_t *)request, strlen(request), &response) != 0 || response.ptr == NULL) {
        fail("ABI JSON warm-up call failed");
    }
    plugin_free(response.ptr, response.len);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s /absolute/path/to/tagged-library.so\n", argv[0]);
        return 2;
    }

    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (library == NULL) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }

    plugin_init_fn plugin_init;
    cliproxy_plugin_call_fn plugin_call;
    cliproxy_plugin_free_fn plugin_free;
    cliproxy_plugin_shutdown_fn plugin_shutdown;
    set_panic_point_fn set_panic_point;
    *(void **)(&plugin_init) = required_symbol(library, "cliproxy_plugin_init");
    *(void **)(&plugin_call) = required_symbol(library, "cliproxyPluginCall");
    *(void **)(&plugin_free) = required_symbol(library, "cliproxyPluginFree");
    *(void **)(&plugin_shutdown) = required_symbol(library, "cliproxyPluginShutdown");
    *(void **)(&set_panic_point) = required_symbol(library, "cliproxyTestSetPanicPoint");

    cliproxy_plugin_api api;
    memset(&api, 0xA5, sizeof(api));
    set_panic_point(PANIC_INIT);
    if (plugin_init(NULL, &api) != 1) {
        fail("panic-injected init did not fail safely");
    }
    if (api.abi_version != 0 || api.call != NULL || api.free_buffer != NULL || api.shutdown != NULL) {
        fail("panic-injected init left a partially initialized plugin API");
    }

    memset(&api, 0xA5, sizeof(api));
    set_panic_point(PANIC_INIT_AFTER_PUBLISH);
    if (plugin_init(NULL, &api) != 1) {
        fail("post-publication init panic did not fail safely");
    }
    if (api.abi_version != 0 || api.call != NULL || api.free_buffer != NULL || api.shutdown != NULL) {
        fail("init recovery did not clear partially published function pointers");
    }

    if (plugin_init(NULL, &api) != 0) {
        fail("clean init failed after recovered init panic");
    }
    if (api.abi_version != 1 || api.call == NULL || api.free_buffer == NULL || api.shutdown == NULL) {
        fail("clean init did not publish the complete plugin API");
    }
    plugin_call = api.call;
    plugin_free = api.free_buffer;
    plugin_shutdown = api.shutdown;

    const char null_response_reconfigure_request[] =
        "{\"config_yaml\":\"account_protection_enabled: true\"}";
    if (plugin_call("plugin.reconfigure", (uint8_t *)null_response_reconfigure_request,
                    strlen(null_response_reconfigure_request), NULL) != 1) {
        fail("call with a NULL response buffer did not fail before method execution");
    }

    cliproxy_buffer response = {0};
    const char scheduler_probe_request[] =
        "{\"Provider\":\"codex\",\"Candidates\":[{\"ID\":\"null-response-sentinel\",\"Provider\":\"codex\"}]}";
    if (plugin_call("scheduler.pick", (uint8_t *)scheduler_probe_request,
                    strlen(scheduler_probe_request), &response) != 0) {
        fail("scheduler probe failed after the NULL response call");
    }
    if (!buffer_contains(&response, "\"Handled\":false")) {
        fail("NULL response validation dispatched plugin.reconfigure before failing");
    }
    plugin_free(response.ptr, response.len);

    response.ptr = NULL;
    response.len = 0;
    if (plugin_call("plugin.reconfigure", NULL, 1, &response) != 1) {
        fail("call with a NULL request pointer and non-zero length did not fail");
    }
    if (!buffer_contains(&response, "\"code\":\"invalid_request\"")) {
        fail("malformed request pointer response did not contain invalid_request");
    }
    plugin_free(response.ptr, response.len);

    response.ptr = NULL;
    response.len = 0;
    set_panic_point(PANIC_CALL);
    if (plugin_call("management.register", NULL, 0, &response) != 1) {
        fail("panic-injected call did not return failure");
    }
    require_safe_panic_response(&response);
    plugin_free(response.ptr, response.len);

    response.ptr = NULL;
    response.len = 0;
    set_panic_point(PANIC_CALL_AFTER_RESPONSE);
    if (plugin_call("management.register", NULL, 0, &response) != 1) {
        fail("post-response call panic did not return failure");
    }
    require_safe_panic_response(&response);
    plugin_free(response.ptr, response.len);

    response.ptr = NULL;
    response.len = 0;
    if (plugin_call("management.register", NULL, 0, &response) != 0 || response.ptr == NULL) {
        fail("clean call did not return a real plugin-owned response buffer");
    }
    void *real_plugin_pointer = response.ptr;
    size_t real_plugin_length = response.len;
    set_panic_point(PANIC_FREE);
    plugin_free(real_plugin_pointer, real_plugin_length);
    // The injected panic occurs before C.free. Reusing this exact pointer is
    // therefore safe and proves the test never fabricated a native address.
    plugin_free(real_plugin_pointer, real_plugin_length);

    const char register_request[] =
        "{\"config_yaml\":\"model_price_auto_update_enabled: false\\n"
        "summary_precompute_enabled: false\\nquota_trigger_enabled: false\\n"
        "account_protection_enabled: false\"}";
    response.ptr = NULL;
    response.len = 0;
    if (plugin_call("plugin.register", (uint8_t *)register_request, strlen(register_request), &response) != 0 || response.ptr == NULL) {
        fail("plugin.register failed before shutdown test");
    }
    plugin_free(response.ptr, response.len);

    // Open and initialize the lazy SQLite/WAL resources before taking the FD
    // baseline. Otherwise the leak check measures first-use initialization by
    // background maintenance rather than growth caused by the repeated ABI
    // calls themselves.
    const char usage_request[] =
        "{\"Provider\":\"codex\",\"Generate\":true,"
        "\"RequestedAt\":\"2026-07-16T00:00:00Z\","
        "\"Detail\":{\"TotalTokens\":1}}";
    json_call_and_free(plugin_call, plugin_free, "usage.handle", usage_request);
    const struct timespec warmup_delay = {.tv_sec = 0, .tv_nsec = 200000000L};
    nanosleep(&warmup_delay, NULL);

    // Warm the Go runtime and allocator before measuring. The repeated loop
    // covers both ordinary buffers and recovered call panics using real
    // plugin-owned allocations.
    for (int i = 0; i < 32; i++) {
        normal_call_and_free(plugin_call, plugin_free);
    }
    long rss_before = resident_bytes();
    int fds_before = open_fd_count();
    for (int i = 0; i < 1000; i++) {
        if (i % 10 != 0) {
            normal_call_and_free(plugin_call, plugin_free);
            continue;
        }
        response.ptr = NULL;
        response.len = 0;
        set_panic_point(PANIC_CALL_AFTER_RESPONSE);
        if (plugin_call("management.register", NULL, 0, &response) != 1) {
            fail("repeated panic-injected call did not fail safely");
        }
        require_safe_panic_response(&response);
        plugin_free(response.ptr, response.len);
    }
    long rss_after = resident_bytes();
    int fds_after = open_fd_count();
    printf("ABI repeated loop: rss_before=%ld rss_after=%ld fds_before=%d fds_after=%d\n",
           rss_before, rss_after, fds_before, fds_after);
    if (fds_before >= 0 && fds_after > fds_before + 2) {
        dump_open_fds();
        fail("repeated ABI loop leaked file descriptors");
    }
    if (rss_before >= 0 && rss_after > rss_before + (64L * 1024L * 1024L)) {
        fail("repeated ABI loop exceeded the 64 MiB RSS growth budget");
    }
    set_panic_point(PANIC_SHUTDOWN_SUMMARY_MAINTENANCE);
    plugin_shutdown();

    response.ptr = NULL;
    response.len = 0;
    if (plugin_call("management.register", NULL, 0, &response) != 1 || !buffer_contains(&response, "\"code\":\"plugin_stopped\"")) {
        fail("best-effort shutdown did not leave the plugin stopped");
    }
    plugin_free(response.ptr, response.len);

    set_panic_point(PANIC_SHUTDOWN_BOUNDARY);
    plugin_shutdown();

    if (dlclose(library) != 0) {
        fprintf(stderr, "dlclose failed: %s\n", dlerror());
        return 1;
    }
    puts("native C ABI panic boundary harness passed");
    return 0;
}
