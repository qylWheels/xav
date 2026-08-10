#include "vmlinux.h"

// XXX: vmlinux.h must be at top.

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "xavcore/protection/hips/rules/raw_rule.h"

#define PREFIX "xavcore hips monitor: "

struct all_rules {
    struct Rule rules[MAX_RULE_COUNT];
    u32 rule_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);

    // XXX: Must use __uint() and *_size, or clang will complain
    // about __type(value, struct Rule).
    __uint(key_size, 4);
    __uint(value_size, sizeof(struct all_rules));
} hips_rules SEC(".maps");

// If s1 or s2 is NULL, return false.
u8 str_is_equal(const char *s1, const char *s2) {
    const int max_len = MAX_PATH_LEN;

    if (s1 == NULL || s2 == NULL) {
        return 0;
    }

    int i;
    char c1, c2;
    bpf_for(i, 0, max_len) {
        bpf_probe_read_kernel(&c1, sizeof(c1), s1 + i);
        bpf_probe_read_kernel(&c2, sizeof(c2), s2 + i);

        if (c1 == '\0' || c2 == '\0') {
            if (c1 == c2) {
                return 1;
            } else {
                return 0;
            }
        }

        if (c1 != c2) {
            return 0;
        }
    }

    return 0;
}

// Not contain '\0'.
u64 str_len(const char *s) {
    u64 i = 0;
    char c;
    for (i = 0; i < MAX_PATH_LEN; ++i) {
        bpf_probe_read_kernel(&c, sizeof(c), s + i);
        if (c == '\0') {
            break;
        }
    }
    return i;
}

struct dp_ctx {
    u8 arr[MAX_PATH_LEN + 5];
    const char *pattern;
    u64 pattern_len;
    const char *s;
    u64 s_len;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct dp_ctx);
} dp SEC(".maps");

static long dp_callback(u64 i, void *ctx) {
    int zero = 0;
    struct dp_ctx *dp_ctx = (struct dp_ctx *)bpf_map_lookup_elem(&dp, &zero);
    if (dp_ctx == NULL) {
        // This is unreachable.
        return 1;
    };
    if (i >= dp_ctx->pattern_len) {
        return 1;  // End bpf_loop().
    }

    char c1, c2;
    bpf_probe_read_kernel(&c1, sizeof(c1), dp_ctx->pattern + i);

    // left_up is prev[0].
    bool left_up = dp_ctx->arr[0];

    // Only consecutive '*' can match empty string.
    dp_ctx->arr[0] = (dp_ctx->arr[0] && c1 == '*');

    for (int j = 1; j <= dp_ctx->s_len && j <= MAX_PATTERN_LEN; j++) {
        // Up is prev[j]
        u8 up = dp_ctx->arr[j];

        if (c1 == '*') {
            // Match 0 time: dp[j]
            // Match multiple times: dp[j-1]
            dp_ctx->arr[j] = (up || dp_ctx->arr[j - 1]);
        } else {
            // Match '?' or normal letter: dp[j]
            bpf_probe_read_kernel(&c2, sizeof(c2), dp_ctx->s + j - 1);
            u8 match = (c1 == '?') || (c1 == c2);
            dp_ctx->arr[j] = (left_up && match);
        }

        left_up = up;
    }

    return 0;
}

u8 str_is_match_pat(const char *pattern, const char *s) {
    int i, j;
    int zero = 0, one = 1;
    char c1, c2;

    if (pattern == NULL || s == NULL) {
        return 0;
    }

    // Initialize
    struct dp_ctx *ctx = (struct dp_ctx *)bpf_map_lookup_elem(&dp, &zero);
    if (ctx == NULL) {
        // This is unreachable.
        return 0;
    }
    ctx->arr[0] = 1;
    for (i = 1; i <= MAX_PATH_LEN; i++) {
        ctx->arr[i] = 0;
    }
    ctx->pattern = pattern;
    ctx->pattern_len = str_len(pattern);
    ctx->s = s;
    ctx->s_len = str_len(s);

    // Do dp.
    bpf_loop(ctx->pattern_len, (void *)dp_callback, NULL, 0);

    if (ctx->s_len <= MAX_PATTERN_LEN) {
        return ctx->arr[ctx->s_len];
    } else {
        // Unreachable.
        return 0;
    }
}

struct pathbuf {
    char path[MAX_PATH_LEN + 5];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 8);
    __type(key, int);
    __type(value, struct pathbuf);
} pathbuf SEC(".maps");

struct match_context {
    u8 path_index;
    u8 allow;
};

static long match_rule_callback(u64 i, void *ctx) {
    struct match_context *c = (struct match_context *)ctx;
    u32 zero = 0;

    // Get all rules.
    struct all_rules *all_rules =
        (struct all_rules *)bpf_map_lookup_elem(&hips_rules, &zero);
    if (all_rules == NULL) {
        // Unreachable.
        return 0;
    }

    if (i >= all_rules->rule_count || i >= MAX_RULE_COUNT) {
        return 1;  // End loop.
    }

    // Get path.
    struct pathbuf *path =
        (struct pathbuf *)bpf_map_lookup_elem(&pathbuf, &c->path_index);
    if (path == NULL) {
        // Unreachable.
        return 0;
    }

    struct Rule *rule = &all_rules->rules[i];
    switch (rule->tag) {
        case 0: {
            struct FileRule *file_rule = &rule->u.file_rule;
            char pattern[16] = "*/f*ks??t";
            if (str_is_match_pat((const char *)pattern,
                                 (const char *)path->path) == 1) {
                c->allow = 0;
            }
            return 1;  // End loop.
        }
    }

    return 0;
}

SEC("lsm/path_unlink")
int BPF_PROG(path_unlink_monitor, struct path *dir, struct dentry *dentry) {
    int zero = 0, one = 1;
    struct pathbuf *pathbuf0 =
        (struct pathbuf *)bpf_map_lookup_elem(&pathbuf, &zero);
    struct pathbuf *pathbuf1 =
        (struct pathbuf *)bpf_map_lookup_elem(&pathbuf, &one);
    if (pathbuf0 == NULL || pathbuf1 == NULL) {
        // This is unreachable.
        return 0;
    }
    bpf_d_path(dir, pathbuf0->path, MAX_PATH_LEN);
    BPF_SNPRINTF(pathbuf1->path, MAX_PATH_LEN, "%s/%s", (u64)pathbuf0->path,
                 (u64)dentry->d_name.name);
    bpf_printk(PREFIX "path_unlink_monitor is triggered: %s\n", pathbuf1->path);

    struct match_context c = {1, 1};
    bpf_loop(MAX_RULE_COUNT, (void *)match_rule_callback, &c, 0);
    if (!c.allow) {
        return -1;
    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
