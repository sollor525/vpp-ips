/*
 * ips_pcre_engine.c - VPP IPS PCRE/Regex Engine Integration
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include <vlib/vlib.h>
#include <vppinfra/hash.h>
#include <vppinfra/mem.h>
#include <vppinfra/string.h>

#include "ips_suricata_engine.h"
#include "ips_suricata_rule_types.h"
#include "../ips_logging.h"

/* Include PCRE headers */
#include <pcre.h>

/* Maximum number of PCRE captures */
#define IPS_PCRE_MAX_CAPTURES 128

/* PCRE pattern cache structure */
typedef struct ips_pcre_pattern_t {
    pcre *compiled_regex;         /* Compiled PCRE pattern */
    pcre_extra *study_data;       /* PCRE study data */
    char *pattern_string;         /* Original pattern string */
    u32 pattern_len;              /* Pattern length */
    u32 capture_count;            /* Number of capture groups */
    u32 options;                  /* PCRE compilation options */
    u32 rule_id;                  /* Associated rule ID */
    u8 is_valid;                  /* Pattern is valid and compiled */
} ips_pcre_pattern_t;

/* PCRE match context */
typedef struct ips_pcre_match_context_t {
    const char *subject;          /* Subject string */
    u32 subject_length;           /* Subject length */
    int *ovector;                 /* Output vector for matches */
    u32 ovector_size;             /* Size of output vector */
    u32 match_count;              /* Number of matches found */
    char **captures;              /* Capture group strings */
    u32 *capture_lengths;         /* Capture group lengths */
} ips_pcre_match_context_t;

/* Per-thread PCRE state */
typedef struct ips_pcre_thread_state_t {
    ips_pcre_match_context_t *match_context; /* Match context */
    u64 pattern_matches;          /* Total pattern matches */
    u64 total_compilations;       /* Total pattern compilations */
    u64 compilation_errors;       /* Compilation errors */
    f64 total_match_time;         /* Total time spent matching */
} ips_pcre_thread_state_t;

/* Global PCRE engine state */
typedef struct ips_pcre_engine_t {
    ips_pcre_pattern_t *patterns; /* Compiled patterns */
    u32 pattern_count;            /* Number of patterns */
    hash_t *pattern_hash;         /* Hash table for pattern lookup */
    ips_pcre_thread_state_t **thread_states; /* Per-thread states */
    u32 thread_count;             /* Number of threads */
    u8 initialized;               /* Engine initialized flag */
} ips_pcre_engine_t;

/* Global engine instance */
static ips_pcre_engine_t pcre_engine = {0};

/**
 * @brief Convert Suricata PCRE options to PCRE library options
 */
static u32
ips_suricata_to_pcre_options(const ips_pcre_match_t *suricata_pcre)
{
    u32 options = 0;

    if (!suricata_pcre)
        return options;

    /* Basic PCRE options from Suricata options */
    if (suricata_pcre->pcre_options & 0x01)  // PCRE_CASELESS
        options |= PCRE_CASELESS;
    if (suricata_pcre->pcre_options & 0x02)  // PCRE_MULTILINE
        options |= PCRE_MULTILINE;
    if (suricata_pcre->pcre_options & 0x04)  // PCRE_DOTALL
        options |= PCRE_DOTALL;
    if (suricata_pcre->pcre_options & 0x08)  // PCRE_EXTENDED
        options |= PCRE_EXTENDED;
    if (suricata_pcre->pcre_options & 0x10)  // PCRE_ANCHORED
        options |= PCRE_ANCHORED;
    if (suricata_pcre->pcre_options & 0x20)  // PCRE_DOLLAR_ENDONLY
        options |= PCRE_DOLLAR_ENDONLY;
    if (suricata_pcre->pcre_options & 0x40)  // PCRE_UNGREEDY
        options |= PCRE_UNGREEDY;

    return options;
}

/**
 * @brief Create per-thread PCRE state
 */
static ips_pcre_thread_state_t *
ips_pcre_init_thread_state(u32 thread_index)
{
    ips_pcre_thread_state_t *state =
        clib_mem_alloc(sizeof(ips_pcre_thread_state_t));
    if (!state)
        return NULL;

    clib_memset(state, 0, sizeof(*state));

    /* Create match context */
    state->match_context = clib_mem_alloc(sizeof(ips_pcre_match_context_t));
    if (!state->match_context) {
        clib_mem_free(state);
        return NULL;
    }

    clib_memset(state->match_context, 0, sizeof(*state->match_context));

    /* Allocate output vector for matches */
    state->match_context->ovector_size = (IPS_PCRE_MAX_CAPTURES + 1) * 3;
    state->match_context->ovector =
        clib_mem_alloc(state->match_context->ovector_size * sizeof(int));
    if (!state->match_context->ovector) {
        clib_mem_free(state->match_context);
        clib_mem_free(state);
        return NULL;
    }

    return state;
}

/**
 * @brief Initialize PCRE engine
 */
int
ips_pcre_engine_init(void)
{
    if (pcre_engine.initialized)
        return 0;

    /* Initialize thread states */
    pcre_engine.thread_count = vlib_get_n_threads();
    vec_validate(pcre_engine.thread_states, pcre_engine.thread_count - 1);

    for (u32 i = 0; i < pcre_engine.thread_count; i++) {
        pcre_engine.thread_states[i] = ips_pcre_init_thread_state(i);
        if (!pcre_engine.thread_states[i]) {
            ips_log_system_async(IPS_LOG_LEVEL_ERROR,
                                "Failed to initialize PCRE thread state %u", i);
            return -1;
        }
    }

    /* Initialize pattern hash table */
    pcre_engine.pattern_hash = hash_create(0, sizeof(uword));

    pcre_engine.initialized = 1;

    ips_log_system_async(IPS_LOG_LEVEL_INFO,
                        "PCRE engine initialized for %u threads",
                        pcre_engine.thread_count);

    return 0;
}

/**
 * @brief Cleanup PCRE engine
 */
void
ips_pcre_engine_cleanup(void)
{
    if (!pcre_engine.initialized)
        return;

    /* Free compiled patterns */
    if (pcre_engine.patterns) {
        for (u32 i = 0; i < pcre_engine.pattern_count; i++) {
            ips_pcre_pattern_t *pattern = &pcre_engine.patterns[i];
            if (pattern->compiled_regex)
                pcre_free(pattern->compiled_regex);
            if (pattern->study_data)
                pcre_free_study(pattern->study_data);
            if (pattern->pattern_string)
                clib_mem_free(pattern->pattern_string);
        }
        vec_free(pcre_engine.patterns);
    }

    /* Free thread states */
    if (pcre_engine.thread_states) {
        for (u32 i = 0; i < pcre_engine.thread_count; i++) {
            if (pcre_engine.thread_states[i]) {
                if (pcre_engine.thread_states[i]->match_context) {
                    if (pcre_engine.thread_states[i]->match_context->ovector)
                        clib_mem_free(pcre_engine.thread_states[i]->match_context->ovector);
                    clib_mem_free(pcre_engine.thread_states[i]->match_context);
                }
                clib_mem_free(pcre_engine.thread_states[i]);
            }
        }
        vec_free(pcre_engine.thread_states);
    }

    /* Free hash table */
    if (pcre_engine.pattern_hash)
        hash_free(pcre_engine.pattern_hash);

    clib_memset(&pcre_engine, 0, sizeof(pcre_engine));
}

/**
 * @brief Compile a PCRE pattern
 */
static int
ips_pcre_compile_pattern(ips_pcre_pattern_t *pattern, const char *pattern_str,
                         u32 pattern_len, u32 options)
{
    if (!pattern || !pattern_str || pattern_len == 0)
        return -1;

    const char *error;
    int erroffset;

    /* Compile the pattern */
    pattern->compiled_regex = pcre_compile(
        pattern_str,
        options,
        &error,
        &erroffset,
        NULL        // Use default character tables
    );

    if (!pattern->compiled_regex) {
        ips_log_system_async(IPS_LOG_LEVEL_ERROR,
                            "PCRE compilation failed at offset %d: %s",
                            erroffset, error ? error : "Unknown error");
        return -1;
    }

    /* Study the pattern for optimization */
    pattern->study_data = pcre_study(
        pattern->compiled_regex,
        PCRE_STUDY_JIT_COMPILE,  /* Enable JIT if available */
        &error
    );

    if (error) {
        ips_log_system_async(IPS_LOG_LEVEL_WARNING,
                            "PCRE study failed: %s", error);
        /* Study failure is not fatal, continue without optimization */
    }

    /* Get pattern information */
    int info;
    if (pcre_fullinfo(pattern->compiled_regex, pattern->study_data,
                     PCRE_INFO_CAPTURECOUNT, &info) == 0) {
        pattern->capture_count = info;
    }

    /* Store pattern information */
    pattern->pattern_string = clib_mem_alloc(pattern_len + 1);
    if (pattern->pattern_string) {
        clib_memcpy(pattern->pattern_string, pattern_str, pattern_len);
        pattern->pattern_string[pattern_len] = '\0';
        pattern->pattern_len = pattern_len;
    }
    pattern->options = options;
    pattern->is_valid = 1;

    return 0;
}

/**
 * @brief Add PCRE pattern from Suricata rule
 */
int
ips_pcre_engine_add_pattern(ips_pcre_match_t *suricata_pcre, u32 rule_id)
{
    if (!pcre_engine.initialized) {
        if (ips_pcre_engine_init() != 0)
            return -1;
    }

    if (!suricata_pcre || !suricata_pcre->pattern)
        return -1;

    /* Create new pattern entry */
    vec_validate(pcre_engine.patterns, pcre_engine.pattern_count);
    ips_pcre_pattern_t *pattern = &pcre_engine.patterns[pcre_engine.pattern_count];

    /* Convert Suricata PCRE options */
    u32 pcre_options = ips_suricata_to_pcre_options(suricata_pcre);

    /* Compile the pattern */
    if (ips_pcre_compile_pattern(pattern, suricata_pcre->pattern,
                                suricata_pcre->pattern_len, pcre_options) != 0) {
        ips_log_system_async(IPS_LOG_LEVEL_ERROR,
                            "Failed to compile PCRE pattern for rule %u", rule_id);
        return -1;
    }

    pattern->rule_id = rule_id;

    /* Add to hash table for quick lookup */
    hash_set(pcre_engine.pattern_hash, rule_id, pcre_engine.pattern_count);

    pcre_engine.pattern_count++;

    ips_log_system_async(IPS_LOG_LEVEL_DEBUG,
                        "Added PCRE pattern for rule %u (total: %u)",
                        rule_id, pcre_engine.pattern_count);

    return 0;
}

/**
 * @brief Match data against compiled PCRE pattern
 */
int
ips_pcre_engine_match_pattern(u32 rule_id, const u8 *data, u32 data_len,
                             u32 offset, u32 *matches_found)
{
    if (!pcre_engine.initialized || !data || data_len == 0 || !matches_found)
        return -1;

    u32 thread_index = vlib_get_thread_index();
    if (thread_index >= pcre_engine.thread_count)
        return -1;

    ips_pcre_thread_state_t *thread_state = pcre_engine.thread_states[thread_index];
    if (!thread_state || !thread_state->match_context)
        return -1;

    /* Find pattern in hash table */
    uword *pattern_index = hash_get(pcre_engine.pattern_hash, rule_id);
    if (!pattern_index) {
        ips_log_system_async(IPS_LOG_LEVEL_DEBUG,
                            "No PCRE pattern found for rule %u", rule_id);
        *matches_found = 0;
        return 0;
    }

    if (*pattern_index >= pcre_engine.pattern_count) {
        ips_log_system_async(IPS_LOG_LEVEL_ERROR,
                            "Invalid pattern index %u for rule %u",
                            *pattern_index, rule_id);
        return -1;
    }

    ips_pcre_pattern_t *pattern = &pcre_engine.patterns[*pattern_index];
    if (!pattern->is_valid) {
        ips_log_system_async(IPS_LOG_LEVEL_WARNING,
                            "Invalid PCRE pattern for rule %u", rule_id);
        *matches_found = 0;
        return 0;
    }

    f64 start_time = vlib_time_now(vlib_get_main());

    /* Setup match context */
    ips_pcre_match_context_t *ctx = thread_state->match_context;
    ctx->subject = (const char *)data + offset;
    ctx->subject_length = data_len - offset;

    /* Execute the match */
    int rc = pcre_exec(
        pattern->compiled_regex,
        pattern->study_data,
        ctx->subject,
        ctx->subject_length,
        0,              /* Start at offset 0 in subject */
        0,              /* Default options */
        ctx->ovector,
        ctx->ovector_size
    );

    f64 end_time = vlib_time_now(vlib_get_main());
    thread_state->total_match_time += (end_time - start_time);

    if (rc < 0) {
        /* No match or error */
        if (rc == PCRE_ERROR_NOMATCH) {
            *matches_found = 0;
            return 0;
        } else {
            ips_log_system_async(IPS_LOG_LEVEL_ERROR,
                                "PCRE match error %d for rule %u", rc, rule_id);
            return -1;
        }
    }

    /* Match found - rc is the number of substrings matched */
    ctx->match_count = rc;
    *matches_found = rc;

    thread_state->pattern_matches++;

    ips_log_system_async(IPS_LOG_LEVEL_DEBUG,
                        "PCRE match found for rule %u: %u substrings",
                        rule_id, rc);

    return 0;
}

/**
 * @brief Get PCRE engine statistics
 */
void
ips_pcre_engine_get_stats(u64 *total_matches, u64 *total_compilations,
                         u64 *compilation_errors, f64 *avg_match_time)
{
    if (!pcre_engine.initialized) {
        if (total_matches) *total_matches = 0;
        if (total_compilations) *total_compilations = 0;
        if (compilation_errors) *compilation_errors = 0;
        if (avg_match_time) *avg_match_time = 0.0;
        return;
    }

    u64 matches = 0;
    u64 compilations = 0;
    u64 errors = 0;
    f64 total_time = 0.0;
    u64 total_scans = 0;

    for (u32 i = 0; i < pcre_engine.thread_count; i++) {
        ips_pcre_thread_state_t *state = pcre_engine.thread_states[i];
        if (state) {
            matches += state->pattern_matches;
            compilations += state->total_compilations;
            errors += state->compilation_errors;
            total_time += state->total_match_time;
            total_scans += state->pattern_matches; /* Approximation */
        }
    }

    if (total_matches) *total_matches = matches;
    if (total_compilations) *total_compilations = compilations;
    if (compilation_errors) *compilation_errors = errors;
    if (avg_match_time) *avg_match_time = (total_scans > 0) ? (total_time / total_scans) : 0.0;
}

/**
 * @brief Reset PCRE engine statistics
 */
void
ips_pcre_engine_reset_stats(void)
{
    if (!pcre_engine.initialized)
        return;

    for (u32 i = 0; i < pcre_engine.thread_count; i++) {
        ips_pcre_thread_state_t *state = pcre_engine.thread_states[i];
        if (state) {
            state->pattern_matches = 0;
            state->total_compilations = 0;
            state->compilation_errors = 0;
            state->total_match_time = 0.0;
        }
    }
}