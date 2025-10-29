/*
 * ips_hyperscan_engine.c - VPP IPS Hyperscan Integration Engine
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

/* Include Hyperscan headers */
#include <hs/hs.h>
#include <hs/hs_common.h>
#include <hs/hs_compile.h>
#include <hs/hs_runtime.h>

/* Maximum number of patterns in a single database */
#define IPS_HS_MAX_PATTERNS 1024

/* Hyperscan compile flags */
#define IPS_HS_DEFAULT_FLAGS (HS_FLAG_CASELESS | HS_FLAG_SOM_LEFTMOST)

/* Hyperscan pattern database structure */
typedef struct ips_hs_database_t {
    hs_database_t *hs_db;           /* Compiled Hyperscan database */
    hs_scratch_t *hs_scratch;       /* Scratch space for matching */
    u32 *rule_ids;                  /* Rule ID mapping for each pattern */
    u32 pattern_count;              /* Number of patterns in database */
    char *patterns[IPS_HS_MAX_PATTERNS]; /* Pattern strings */
    unsigned int flags[IPS_HS_MAX_PATTERNS]; /* Pattern flags */
    unsigned int ids[IPS_HS_MAX_PATTERNS];   /* Pattern IDs */
    u8 is_valid;                    /* Database is valid and ready */
} ips_hs_database_t;

/* Per-thread Hyperscan state */
typedef struct ips_hs_thread_state_t {
    hs_scratch_t *scratch;          /* Thread-local scratch space */
    u64 match_count;                /* Number of matches found */
    u64 total_scans;                /* Total packets scanned */
    f64 total_scan_time;            /* Total time spent scanning */
} ips_hs_thread_state_t;

/* Global Hyperscan engine state */
typedef struct ips_hs_engine_t {
    ips_hs_database_t *databases;   /* Multiple databases for different protocols */
    u32 database_count;             /* Number of databases */
    hash_t *rule_to_db_map;         /* Map rule ID to database index */
    ips_hs_thread_state_t **thread_states; /* Per-thread states */
    u32 thread_count;               /* Number of threads */
    u8 initialized;                 /* Engine initialized flag */
} ips_hs_engine_t;

/* Global engine instance */
static ips_hs_engine_t hs_engine = {0};

/**
 * @brief Hyperscan match callback function
 */
static int
ips_hs_match_handler(unsigned int id, unsigned long long from,
                    unsigned long long to, unsigned int flags, void *context)
{
    ips_packet_context_t *packet_ctx = (ips_packet_context_t *)context;
    if (!packet_ctx)
        return 0;

    /* Find the rule that corresponds to this pattern ID */
    u32 rule_id = 0;
    ips_suricata_rule_t *rule = NULL;

    /* Look up rule ID from pattern ID using engine's rule_to_db_map */
    uword *p = hash_get(hs_engine.rule_to_db_map, id);
    if (p) {
        u32 db_index = p[0];
        if (db_index < hs_engine.database_count) {
            ips_hs_database_t *db = &hs_engine.databases[db_index];
            if (id < db->pattern_count) {
                rule_id = db->rule_ids[id];
                /* Get rule from global rule table - this requires integration with rule engine */
                // rule = ips_rule_table_get_by_id(rule_id);
            }
        }
    }

    ips_log_system_async(IPS_LOG_LEVEL_DEBUG,
                        "Hyperscan match: pattern %u (rule %u) at offset %llu-%llu",
                        id, rule_id, from, to);

    /* Add match to packet context */
    if (packet_ctx->matches_found < IPS_MAX_MATCHES_PER_PACKET) {
        /* Store match information using existing packet context structure */
        /* Note: ips_packet_context_t has matched_rules array but not detailed match info */
        packet_ctx->matched_rules[packet_ctx->matches_found] = rule;  /* Set matched rule */
        /* TODO: We need to extend ips_packet_context_t to include detailed match offsets */

        packet_ctx->matches_found++;

        ips_log_system_async(IPS_LOG_LEVEL_DEBUG,
                            "Stored match %u: rule %u, pattern %u, offset %llu, length %llu",
                            packet_ctx->matches_found, rule_id, id, from, to - from);
    }

    return 0; /* Continue matching */
}

/**
 * @brief Initialize per-thread Hyperscan state
 */
static ips_hs_thread_state_t *
ips_hs_init_thread_state(u32 thread_index)
{
    ips_hs_thread_state_t *state =
        clib_mem_alloc(sizeof(ips_hs_thread_state_t));
    if (!state)
        return NULL;

    clib_memset(state, 0, sizeof(*state));

    /* Create scratch space - use the first database's scratch as template */
    if (hs_engine.database_count > 0 && hs_engine.databases[0].hs_scratch) {
        if (hs_clone_scratch(hs_engine.databases[0].hs_scratch, &state->scratch) != HS_SUCCESS) {
            clib_mem_free(state);
            return NULL;
        }
    }

    return state;
}

/**
 * @brief Initialize Hyperscan engine
 */
int
ips_hyperscan_engine_init(void)
{
    if (hs_engine.initialized)
        return 0;

    /* Initialize thread states */
    hs_engine.thread_count = vlib_get_n_threads();
    vec_validate(hs_engine.thread_states, hs_engine.thread_count - 1);

    for (u32 i = 0; i < hs_engine.thread_count; i++) {
        hs_engine.thread_states[i] = ips_hs_init_thread_state(i);
        if (!hs_engine.thread_states[i]) {
            ips_log_system_async(IPS_LOG_LEVEL_ERROR,
                                "Failed to initialize Hyperscan thread state %u", i);
            return -1;
        }
    }

    /* Initialize rule to database mapping */
    hs_engine.rule_to_db_map = hash_create(0, sizeof(uword));

    hs_engine.initialized = 1;

    ips_log_system_async(IPS_LOG_LEVEL_INFO,
                        "Hyperscan engine initialized for %u threads",
                        hs_engine.thread_count);

    return 0;
}

/**
 * @brief Cleanup Hyperscan engine
 */
void
ips_hyperscan_engine_cleanup(void)
{
    if (!hs_engine.initialized)
        return;

    /* Free databases */
    if (hs_engine.databases) {
        for (u32 i = 0; i < hs_engine.database_count; i++) {
            ips_hs_database_t *db = &hs_engine.databases[i];
            if (db->hs_db)
                hs_free_database(db->hs_db);
            if (db->hs_scratch)
                hs_free_scratch(db->hs_scratch);
            if (db->rule_ids)
                vec_free(db->rule_ids);
            for (u32 j = 0; j < db->pattern_count; j++) {
                if (db->patterns[j])
                    clib_mem_free(db->patterns[j]);
            }
        }
        vec_free(hs_engine.databases);
    }

    /* Free thread states */
    if (hs_engine.thread_states) {
        for (u32 i = 0; i < hs_engine.thread_count; i++) {
            if (hs_engine.thread_states[i]) {
                if (hs_engine.thread_states[i]->scratch)
                    hs_free_scratch(hs_engine.thread_states[i]->scratch);
                clib_mem_free(hs_engine.thread_states[i]);
            }
        }
        vec_free(hs_engine.thread_states);
    }

    /* Free hash table */
    if (hs_engine.rule_to_db_map)
        hash_free(hs_engine.rule_to_db_map);

    clib_memset(&hs_engine, 0, sizeof(hs_engine));
}

/**
 * @brief Compile Suricata rule patterns into Hyperscan database
 */
static int
ips_hs_compile_patterns(ips_suricata_rule_t **rules, u32 rule_count,
                       ips_hs_database_t *database)
{
    if (!rules || !database || rule_count == 0)
        return -1;

    /* Prepare patterns for compilation */
    database->pattern_count = 0;

    for (u32 i = 0; i < rule_count && database->pattern_count < IPS_HS_MAX_PATTERNS; i++) {
        ips_suricata_rule_t *rule = rules[i];
        if (!rule || !rule->enabled || rule->content_count == 0)
            continue;

        /* Add each content pattern to the database */
        for (u32 j = 0; j < rule->content_count && database->pattern_count < IPS_HS_MAX_PATTERNS; j++) {
            ips_content_match_t *content = &rule->contents[j];
            if (!content->pattern || content->pattern_len == 0)
                continue;

            /* Convert content pattern to string */
            char *pattern_str = clib_mem_alloc(content->pattern_len * 2 + 1);
            if (!pattern_str)
                continue;

            /* Simple hex-to-string conversion for binary patterns */
            for (u32 k = 0; k < content->pattern_len; k++) {
                sprintf(&pattern_str[k * 2], "%02x", content->pattern[k]);
            }

            database->patterns[database->pattern_count] = pattern_str;
            database->flags[database->pattern_count] = IPS_HS_DEFAULT_FLAGS;
            database->ids[database->pattern_count] = database->pattern_count;
            database->pattern_count++;
        }
    }

    if (database->pattern_count == 0) {
        ips_log_system_async(IPS_LOG_LEVEL_WARNING,
                            "No valid patterns found for compilation");
        return -1;
    }

    /* Compile the database */
    hs_compile_error_t *compile_err = NULL;
    hs_error_t err = hs_compile_multi(
        (const char **)database->patterns,
        database->flags,
        database->ids,
        database->pattern_count,
        HS_MODE_BLOCK,  /* Block mode for packet inspection */
        NULL,           /* Platform info (auto-detect) */
        &database->hs_db,
        &compile_err
    );

    if (err != HS_SUCCESS) {
        ips_log_system_async(IPS_LOG_LEVEL_ERROR,
                            "Hyperscan compilation failed: %s",
                            compile_err ? compile_err->message : "Unknown error");
        if (compile_err)
            hs_free_compile_error(compile_err);
        return -1;
    }

    /* Allocate scratch space */
    err = hs_alloc_scratch(database->hs_db, &database->hs_scratch);
    if (err != HS_SUCCESS) {
        ips_log_system_async(IPS_LOG_LEVEL_ERROR,
                            "Failed to allocate Hyperscan scratch space");
        hs_free_database(database->hs_db);
        database->hs_db = NULL;
        return -1;
    }

    database->is_valid = 1;

    ips_log_system_async(IPS_LOG_LEVEL_INFO,
                        "Successfully compiled %u patterns into Hyperscan database",
                        database->pattern_count);

    return 0;
}

/**
 * @brief Add rules to Hyperscan engine
 */
int
ips_hyperscan_engine_add_rules(ips_suricata_rule_t **rules, u32 rule_count)
{
    if (!hs_engine.initialized) {
        if (ips_hyperscan_engine_init() != 0)
            return -1;
    }

    if (!rules || rule_count == 0)
        return -1;

    /* Create a new database */
    vec_validate(hs_engine.databases, hs_engine.database_count);
    ips_hs_database_t *database = &hs_engine.databases[hs_engine.database_count];
    clib_memset(database, 0, sizeof(*database));

    /* Compile patterns */
    if (ips_hs_compile_patterns(rules, rule_count, database) != 0) {
        ips_log_system_async(IPS_LOG_LEVEL_ERROR,
                            "Failed to compile patterns for Hyperscan database");
        return -1;
    }

    /* Update thread scratch spaces if needed */
    for (u32 i = 0; i < hs_engine.thread_count; i++) {
        if (hs_engine.thread_states[i] && !hs_engine.thread_states[i]->scratch) {
            hs_clone_scratch(database->hs_scratch, &hs_engine.thread_states[i]->scratch);
        }
    }

    hs_engine.database_count++;

    ips_log_system_async(IPS_LOG_LEVEL_INFO,
                        "Added Hyperscan database %u with %u patterns",
                        hs_engine.database_count - 1, database->pattern_count);

    return 0;
}

/**
 * @brief Scan packet data with Hyperscan
 */
int
ips_hyperscan_engine_scan_packet(ips_packet_context_t *packet_ctx,
                                const u8 *data, u32 data_len)
{
    if (!hs_engine.initialized || !packet_ctx || !data || data_len == 0)
        return -1;

    u32 thread_index = vlib_get_thread_index();
    if (thread_index >= hs_engine.thread_count)
        return -1;

    ips_hs_thread_state_t *thread_state = hs_engine.thread_states[thread_index];
    if (!thread_state || !thread_state->scratch)
        return -1;

    f64 start_time = vlib_time_now(vlib_get_main());

    /* Scan with all available databases */
    for (u32 i = 0; i < hs_engine.database_count; i++) {
        ips_hs_database_t *database = &hs_engine.databases[i];
        if (!database->is_valid)
            continue;

        hs_error_t err = hs_scan(
            database->hs_db,
            (const char *)data,
            data_len,
            0,          /* No flags */
            thread_state->scratch,
            ips_hs_match_handler,
            packet_ctx
        );

        if (err != HS_SUCCESS && err != HS_SCAN_TERMINATED) {
            ips_log_system_async(IPS_LOG_LEVEL_ERROR,
                                "Hyperscan scan failed on database %u: %d", i, err);
            continue;
        }
    }

    f64 end_time = vlib_time_now(vlib_get_main());
    thread_state->total_scans++;
    thread_state->total_scan_time += (end_time - start_time);

    return packet_ctx->matches_found;
}

/**
 * @brief Get Hyperscan engine statistics
 */
void
ips_hyperscan_engine_get_stats(u64 *total_scans, u64 *total_matches,
                              f64 *avg_scan_time)
{
    if (!hs_engine.initialized) {
        if (total_scans) *total_scans = 0;
        if (total_matches) *total_matches = 0;
        if (avg_scan_time) *avg_scan_time = 0.0;
        return;
    }

    u64 scans = 0;
    u64 matches = 0;
    f64 total_time = 0.0;

    for (u32 i = 0; i < hs_engine.thread_count; i++) {
        ips_hs_thread_state_t *state = hs_engine.thread_states[i];
        if (state) {
            scans += state->total_scans;
            matches += state->match_count;
            total_time += state->total_scan_time;
        }
    }

    if (total_scans) *total_scans = scans;
    if (total_matches) *total_matches = matches;
    if (avg_scan_time) *avg_scan_time = (scans > 0) ? (total_time / scans) : 0.0;
}

/**
 * @brief Reset Hyperscan engine statistics
 */
void
ips_hyperscan_engine_reset_stats(void)
{
    if (!hs_engine.initialized)
        return;

    for (u32 i = 0; i < hs_engine.thread_count; i++) {
        ips_hs_thread_state_t *state = hs_engine.thread_states[i];
        if (state) {
            state->match_count = 0;
            state->total_scans = 0;
            state->total_scan_time = 0.0;
        }
    }
}