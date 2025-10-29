/*
 * ips_flowbits.c - VPP IPS Flowbits Implementation
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include <vlib/vlib.h>
#include <vppinfra/hash.h>
#include <vppinfra/string.h>

#include "ips_suricata_engine.h"
#include "ips_suricata_rule_types.h"
#include "../session/ips_session.h"
#include "../ips_logging.h"

/* Flowbit state entry - defined in ips_suricata_engine.h */

/* Flowbit key for hash */
typedef struct {
    u32 session_id;
    u32 flowbit_name_hash;
} ips_flowbit_key_t;

/* Per-thread flowbit storage */
typedef struct {
    hash_t *flowbit_hash;
    u32 cleanup_counter;
    f64 last_cleanup_time;
    u64 total_operations;
    u64 cache_hits;
    u64 cache_misses;
} ips_flowbit_storage_t;

/* Get per-thread flowbit storage */
static ips_flowbit_storage_t *
ips_get_flowbit_storage(void)
{
    static ips_flowbit_storage_t *storage = NULL;
    static u32 num_threads = 0;

    u32 thread_index = vlib_get_thread_index();

    if (storage == NULL) {
        num_threads = vlib_get_n_threads();
        vec_validate(storage, num_threads - 1);
    }

    if (storage[thread_index].flowbit_hash == NULL) {
        storage[thread_index].flowbit_hash = hash_create(0, sizeof(uword));
        storage[thread_index].last_cleanup_time = vlib_time_now(vlib_get_main());
    }

    return &storage[thread_index];
}

/**
 * @brief Compute flowbit name hash
 */
static u32
ips_flowbit_name_hash(const char *name)
{
    u32 hash = 5381;
    int c;

    while ((c = *name++)) {
        hash = ((hash << 5) + hash) + c;  /* hash * 33 + c */
    }

    return hash;
}

/**
 * @brief Create flowbit key
 */
static ips_flowbit_key_t
ips_flowbit_make_key(u32 session_id, const char *flowbit_name)
{
    ips_flowbit_key_t key;
    key.session_id = session_id;
    key.flowbit_name_hash = ips_flowbit_name_hash(flowbit_name);
    return key;
}

/**
 * @brief Get or create flowbit state
 */
static ips_flowbit_state_t *
ips_get_flowbit_state(u32 session_id, const char *flowbit_name)
{
    ips_flowbit_storage_t *storage = ips_get_flowbit_storage();
    ips_flowbit_key_t key = ips_flowbit_make_key(session_id, flowbit_name);

    uword *p = hash_get(storage->flowbit_hash, key.session_id ^ key.flowbit_name_hash);
    if (p) {
        storage->cache_hits++;
        return (ips_flowbit_state_t *)p[0];
    }

    /* Create new flowbit state */
    ips_flowbit_state_t *state = clib_mem_alloc(sizeof(ips_flowbit_state_t));
    if (!state) {
        storage->total_operations++;
        return NULL;
    }

    clib_memset(state, 0, sizeof(*state));
    state->set_time = vlib_time_now(vlib_get_main());

    hash_set(storage->flowbit_hash,
             key.session_id ^ key.flowbit_name_hash, (uword)state);

    storage->cache_misses++;
    storage->total_operations++;

    return state;
}

/**
 * @brief Set flowbit for session
 */
int
ips_flowbit_set(ips_session_t *session, const char *flowbit_name,
                u32 thread_index)
{
    if (!session || !flowbit_name)
        return -1;

    ips_flowbit_state_t *state = ips_get_flowbit_state(session->session_index, flowbit_name);
    if (!state)
        return -1;

    state->is_set = 1;
    state->set_time = vlib_time_now(vlib_get_main());
    state->set_packet_count = session->packet_count_src + session->packet_count_dst;

    return 0;
}

/**
 * @brief Unset flowbit for session
 */
int
ips_flowbit_unset(ips_session_t *session, const char *flowbit_name,
                  u32 thread_index)
{
    if (!session || !flowbit_name)
        return -1;

    ips_flowbit_state_t *state = ips_get_flowbit_state(session->session_index, flowbit_name);
    if (!state)
        return -1;

    state->is_set = 0;
    state->access_count++;

    return 0;
}

/**
 * @brief Check if flowbit is set
 */
int
ips_flowbit_is_set(ips_session_t *session, const char *flowbit_name,
                   u32 thread_index)
{
    if (!session || !flowbit_name)
        return 0;

    ips_flowbit_state_t *state = ips_get_flowbit_state(session->session_index, flowbit_name);
    if (!state)
        return 0;

    state->access_count++;
    return state->is_set;
}

/**
 * @brief Check if flowbit is not set
 */
int
ips_flowbit_is_not_set(ips_session_t *session, const char *flowbit_name,
                       u32 thread_index)
{
    return !ips_flowbit_is_set(session, flowbit_name, thread_index);
}

/**
 * @brief Execute flowbit operation
 */
int
ips_flowbit_execute_operation(ips_session_t *session,
                              const ips_flowbit_t *flowbit,
                              u32 thread_index)
{
    if (!session || !flowbit)
        return -1;

    int result = 0;

    switch (flowbit->operation) {
    case IPS_FLOWBIT_SET:
        result = ips_flowbit_set(session, flowbit->name, thread_index);
        break;

    case IPS_FLOWBIT_UNSET:
        result = ips_flowbit_unset(session, flowbit->name, thread_index);
        break;

    case IPS_FLOWBIT_ISSET:
        result = ips_flowbit_is_set(session, flowbit->name, thread_index);
        break;

    case IPS_FLOWBIT_ISNOTSET:
        result = ips_flowbit_is_not_set(session, flowbit->name, thread_index);
        break;

    case IPS_FLOWBIT_NOALERT:
        /* Set flowbit but don't generate alert */
        result = ips_flowbit_set(session, flowbit->name, thread_index);
        if (result == 0) {
            /* Mark as noalert by setting a special flag in flowbit state */
            ips_flowbit_state_t *state = ips_get_flowbit_state(session->session_index, flowbit->name);
            if (state) {
                state->is_persistent = 1;  /* Use this flag for noalert */
            }
        }
        break;

    default:
        return -1;
    }

    return result;
}

/**
 * @brief Check flowbits for a rule
 */
int
ips_flowbits_check_rule(ips_suricata_rule_t *rule,
                        ips_session_t *session,
                        u32 thread_index)
{
    if (!rule || !session || rule->flowbit_count == 0)
        return 1;  /* No flowbits to check, rule passes */

    u32 thread_idx = thread_index;
    if (thread_idx == (u32)-1)
        thread_idx = vlib_get_thread_index();

    for (u32 i = 0; i < rule->flowbit_count; i++) {
        ips_flowbit_t *flowbit = &rule->flowbits[i];

        int result = ips_flowbit_execute_operation(session, flowbit, thread_idx);

        switch (flowbit->operation) {
        case IPS_FLOWBIT_ISSET:
            if (!result) return 0;  /* Flowbit not set, rule fails */
            break;

        case IPS_FLOWBIT_ISNOTSET:
            if (result) return 0;   /* Flowbit is set, rule fails */
            break;

        case IPS_FLOWBIT_SET:
        case IPS_FLOWBIT_UNSET:
        case IPS_FLOWBIT_NOALERT:
            /* These are operations, not checks */
            break;

        default:
            return -1;  /* Invalid operation */
        }
    }

    return 1;  /* All flowbit checks passed */
}

/**
 * @brief Cleanup expired flowbits
 */
void
ips_flowbit_cleanup_expired(u32 thread_index, f64 current_time)
{
    ips_flowbit_storage_t *storage = ips_get_flowbit_storage();

    /* Run cleanup every 60 seconds */
    if (current_time - storage->last_cleanup_time < 60.0)
        return;

    storage->last_cleanup_time = current_time;
    storage->cleanup_counter++;

    u32 cleanup_count = 0;
    u32 total_count = 0;

    /* Iterate through all flowbits */
    hash_pair_t *p;
    hash_foreach_pair(p, storage->flowbit_hash, ({
        total_count++;

        ips_flowbit_state_t *state = (ips_flowbit_state_t *)p->value[0];

        /* Check if flowbit is expired (older than 1 hour and not accessed recently) */
        f64 age = current_time - state->set_time;
        if (age > 3600.0 && state->access_count < 10) {
            /* Remove expired flowbit */
            clib_mem_free(state);
            hash_unset(storage->flowbit_hash, p->key);
            cleanup_count++;
        } else if (age > 7200.0) {  /* 2 hours for any flowbit */
            /* Remove very old flowbits */
            clib_mem_free(state);
            hash_unset(storage->flowbit_hash, p->key);
            cleanup_count++;
        }
    }));

    if (cleanup_count > 0) {
        ips_log_system_async(IPS_LOG_LEVEL_DEBUG,
                            "Cleaned up %u expired flowbits (total: %u)",
                            cleanup_count, total_count);
    }
}

/**
 * @brief Get flowbit statistics
 */
void
ips_flowbit_get_stats(u32 thread_index, u64 *total_operations,
                     u64 *cache_hits, u64 *cache_misses)
{
    ips_flowbit_storage_t *storage = ips_get_flowbit_storage();

    if (total_operations)
        *total_operations = storage->total_operations;
    if (cache_hits)
        *cache_hits = storage->cache_hits;
    if (cache_misses)
        *cache_misses = storage->cache_misses;
}

/**
 * @brief Cleanup flowbit storage for thread
 */
void
ips_flowbit_cleanup_thread(u32 thread_index)
{
    ips_flowbit_storage_t *storage = ips_get_flowbit_storage();

    if (storage->flowbit_hash) {
        /* Free all flowbit states */
        hash_pair_t *p;
        hash_foreach_pair(p, storage->flowbit_hash, ({
            clib_mem_free((ips_flowbit_state_t *)p->value[0]);
        }));

        hash_free(storage->flowbit_hash);
        storage->flowbit_hash = NULL;
    }

    clib_memset(storage, 0, sizeof(*storage));
}

/**
 * @brief Initialize flowbit system
 */
int
ips_flowbits_init(void)
{
    /* Initialize per-thread storage will be done lazily */
    return 0;
}

/**
 * @brief Cleanup flowbit system
 */
void
ips_flowbits_cleanup(void)
{
    /* Cleanup all threads */
    u32 num_threads = vlib_get_n_threads();
    for (u32 i = 0; i < num_threads; i++) {
        ips_flowbit_cleanup_thread(i);
    }
}