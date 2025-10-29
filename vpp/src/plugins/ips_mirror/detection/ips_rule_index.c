/*
 * ips_rule_index.c - VPP IPS Rule Indexing and Lookup System
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include <vlib/vlib.h>
#include <vppinfra/hash.h>
#include <vppinfra/vec.h>

#include "ips_suricata_engine.h"
#include "ips_suricata_rule_types.h"
#include "ips_rule_index.h"
#include "../ips_logging.h"

/* Rule index entry - defined in ips_rule_index.h */

/* Protocol-based index */
typedef struct {
    ips_rule_index_entry_t *rules;
    u32 count;
    u32 capacity;
} ips_protocol_index_t;

/* Port-based index (0-65535, 65536 entries) */
typedef struct {
    ips_rule_index_entry_t *rules;
    u32 count;
    u32 capacity;
} ips_port_index_t;

/* Content-based index using hash chains */
typedef struct ips_content_hash_entry_t {
    u32 content_hash;     /* Hash of content pattern */
    ips_rule_index_entry_t *rules;
    u32 count;
    u32 capacity;
    struct ips_content_hash_entry_t *next;  /* Hash chain link */
} ips_content_hash_entry_t;

/* Global rule index */
typedef struct {
    /* Protocol indexes */
    ips_protocol_index_t protocol_indexes[256];

    /* Port indexes */
    ips_port_index_t src_port_indexes[65536];
    ips_port_index_t dst_port_indexes[65536];

    /* Content hash table */
    ips_content_hash_entry_t **content_hash_table;
    u32 content_hash_size;
    u32 content_hash_mask;

    /* SID hash for fast lookup */
    hash_t *sid_hash;

    /* Statistics */
    u64 total_lookups;
    u64 protocol_hits;
    u64 port_hits;
    u64 content_hits;
    u64 sid_hits;
    u64 index_misses;

    /* Index configuration */
    u8 enable_content_index;
    u8 enable_port_index;
    u8 enable_protocol_index;
    u32 max_rules_per_port;
    u32 max_rules_per_protocol;

} ips_rule_index_t;

/* Global index instance */
static ips_rule_index_t rule_index = {0};

/**
 * @brief Compute content hash for indexing
 */
static u32
ips_compute_content_hash(const u8 *content, u32 content_len)
{
    if (!content || content_len == 0)
        return 0;

    /* Use Jenkins hash for good distribution */
    u32 hash = 0;
    for (u32 i = 0; i < content_len; i++) {
        hash += content[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }

    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);

    return hash;
}

/**
 * @brief Initialize rule index system
 */
int
ips_rule_index_init(void)
{
    if (rule_index.sid_hash) {
        /* Already initialized */
        return 0;
    }

    /* Initialize SID hash */
    rule_index.sid_hash = hash_create(0, sizeof(uword));

    /* Initialize content hash table */
    rule_index.content_hash_size = 65536;  /* 64K entries */
    rule_index.content_hash_mask = rule_index.content_hash_size - 1;
    rule_index.content_hash_table =
        clib_mem_alloc(rule_index.content_hash_size * sizeof(ips_content_hash_entry_t*));
    if (!rule_index.content_hash_table) {
        return -1;
    }

    clib_memset(rule_index.content_hash_table, 0,
                rule_index.content_hash_size * sizeof(ips_content_hash_entry_t*));

    /* Initialize configuration */
    rule_index.enable_content_index = 1;
    rule_index.enable_port_index = 1;
    rule_index.enable_protocol_index = 1;
    rule_index.max_rules_per_port = 1024;
    rule_index.max_rules_per_protocol = 4096;

    ips_log_system_async(IPS_LOG_LEVEL_INFO,
                        "Rule index system initialized");

    return 0;
}

/**
 * @brief Add rule to protocol index
 */
static int
ips_index_add_to_protocol(ips_suricata_rule_t *rule)
{
    u8 protocol = rule->protocol;
    if (protocol == IPS_PROTO_ANY)
        protocol = 255;  /* Map IPS_PROTO_ANY to index 255 */

    ips_protocol_index_t *proto_idx = &rule_index.protocol_indexes[protocol];

    /* Check capacity */
    if (proto_idx->count >= proto_idx->capacity) {
        u32 new_capacity = proto_idx->capacity ? proto_idx->capacity * 2 : 64;
        if (new_capacity > rule_index.max_rules_per_protocol)
            new_capacity = rule_index.max_rules_per_protocol;

        if (new_capacity <= proto_idx->capacity)
            return -1;  /* At capacity limit */

        vec_validate(proto_idx->rules, new_capacity - 1);
        proto_idx->capacity = new_capacity;
    }

    /* Create index entry */
    ips_rule_index_entry_t entry;
    entry.rule = rule;
    entry.rule_hash = ips_suricata_rule_hash(rule);
    entry.priority = rule->priority;
    entry.content_min_len = rule->content_min_len;
    entry.fast_pattern_idx = rule->fast_pattern_index;

    /* Add to index */
    proto_idx->rules[proto_idx->count++] = entry;

    return 0;
}

/**
 * @brief Add rule to port index
 */
static int
ips_index_add_to_ports(ips_suricata_rule_t *rule)
{
    /* Add to source port index */
    if (!rule->src_port.is_any) {
        for (u16 port = rule->src_port.start; port <= rule->src_port.end; port++) {
            ips_port_index_t *port_idx = &rule_index.src_port_indexes[port];

            /* Check capacity */
            if (port_idx->count >= port_idx->capacity) {
                u32 new_capacity = port_idx->capacity ? port_idx->capacity * 2 : 16;
                if (new_capacity > rule_index.max_rules_per_port)
                    new_capacity = rule_index.max_rules_per_port;

                if (new_capacity <= port_idx->capacity)
                    continue;  /* At capacity limit, skip this port */

                vec_validate(port_idx->rules, new_capacity - 1);
                port_idx->capacity = new_capacity;
            }

            /* Create index entry */
            ips_rule_index_entry_t entry;
            entry.rule = rule;
            entry.rule_hash = ips_suricata_rule_hash(rule);
            entry.priority = rule->priority;
            entry.content_min_len = rule->content_min_len;
            entry.fast_pattern_idx = rule->fast_pattern_index;

            port_idx->rules[port_idx->count++] = entry;
        }
    }

    /* Add to destination port index */
    if (!rule->dst_port.is_any) {
        for (u16 port = rule->dst_port.start; port <= rule->dst_port.end; port++) {
            ips_port_index_t *port_idx = &rule_index.dst_port_indexes[port];

            /* Check capacity */
            if (port_idx->count >= port_idx->capacity) {
                u32 new_capacity = port_idx->capacity ? port_idx->capacity * 2 : 16;
                if (new_capacity > rule_index.max_rules_per_port)
                    new_capacity = rule_index.max_rules_per_port;

                if (new_capacity <= port_idx->capacity)
                    continue;  /* At capacity limit, skip this port */

                vec_validate(port_idx->rules, new_capacity - 1);
                port_idx->capacity = new_capacity;
            }

            /* Create index entry */
            ips_rule_index_entry_t entry;
            entry.rule = rule;
            entry.rule_hash = ips_suricata_rule_hash(rule);
            entry.priority = rule->priority;
            entry.content_min_len = rule->content_min_len;
            entry.fast_pattern_idx = rule->fast_pattern_index;

            port_idx->rules[port_idx->count++] = entry;
        }
    }

    return 0;
}

/**
 * @brief Add rule to content index
 */
static int
ips_index_add_to_content(ips_suricata_rule_t *rule)
{
    if (rule->content_count == 0 || !rule_index.enable_content_index)
        return 0;  /* No content to index */

    /* Use first content as primary index key */
    ips_content_match_t *content = &rule->contents[0];
    if (!content || content->pattern_len == 0)
        return 0;

    u32 content_hash = ips_compute_content_hash(content->pattern, content->pattern_len);
    u32 hash_index = content_hash & rule_index.content_hash_mask;

    /* Find or create hash entry */
    ips_content_hash_entry_t *hash_entry = rule_index.content_hash_table[hash_index];
    ips_content_hash_entry_t *prev_entry = NULL;

    while (hash_entry) {
        if (hash_entry->content_hash == content_hash) {
            /* Found existing entry */
            break;
        }
        prev_entry = hash_entry;
        hash_entry = hash_entry->next;
    }

    if (!hash_entry) {
        /* Create new hash entry */
        hash_entry = clib_mem_alloc(sizeof(ips_content_hash_entry_t));
        if (!hash_entry)
            return -1;

        clib_memset(hash_entry, 0, sizeof(*hash_entry));
        hash_entry->content_hash = content_hash;

        /* Add to hash chain */
        if (prev_entry) {
            prev_entry->next = hash_entry;
        } else {
            rule_index.content_hash_table[hash_index] = hash_entry;
        }
    }

    /* Check capacity */
    if (hash_entry->count >= hash_entry->capacity) {
        u32 new_capacity = hash_entry->capacity ? hash_entry->capacity * 2 : 8;
        vec_validate(hash_entry->rules, new_capacity - 1);
        hash_entry->capacity = new_capacity;
    }

    /* Create index entry */
    ips_rule_index_entry_t entry;
    entry.rule = rule;
    entry.rule_hash = ips_suricata_rule_hash(rule);
    entry.priority = rule->priority;
    entry.content_min_len = rule->content_min_len;
    entry.fast_pattern_idx = rule->fast_pattern_index;

    /* Add to content index */
    vec_add1(hash_entry->rules, entry);
    hash_entry->count++;

    return 0;
}

/**
 * @brief Add rule to all indexes
 */
int
ips_rule_index_add_rule(ips_suricata_rule_t *rule)
{
    if (!rule || !rule_index.sid_hash)
        return -1;

    /* Add to SID hash */
    hash_set(rule_index.sid_hash, rule->sid, (uword)rule);

    /* Add to protocol index */
    if (rule_index.enable_protocol_index) {
        ips_index_add_to_protocol(rule);
    }

    /* Add to port indexes */
    if (rule_index.enable_port_index) {
        ips_index_add_to_ports(rule);
    }

    /* Add to content index */
    ips_index_add_to_content(rule);

    return 0;
}

/**
 * @brief Lookup rules by protocol
 */
static ips_rule_index_entry_t *
ips_index_lookup_by_protocol(u8 protocol, u32 *count)
{
    if (protocol == IPS_PROTO_ANY)
        protocol = 255;  /* "any" protocol */

    ips_protocol_index_t *proto_idx = &rule_index.protocol_indexes[protocol];
    *count = proto_idx->count;
    rule_index.protocol_hits++;

    return proto_idx->rules;
}

/**
 * @brief Lookup rules by port
 */
static ips_rule_index_entry_t *
__attribute__((unused)) ips_index_lookup_by_port(u16 port, u32 *count, u8 is_dst_port)
{
    ips_port_index_t *port_idx = is_dst_port ?
        &rule_index.dst_port_indexes[port] : &rule_index.src_port_indexes[port];
    *count = port_idx->count;
    rule_index.port_hits++;

    return port_idx->rules;
}

/**
 * @brief Lookup rules by content
 */
static ips_rule_index_entry_t *
__attribute__((unused)) ips_index_lookup_by_content(const u8 *content, u32 content_len, u32 *count)
{
    if (!content || content_len == 0 || !rule_index.enable_content_index) {
        *count = 0;
        return NULL;
    }

    u32 content_hash = ips_compute_content_hash(content, content_len);
    u32 hash_index = content_hash & rule_index.content_hash_mask;

    ips_content_hash_entry_t *hash_entry = rule_index.content_hash_table[hash_index];
    while (hash_entry) {
        if (hash_entry->content_hash == content_hash) {
            *count = hash_entry->count;
            rule_index.content_hits++;
            return hash_entry->rules;
        }
        hash_entry = hash_entry->next;
    }

    *count = 0;
    return NULL;
}

/**
 * @brief Lookup rule by SID
 */
static ips_suricata_rule_t *
ips_index_lookup_by_sid(u32 sid)
{
    uword *p = hash_get(rule_index.sid_hash, sid);
    if (p) {
        rule_index.sid_hits++;
        return (ips_suricata_rule_t *)p[0];
    }
    return NULL;
}

/**
 * @brief Find candidate rules for packet
 */
ips_rule_index_entry_t *
ips_find_candidate_rules(ips_packet_context_t *ctx, u32 *count)
{
    rule_index.total_lookups++;

    /* Start with protocol-based lookup */
    ips_rule_index_entry_t *candidates = ips_index_lookup_by_protocol(ctx->protocol, count);

    /* TODO: Implement more sophisticated candidate selection:
     * 1. Combine protocol and port indexes
     * 2. Use content index for packets with application data
     * 3. Apply rule priority filtering
     * 4. Remove duplicates
     */

    if (*count == 0) {
        rule_index.index_misses++;
    }

    return candidates;
}

/**
 * @brief Remove rule from all indexes
 */
int
ips_rule_index_remove_rule(u32 sid)
{
    ips_suricata_rule_t *rule = ips_index_lookup_by_sid(sid);
    if (!rule)
        return -1;

    /* Remove from SID hash */
    hash_unset(rule_index.sid_hash, sid);

    /* TODO: Remove from other indexes */
    /* This is more complex as we need to search through the indexes */

    return 0;
}

/**
 * @brief Get index statistics
 */
void
ips_rule_index_get_stats(u64 *total_lookups,
                         u64 *protocol_hits,
                         u64 *port_hits,
                         u64 *content_hits,
                         u64 *sid_hits,
                         u64 *index_misses)
{
    if (total_lookups)
        *total_lookups = rule_index.total_lookups;
    if (protocol_hits)
        *protocol_hits = rule_index.protocol_hits;
    if (port_hits)
        *port_hits = rule_index.port_hits;
    if (content_hits)
        *content_hits = rule_index.content_hits;
    if (sid_hits)
        *sid_hits = rule_index.sid_hits;
    if (index_misses)
        *index_misses = rule_index.index_misses;
}

/**
 * @brief Reset index statistics
 */
void
ips_rule_index_reset_stats(void)
{
    clib_memset(&rule_index.total_lookups, 0,
                sizeof(rule_index.total_lookups) +
                sizeof(rule_index.protocol_hits) +
                sizeof(rule_index.port_hits) +
                sizeof(rule_index.content_hits) +
                sizeof(rule_index.sid_hits) +
                sizeof(rule_index.index_misses));
}

/**
 * @brief Optimize rule ordering in indexes
 */
void
ips_rule_index_optimize_ordering(void)
{
    /* TODO: Implement rule ordering optimization:
     * 1. Sort rules by priority
     * 2. Move frequently matched rules to front
     * 3. Group rules by content length
     * 4. Optimize cache locality
     */
}

/**
 * @brief Cleanup rule index system
 */
void
ips_rule_index_cleanup(void)
{
    if (rule_index.sid_hash) {
        hash_free(rule_index.sid_hash);
        rule_index.sid_hash = NULL;
    }

    /* Free protocol indexes */
    for (int i = 0; i < 256; i++) {
        if (rule_index.protocol_indexes[i].rules) {
            vec_free(rule_index.protocol_indexes[i].rules);
            rule_index.protocol_indexes[i].rules = NULL;
            rule_index.protocol_indexes[i].count = 0;
            rule_index.protocol_indexes[i].capacity = 0;
        }
    }

    /* Free port indexes */
    for (int i = 0; i < 65536; i++) {
        if (rule_index.src_port_indexes[i].rules) {
            vec_free(rule_index.src_port_indexes[i].rules);
            rule_index.src_port_indexes[i].rules = NULL;
            rule_index.src_port_indexes[i].count = 0;
            rule_index.src_port_indexes[i].capacity = 0;
        }

        if (rule_index.dst_port_indexes[i].rules) {
            vec_free(rule_index.dst_port_indexes[i].rules);
            rule_index.dst_port_indexes[i].rules = NULL;
            rule_index.dst_port_indexes[i].count = 0;
            rule_index.dst_port_indexes[i].capacity = 0;
        }
    }

    /* Free content hash table */
    if (rule_index.content_hash_table) {
        for (u32 i = 0; i < rule_index.content_hash_size; i++) {
            ips_content_hash_entry_t *entry = rule_index.content_hash_table[i];
            while (entry) {
                ips_content_hash_entry_t *next = entry->next;
                if (entry->rules)
                    vec_free(entry->rules);
                clib_mem_free(entry);
                entry = next;
            }
        }
        clib_mem_free(rule_index.content_hash_table);
        rule_index.content_hash_table = NULL;
    }

    clib_memset(&rule_index, 0, sizeof(rule_index));
}