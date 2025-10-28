/*
 * ips_suricata_rule_types.h - VPP IPS Enhanced Suricata Rule Types
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __IPS_SURICATA_RULE_TYPES_H__
#define __IPS_SURICATA_RULE_TYPES_H__

#include <vlib/vlib.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip6.h>
#include <vppinfra/vec.h>
#include <vppinfra/hash.h>
#include "../ips.h"  /* Use existing type definitions */

/* Forward declarations - removed to avoid type redefinition conflicts */

/* Maximum sizes for rule components */
#define IPS_MAX_RULE_LENGTH 8192
#define IPS_MAX_CONTENT_LENGTH 65535
#define IPS_MAX_PCRE_PATTERN_LENGTH 4096
#define IPS_MAX_FLOWBIT_NAME 64
#define IPS_MAX_MESSAGE_LENGTH 256
#define IPS_MAX_CLASSIFICATION_LENGTH 128
#define IPS_MAX_REFERENCE_LENGTH 256
#define IPS_MAX_RULE_PARTS 64

/* Note: ips_action_t is defined in ips.h */

/* Protocol types for Suricata rules */
typedef enum
{
    IPS_SURICATA_PROTO_TCP = IPS_PROTO_TCP,
    IPS_SURICATA_PROTO_UDP = IPS_PROTO_UDP,
    IPS_SURICATA_PROTO_ICMP = IPS_PROTO_ICMP,
    IPS_SURICATA_PROTO_IP = 255,
    IPS_SURICATA_PROTO_ANY = 0
} ips_protocol_t;

/* Rule direction */
typedef enum
{
    IPS_DIR_ANY = 0,
    IPS_DIR_SRC_TO_DST,
    IPS_DIR_DST_TO_SRC,
    IPS_DIR_BIDIRECTIONAL
} ips_direction_t;

/* Content match modifiers */
typedef enum
{
    IPS_CONTENT_MOD_NONE = 0,
    IPS_CONTENT_MOD_NOCASE = 0x01,
    IPS_CONTENT_MOD_RAWBYTES = 0x02,
    IPS_CONTENT_MOD_FAST_PATTERN = 0x04,
    IPS_CONTENT_MOD_WITHIN = 0x08,
    IPS_CONTENT_MOD_DISTANCE = 0x10,
    IPS_CONTENT_MOD_OFFSET = 0x20,
    IPS_CONTENT_MOD_DEPTH = 0x40,
    IPS_CONTENT_MOD_HTTP_METHOD = 0x80,
    IPS_CONTENT_MOD_HTTP_URI = 0x100,
    IPS_CONTENT_MOD_HTTP_HEADER = 0x200,
    IPS_CONTENT_MOD_HTTP_CLIENT_BODY = 0x400,
    IPS_CONTENT_MOD_HTTP_SERVER_BODY = 0x800,
    IPS_CONTENT_MOD_HTTP_COOKIE = 0x1000,
    IPS_CONTENT_MOD_HTTP_USER_AGENT = 0x2000,
    IPS_CONTENT_MOD_HTTP_HOST = 0x4000,
} ips_content_modifiers_t;

/* Byte test operators */
typedef enum
{
    IPS_BYTE_TEST_EQ = 0,
    IPS_BYTE_TEST_NE,
    IPS_BYTE_TEST_LT,
    IPS_BYTE_TEST_GT,
    IPS_BYTE_TEST_LE,
    IPS_BYTE_TEST_GE,
    IPS_BYTE_TEST_AND,
    IPS_BYTE_TEST_OR,
    IPS_BYTE_TEST_XOR,
    IPS_BYTE_TEST_MAX
} ips_byte_test_op_t;

/* Byte jump modifiers */
typedef enum
{
    IPS_BYTE_JUMP_NONE = 0,
    IPS_BYTE_JUMP_FROM_BEGINNING = 0x01,
    IPS_BYTE_JUMP_FROM_END = 0x02,
    IPS_BYTE_JUMP_FROM_STRING = 0x04,
    IPS_BYTE_JUMP_ALIGN = 0x08,
    IPS_BYTE_JUMP_RELATIVE = 0x10,
    IPS_BYTE_JUMP_POST_OFFSET = 0x20,
} ips_byte_jump_modifiers_t;

/* Flowbit operations */
typedef enum
{
    IPS_FLOWBIT_SET = 0,
    IPS_FLOWBIT_UNSET,
    IPS_FLOWBIT_ISSET,
    IPS_FLOWBIT_ISNOTSET,
    IPS_FLOWBIT_NOALERT,
    IPS_FLOWBIT_MAX
} ips_flowbit_op_t;

/* Threshold types */
typedef enum
{
    IPS_THRESHOLD_LIMIT = 0,
    IPS_THRESHOLD_THRESHOLD,
    IPS_THRESHOLD_BOTH,
    IPS_THRESHOLD_MAX
} ips_threshold_type_t;

/* IP address and network representation */
typedef struct
{
    ip46_address_t addr;
    ip46_address_t mask;
    u8 is_ipv6;
    u8 is_any;
} ips_ip_spec_t;

/* Port range representation */
typedef struct
{
    u16 start;
    u16 end;
    u8 is_any;
} ips_port_spec_t;

/* Content match structure */
typedef struct ips_content_match_t
{
    /* Pattern data */
    u8 *pattern;
    u32 pattern_len;
    u8 *hex_pattern;  /* For hex string patterns */
    u32 hex_pattern_len;

    /* Modifiers */
    u32 modifiers;  /* bitfield of ips_content_modifiers_t */
    u32 offset;
    u32 depth;
    u32 distance;
    u32 within;

    /* Fast pattern information */
    u8 is_fast_pattern;
    u32 fast_pattern_offset;
    u32 fast_pattern_len;

    /* Matching state */
    u8 pattern_hash[16];  /* For quick comparison */
} ips_content_match_t;

/* PCRE match structure */
typedef struct ips_pcre_match_t
{
    /* PCRE pattern */
    char *pattern;
    u32 pattern_len;

    /* PCRE options */
    u32 pcre_options;
    u32 compile_options;

    /* Modifiers */
    u32 offset;
    u32 distance;
    u32 within;

    /* Compiled regex (placeholder for PCRE implementation) */
    void *compiled_regex;
    void *study_data;
} ips_pcre_match_t;

/* Byte test structure */
typedef struct ips_byte_test_t
{
    u32 offset;
    u8 bytes;           /* Number of bytes to test (1-4) */
    ips_byte_test_op_t op;
    u32 value;
    u8 base;            /* Base for value (10, 16, or dec/hex/oct) */
    u8 relative;
    u32 mask;
} ips_byte_test_t;

/* Byte jump structure */
typedef struct ips_byte_jump_t
{
    u32 offset;
    u8 bytes;           /* Number of bytes to convert (1-4) */
    u8 base;            /* Base for conversion */
    u32 multiplier;
    u32 post_offset;
    u8 relative;
    u32 modifiers;      /* bitfield of ips_byte_jump_modifiers_t */
} ips_byte_jump_t;

/* Flowbit structure */
typedef struct ips_flowbit_t
{
    char name[IPS_MAX_FLOWBIT_NAME];
    ips_flowbit_op_t operation;
    u32 group_id;       /* For flowbit groups */
} ips_flowbit_t;

/* Threshold structure */
typedef struct ips_threshold_t
{
    ips_threshold_type_t type;
    u32 count;
    u32 seconds;
    u32 track;          /* track by_src|by_dst|by_rule */
    char type_str[16];  /* limit|threshold|both */
} ips_threshold_t;

/* Enhanced Suricata rule structure */
typedef struct ips_suricata_rule_t
{
    /* Rule identification */
    u32 sid;                    /* Signature ID */
    u32 rev;                    /* Revision */
    u32 gid;                    /* Generator ID (default: 1) */
    char msg[IPS_MAX_MESSAGE_LENGTH];
    char classification[IPS_MAX_CLASSIFICATION_LENGTH];
    char reference[IPS_MAX_REFERENCE_LENGTH];
    u32 priority;

    /* Rule header */
    ips_action_t action;
    ips_protocol_t protocol;
    ips_direction_t direction;

    /* Source and destination specifications */
    ips_ip_spec_t src_ip;
    ips_port_spec_t src_port;
    ips_ip_spec_t dst_ip;
    ips_port_spec_t dst_port;

    /* Rule state */
    u8 enabled;
    u8 parsed;
    u8 has_error;
    char error_msg[256];

    /* Rule matching components */
    ips_content_match_t *contents;
    u32 content_count;
    ips_pcre_match_t *pcre_patterns;
    u32 pcre_count;
    ips_byte_test_t *byte_tests;
    u32 byte_test_count;
    ips_byte_jump_t *byte_jumps;
    u32 byte_jump_count;
    ips_flowbit_t *flowbits;
    u32 flowbit_count;

    /* Additional match options */
    u32 dsize_min, dsize_max;
    u8 ttl_min, ttl_max;
    u8 ip_opts;
    u32 ip_id;
    u8 tos;
    u32 icmp_type, icmp_code;
    u8 tcp_flags_mask, tcp_flags_value;
    u32 window_size;
    u8 seq, ack;

    /* Flow options */
    u8 flow_established;
    u8 flow_to_server;
    u8 flow_to_client;
    u8 flow_stateless;
    u8 flow_no_stream;
    u8 flow_only_stream;

    /* File options */
    char fileext[32];
    char filemagic[64];
    char filename[256];
    u32 filesize_min, filesize_max;

    /* Thresholding */
    ips_threshold_t threshold;

    /* Rule metadata */
    u64 created_time;
    u64 last_hit_time;
    u64 hit_count;
    u32 last_hit_thread;

    /* Performance optimization */
    u32 rule_hash;
    u16 content_min_len;    /* Shortest content length */
    u16 fast_pattern_index; /* Index of fast pattern */
    u8 has_http_content;    /* Does rule have HTTP content modifiers */
    u8 has_stream_content;  /* Does rule require stream reassembly */

    /* Rule groups for optimization */
    u32 group_id;
    char group_name[32];

    /* Linked list for hash table */
    struct ips_suricata_rule_t *next;
} ips_suricata_rule_t;

/* Rule statistics */
typedef struct
{
    u32 total_rules;
    u32 enabled_rules;
    u32 disabled_rules;
    u32 error_rules;
    u64 total_matches;
    u64 total_alerts;
    u64 total_drops;
    u64 total_rejects;
    u64 total_passes;
    f64 avg_match_time;
    u32 rules_with_content;
    u32 rules_with_pcre;
    u32 rules_with_flowbits;
} ips_suricata_rule_stats_t;

/* Rule hash table */
typedef struct
{
    ips_suricata_rule_t **rules_by_sid;    /* Hash by SID */
    ips_suricata_rule_t **rules_by_content; /* Hash by content */
    ips_suricata_rule_t **rules_by_protocol; /* Hash by protocol */
    u32 sid_table_size;
    u32 content_table_size;
    u32 protocol_table_size;
    u32 rule_count;
} ips_suricata_rule_table_t;

/* Utility functions */
const char *ips_action_to_string(ips_action_t action);
const char *ips_protocol_to_string(ips_protocol_t proto);
ips_protocol_t ips_string_to_protocol(const char *proto_str);
const char *ips_byte_test_op_to_string(ips_byte_test_op_t op);
const char *ips_flowbit_op_to_string(ips_flowbit_op_t op);
const char *ips_threshold_type_to_string(ips_threshold_type_t type);

u32 ips_suricata_rule_hash(ips_suricata_rule_t *rule);
int ips_suricata_rule_equals(ips_suricata_rule_t *rule1, ips_suricata_rule_t *rule2);
int ips_suricata_rule_matches_packet(ips_suricata_rule_t *rule,
                                    ips_protocol_t proto,
                                    ip46_address_t *src_ip, u16 src_port,
                                    ip46_address_t *dst_ip, u16 dst_port);

/* Rule management functions */
ips_suricata_rule_t *ips_suricata_rule_create(void);
void ips_suricata_rule_free(ips_suricata_rule_t *rule);
ips_suricata_rule_t *ips_suricata_rule_clone(ips_suricata_rule_t *rule);
int ips_suricata_rule_validate(ips_suricata_rule_t *rule);
void ips_suricata_rule_print(ips_suricata_rule_t *rule);

/* Content management functions */
ips_content_match_t *ips_content_match_create(void);
void ips_content_match_free(ips_content_match_t *content);
int ips_content_match_add_pattern(ips_content_match_t *content, const u8 *pattern, u32 len);
int ips_content_match_set_hex_pattern(ips_content_match_t *content, const char *hex_str);

/* PCRE management functions */
ips_pcre_match_t *ips_pcre_match_create(void);
void ips_pcre_match_free(ips_pcre_match_t *pcre);
int ips_pcre_match_set_pattern(ips_pcre_match_t *pcre, const char *pattern);

/* Flowbit management functions */
ips_flowbit_t *ips_flowbit_create(void);
void ips_flowbit_free(ips_flowbit_t *flowbit);
int ips_flowbit_set_name(ips_flowbit_t *flowbit, const char *name);

#endif /* __IPS_SURICATA_RULE_TYPES_H__ */