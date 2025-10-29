/*
 * ips.h - VPP IPS Plugin Main Header
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

#ifndef __included_ips_h__
#define __included_ips_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/session/session.h>
#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* Hyperscan includes - re-enabled with proper configuration */
#include <hs/hs.h>

/* IPS Logging Levels */
typedef enum {
    IPS_LOG_LEVEL_ERROR = 0,    /* Critical errors only */
    IPS_LOG_LEVEL_WARNING = 1,  /* Warnings and important events */
    IPS_LOG_LEVEL_INFO = 2,     /* General information */
    IPS_LOG_LEVEL_DEBUG = 3,    /* Debug information */
    IPS_LOG_LEVEL_TRACE = 4     /* Detailed trace information */
} ips_log_level_t;

/* Global log level - can be configured at runtime */
extern ips_log_level_t ips_global_log_level;

/* Logging macros */
#define IPS_LOG(level, fmt, ...) \
    do { \
        if (level <= ips_global_log_level) { \
            clib_warning(fmt, ##__VA_ARGS__); \
        } \
    } while (0)

#define IPS_ERROR(fmt, ...)   IPS_LOG(IPS_LOG_LEVEL_ERROR, "IPS ERROR: " fmt, ##__VA_ARGS__)
#define IPS_WARNING(fmt, ...) IPS_LOG(IPS_LOG_LEVEL_WARNING, "IPS WARNING: " fmt, ##__VA_ARGS__)
#define IPS_INFO(fmt, ...)    IPS_LOG(IPS_LOG_LEVEL_INFO, "IPS INFO: " fmt, ##__VA_ARGS__)
#define IPS_DEBUG(fmt, ...)   IPS_LOG(IPS_LOG_LEVEL_DEBUG, "IPS DEBUG: " fmt, ##__VA_ARGS__)
#define IPS_TRACE(fmt, ...)   IPS_LOG(IPS_LOG_LEVEL_TRACE, "IPS TRACE: " fmt, ##__VA_ARGS__)

/* TCP reorder buffer entry - uses VPP buffer index instead of data copy */
typedef struct tcp_reorder_buffer_t
{
    struct tcp_reorder_buffer_t *next;  /* Next buffer in the list */
    u32 buffer_index;                   /* VPP buffer index */
    u32 seq_number;                     /* TCP sequence number */
    u32 data_len;                       /* Length of TCP payload data */
    f64 timestamp;                      /* When this buffer was received */

    /* Range information similar to IP reassembly */
    u32 range_first;                    /* First byte of this range */
    u32 range_last;                     /* Last byte of this range */
    u32 next_range_bi;                  /* Next range buffer index */
} tcp_reorder_buffer_t;

/* TCP reorder configuration */
#define IPS_TCP_REORDER_MAX_BUFFERS 32     /* Maximum buffers to store per direction */
#define IPS_TCP_REORDER_TIMEOUT 5.0        /* Buffer aging timeout (seconds) */
#define IPS_TCP_REORDER_WINDOW 65536       /* Default reorder window size */

/* IPS Plugin Constants */
#define IPS_PLUGIN_BUILD_VER "1.0.0"
#define IPS_MAX_INTERFACES 256
#define IPS_MAX_SESSIONS 1048576
#define IPS_MAX_RULES 65536
#define IPS_MAX_MATCHES_PER_PACKET 64
#define IPS_SESSION_TIMEOUT_DEFAULT 300
#define IPS_CLEANUP_INTERVAL 30

/* Protocol definitions */
#define IPS_PROTO_IP 0
#define IPS_PROTO_TCP 6
#define IPS_PROTO_UDP 17
#define IPS_PROTO_ICMP 1
#define IPS_PROTO_ICMPV6 58
#define IPS_PROTO_ANY 255

/* Flow directions */
typedef enum
{
    IPS_FLOW_DIR_BOTH = 0,
    IPS_FLOW_DIR_TO_SERVER = 1,
    IPS_FLOW_DIR_TO_CLIENT = 2,
    IPS_FLOW_DIR_FROM_SERVER = 3,
    IPS_FLOW_DIR_FROM_CLIENT = 4,
} ips_flow_direction_t;

/* Encapsulation types */
typedef enum
{
    IPS_ENCAP_NONE = 0,
    IPS_ENCAP_VLAN,
    IPS_ENCAP_DOUBLE_VLAN,
    IPS_ENCAP_MPLS,
    IPS_ENCAP_GRE,
    IPS_ENCAP_VXLAN,
} ips_encap_type_t;

/* Application protocols */
typedef enum
{
    IPS_APP_PROTO_UNKNOWN = 0,
    IPS_APP_PROTO_HTTP,
    IPS_APP_PROTO_HTTPS,
    IPS_APP_PROTO_TLS,
    IPS_APP_PROTO_SSH,
    IPS_APP_PROTO_FTP,
    IPS_APP_PROTO_SMTP,
    IPS_APP_PROTO_DNS,
    IPS_APP_PROTO_TELNET,
} ips_app_proto_t;

/* Rule actions */
typedef enum
{
    IPS_ACTION_PASS = 0,
    IPS_ACTION_DROP,
    IPS_ACTION_ALERT,
    IPS_ACTION_REJECT,
    IPS_ACTION_LOG,
    IPS_ACTION_MAX,
} ips_action_t;

/* Simplified TCP State Definitions - Adapted for Mirror Traffic
 * In mirror mode, we see bidirectional traffic simultaneously,
 * so we don't need to distinguish between SYN_SENT and SYN_RECV */
#ifndef IPS_TCP_STATE_T_DEFINED
#define IPS_TCP_STATE_T_DEFINED
typedef enum
{
    IPS_TCP_STATE_NONE = 0,           /* 无状态/初始状态 */
    IPS_TCP_STATE_NEW,                /* 新连接 (看到 SYN) */
    IPS_TCP_STATE_ESTABLISHED,        /* 已建立连接 (看到 SYN+ACK 或数据包) */
    IPS_TCP_STATE_CLOSING,            /* 连接关闭中 (看到 FIN) */
    IPS_TCP_STATE_CLOSED,             /* 连接已关闭 (看到 RST 或双向 FIN) */
} ips_tcp_state_t;

/* Legacy compatibility - all map to simplified states */
#define IPS_TCP_NONE          IPS_TCP_STATE_NONE
#define IPS_TCP_SYN_SENT      IPS_TCP_STATE_NEW
#define IPS_TCP_SYN_RECV      IPS_TCP_STATE_NEW
#define IPS_TCP_ESTABLISHED   IPS_TCP_STATE_ESTABLISHED
#define IPS_TCP_FIN_WAIT1     IPS_TCP_STATE_CLOSING
#define IPS_TCP_FIN_WAIT2     IPS_TCP_STATE_CLOSING
#define IPS_TCP_TIME_WAIT     IPS_TCP_STATE_CLOSING
#define IPS_TCP_CLOSED        IPS_TCP_STATE_CLOSED
#endif /* IPS_TCP_STATE_T_DEFINED */


/* Rule flags */
#define IPS_RULE_FLAG_ENABLED (1 << 0)
#define IPS_RULE_FLAG_NOCASE (1 << 1)
#define IPS_RULE_FLAG_BIDIRECTIONAL (1 << 2)
#define IPS_RULE_FLAG_UNSUPPORTED (1 << 3)

/* Detection flags */
#define IPS_DETECTION_FLAG_DROP (1 << 0)
#define IPS_DETECTION_FLAG_ALERT (1 << 1)
#define IPS_DETECTION_FLAG_REJECT (1 << 2)
#define IPS_DETECTION_FLAG_LOG (1 << 3)


/* Flow flags */
#define IPS_FLOW_FLAG_ESTABLISHED   (1 << 0)
#define IPS_FLOW_FLAG_STATELESS     (1 << 1)
#define IPS_FLOW_FLAG_TO_SERVER     (1 << 2)
#define IPS_FLOW_FLAG_TO_CLIENT     (1 << 3)

/* Flow key for session identification */
typedef struct
{
    union
    {
        ip4_address_t src_ip4;
        ip6_address_t src_ip6;
    };
    union
    {
        ip4_address_t dst_ip4;
        ip6_address_t dst_ip6;
    };
    u16 src_port;
    u16 dst_port;
    u8 protocol;
    u8 is_ip6;
} ips_flow_key_t;

/* Advanced rule options (Suricata compatible) */
typedef struct
{
  /* Flow state options */
  u8 flow_to_client:1;
  u8 flow_to_server:1;
  u8 flow_established:1;
  u8 flow_stateless:1;
  u8 flow_not_established:1;
  u8 flow_from_server:1;
  u8 flow_from_client:1;

  /* Content matching options */
  u32 depth;
  u32 offset;
  u32 distance;
  u32 within;
  u8 nocase:1;
  u8 rawbytes:1;
  u8 http_header:1;
  u8 http_uri:1;
  u8 http_method:1;
  u8 http_cookie:1;
  u8 http_user_agent:1;
  u8 http_host:1;
  u8 http_request_line:1;
  u8 http_response_line:1;

  /* TCP flags detection - NEW */
  u8 tcp_flags_enabled:1;
  u8 tcp_flags_value;
  u8 tcp_flags_mask;
  u8 tcp_flags_not:1;  /* For negation like !flags:A */

  /* Packet inspection options */
  u32 dsize_min;
  u32 dsize_max;
  u8 dsize_operator; /* 0=equal, 1=greater, 2=less, 3=range */

  /* Byte test options */
  u8 byte_test_enabled:1;
  u32 byte_test_bytes;
  u8 byte_test_operator; /* 0=equal, 1=greater, 2=less, 3=and, 4=or */
  u32 byte_test_value;
  u32 byte_test_offset;
  u8 byte_test_relative:1;

  /* Byte jump options - NEW */
  u8 byte_jump_enabled:1;
  u32 byte_jump_bytes;
  i32 byte_jump_offset;
  u8 byte_jump_relative:1;
  u8 byte_jump_align:1;
  u32 byte_jump_multiplier;

  /* Byte extract options - NEW */
  u8 byte_extract_enabled:1;
  u32 byte_extract_bytes;
  u32 byte_extract_offset;
  u8 byte_extract_relative:1;
  u8 *byte_extract_name;

  /* Threshold options */
  u8 threshold_type; /* 0=limit, 1=threshold, 2=both */
  u8 threshold_track; /* 0=by_src, 1=by_dst, 2=by_rule */
  u32 threshold_count;
  u32 threshold_seconds;

  /* PCRE options */
  u8 *pcre_pattern;
  u32 pcre_flags; /* PCRE_CASELESS, PCRE_MULTILINE, etc */

  /* Flow bits */
  u8 flowbits_cmd; /* 0=set, 1=isset, 2=isnotset, 3=toggle, 4=unset, 5=noalert */
  u8 *flowbits_name;

  /* Data at check */
  u8 isdataat_enabled:1;
  u32 isdataat_size;
  u8 isdataat_relative:1;
  u8 isdataat_rawbytes:1;

  /* Window and ID checks for fragmentation */
  u16 window_value;
  u16 id_value;

  /* TTL/Hop limit - NEW */
  u8 ttl_enabled:1;
  u8 ttl_value;
  u8 ttl_operator; /* 0=equal, 1=greater, 2=less */

  /* TOS/Traffic class - NEW */
  u8 tos_enabled:1;
  u8 tos_value;
  u8 tos_mask;
  u8 tos_not:1;

  /* Fragment options - NEW */
  u8 fragbits_enabled:1;
  u8 fragbits_value; /* M=More, D=Don't fragment, R=Reserved */
  u8 fragbits_mask;
  u8 fragbits_not:1;

  /* Sequence number - NEW */
  u8 seq_enabled:1;
  u32 seq_value;

  /* Acknowledgment number - NEW */
  u8 ack_enabled:1;
  u32 ack_value;

  /* ICMP type/code - NEW */
  u8 icmp_type_enabled:1;
  u8 icmp_type;
  u8 icmp_code_enabled:1;
  u8 icmp_code;

  /* Detection options - NEW */
  u8 detection_filter_enabled:1;
  u32 detection_filter_track; /* 0=by_src, 1=by_dst */
  u32 detection_filter_count;
  u32 detection_filter_seconds;

  /* Stream options - NEW */
  u8 stream_size_enabled:1;
  u32 stream_size_value;
  u8 stream_size_operator; /* 0=equal, 1=greater, 2=less */
  u8 stream_size_client:1;
  u8 stream_size_server:1;

  /* Base64 decode options - NEW */
  u8 base64_decode_enabled:1;
  u32 base64_decode_bytes;
  u32 base64_decode_offset;

  /* URL decode options - NEW */
  u8 urldecode_enabled:1;
  u8 urldecode_query:1;

  /* Fast pattern options - NEW */
  u8 fast_pattern_enabled:1;
  u8 fast_pattern_only:1;
  u32 fast_pattern_offset;
  u32 fast_pattern_length;

  /* Metadata */
  u8 *metadata;

} ips_rule_options_t;

/* Content matching structure for multiple content fields */
typedef struct
{
  u8 *pattern;           /* Content pattern */
  u32 pattern_len;       /* Pattern length */
  u8 is_hex:1;           /* Is hexadecimal pattern */
  u8 nocase:1;           /* Case insensitive */
  u8 rawbytes:1;         /* Raw bytes */

  /* Content modifiers */
  u32 depth;             /* Search depth from start */
  u32 offset;            /* Start offset */
  u32 distance;          /* Distance from previous match */
  u32 within;            /* Within range from previous match */

  /* Fast pattern options */
  u8 fast_pattern:1;     /* Use as fast pattern for Hyperscan */
  u8 fast_pattern_only:1; /* Only use as fast pattern */

  /* Enhanced Suricata modifiers */
  u8 endswith:1;         /* Pattern must be at end of buffer */
  u8 startswith:1;       /* Pattern must be at start of buffer */
  u32 bsize;             /* Buffer size restriction */
  u8 bsize_enabled:1;    /* Buffer size check enabled */
  u8 bsize_operator;     /* 0=equal, 1=greater, 2=less */

  /* HTTP context modifiers */
  u8 http_method:1;
  u8 http_uri:1;
  u8 http_header:1;
  u8 http_cookie:1;
  u8 http_user_agent:1;
  u8 http_host:1;
  u8 http_raw_uri:1;
  u8 http_stat_code:1;
  u8 http_stat_msg:1;

} ips_content_t;

typedef struct
{
  /* Basic rule information */
  u32 rule_id;
  u32 sid;
  u32 gid;
  u32 rev;
  u32 priority;
  ips_action_t action;
  u8 protocol;
  u8 *msg;
  u8 *classtype;
  u8 *reference;

  /* Network matching */
  union
  {
    ip4_address_t ip4;
    ip6_address_t ip6;
  } src_addr;
  union
  {
    ip4_address_t ip4;
    ip6_address_t ip6;
  } dst_addr;
  u8 src_addr_mask;
  u8 dst_addr_mask;
  u16 src_port_min;
  u16 src_port_max;
  u16 dst_port_min;
  u16 dst_port_max;
  ips_flow_direction_t direction;

  /* Multi-content matching - NEW ARCHITECTURE */
  ips_content_t *contents;   /* Array of content patterns */
  u32 content_count;         /* Number of content patterns */

  /* Legacy single content support - DEPRECATED */
  u8 *content;
  u32 content_len;
  u8 *content_hex; /* For binary content matching */
  u32 content_hex_len;

  /* Rule flags and state */
  u32 flags;
  u32 rule_hash;

  /* Advanced options */
  ips_rule_options_t options;

  /* Performance counters */
  u64 match_count;
  u64 alert_count;
  u64 last_match_time;

} ips_rule_t;

/* Flow/Session structure based on Suricata's Flow */
typedef struct
{
    ips_flow_key_t key;

    /* Protocol parsing results */
    u8 *l2_header;
    u8 *l3_header;
    u8 *l4_header;
    u8 *app_header;
    u16 l2_len;
    u16 l3_len;
    u16 l4_len;
    u32 app_len;

    /* Encapsulation information */
    ips_encap_type_t encap_type;
    u16 vlan_id[2];
    u32 mpls_label;
    u32 vni;

    /* Application protocol detection */
    ips_app_proto_t app_proto;
    u8 app_proto_confidence;

    /* TCP state tracking */
    ips_tcp_state_t tcp_state_src;
    ips_tcp_state_t tcp_state_dst;
    u32 tcp_seq_src;
    u32 tcp_seq_dst;
    u32 tcp_ack_src;
    u32 tcp_ack_dst;

    /* Flow direction and flags */
    ips_flow_direction_t direction;
    u32 flags;

    /* Detection results */
    u32 detection_flags;
    u32 matched_rule_count;

    /* Packet deduplication for avoiding double counting */
    u32 last_processed_packet_hash;  /* Hash of last processed packet to prevent double counting */

    /* Hyperscan stream state for streaming mode - re-enabled */
    hs_stream_t *hs_stream;

    /* Stream accumulated state for offset/depth calculation */
    u64 stream_bytes_processed;     /* Total bytes processed in this stream */
    u32 stream_packet_count;        /* Number of packets in this stream */
    u64 last_match_position;        /* Position of last content match for distance/within */

    /* TCP out-of-order reassembly using VPP buffer chain */
    u32 tcp_reorder_first_bi_src;   /* First buffer index for src->dst direction */
    u32 tcp_reorder_first_bi_dst;   /* First buffer index for dst->src direction */
    u32 tcp_next_seq_src;           /* Expected next sequence number for src->dst */
    u32 tcp_next_seq_dst;           /* Expected next sequence number for dst->src */
    u32 tcp_reorder_window_src;     /* Reorder window size for src->dst */
    u32 tcp_reorder_window_dst;     /* Reorder window size for dst->src */
    u32 tcp_reorder_data_len_src;   /* Total buffered data length src->dst */
    u32 tcp_reorder_data_len_dst;   /* Total buffered data length dst->src */
    u16 tcp_reorder_buffer_count_src; /* Number of buffered packets src->dst */
    u16 tcp_reorder_buffer_count_dst; /* Number of buffered packets dst->src */
    u8 tcp_stream_established:1;    /* TCP handshake completed */
    u8 tcp_reorder_enabled:1;       /* TCP reordering enabled for this flow */

    /* Timing */
    f64 flow_start_time;
    f64 last_packet_time;
    u32 packet_count_src;
    u32 packet_count_dst;
    u64 byte_count_src;
    u64 byte_count_dst;

    /* Flow management */
    u32 flow_hash;
    u32 thread_index;
    u32 session_index;
} ips_flow_t;

/* Per-thread data */
typedef struct
{
    /* Flow hash table */
    uword *flow_hash;
    ips_flow_t *flows;
    u32 *free_flow_indices;

    /* Statistics */
    u64 total_packets;
    u64 total_bytes;
    u64 dropped_packets;
    u64 alerted_packets;

    /* Timing */
    f64 last_cleanup_time;
} ips_per_thread_data_t;

/* Main IPS structure */
typedef struct
{
    /* API message ID base */
    u16 msg_id_base;

    /* Per-thread data */
    ips_per_thread_data_t *per_thread_data;

    /* Rules */
    ips_rule_t *rules;
    uword *rule_index_by_id;
    u32 rule_count;
    u8 rules_compiled;
    u8 rules_dirty;

    /* Hyperscan database - re-enabled */
    hs_database_t *hs_database;
    hs_compile_error_t *hs_compile_error;

    /* Interface configuration */
    u8 *interface_enabled;
    u32 enabled_interface_count;

    /* Configuration */
    u32 session_timeout;
    u32 cleanup_interval;
    u8 promiscuous_mode;
    u8 *default_rules_file;

    /* Convenience */
    vlib_main_t *vlib_main;
    vnet_main_t *vnet_main;
    ethernet_main_t *ethernet_main;
} ips_main_t;

extern ips_main_t ips_main;

/**
 * @brief Calculate hash for flow key
 */
static inline u32
ips_flow_key_hash (ips_flow_key_t * key)
{
    u32 hash = 0;

    if (key->is_ip6)
    {
        hash = clib_xxhash (key->src_ip6.as_u64[0]);
        hash = clib_xxhash (hash ^ key->src_ip6.as_u64[1]);
        hash = clib_xxhash (hash ^ key->dst_ip6.as_u64[0]);
        hash = clib_xxhash (hash ^ key->dst_ip6.as_u64[1]);
    }
    else
    {
        hash = clib_xxhash (key->src_ip4.as_u32);
        hash = clib_xxhash (hash ^ key->dst_ip4.as_u32);
    }
    hash = clib_xxhash (hash ^ ((u32) key->src_port << 16 | key->dst_port));
    hash = clib_xxhash (hash ^ key->protocol);

    return hash;
}

always_inline int
ips_flow_key_equal (ips_flow_key_t * k1, ips_flow_key_t * k2)
{
    if (k1->is_ip6 != k2->is_ip6)
        return 0;

    if (k1->is_ip6)
    {
        if (!ip6_address_is_equal (&k1->src_ip6, &k2->src_ip6))
            return 0;
        if (!ip6_address_is_equal (&k1->dst_ip6, &k2->dst_ip6))
            return 0;
    }
    else
    {
        if (k1->src_ip4.as_u32 != k2->src_ip4.as_u32)
            return 0;
        if (k1->dst_ip4.as_u32 != k2->dst_ip4.as_u32)
            return 0;
    }

    return (k1->src_port == k2->src_port &&
            k1->dst_port == k2->dst_port &&
            k1->protocol == k2->protocol);
}

/* Utility functions */
static inline u32
hash_string (const char *str)
{
  u32 hash = 5381;
  unsigned char c;

  while ((c = *str++))
    hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

  return hash;
}

/* Function declarations */
clib_error_t *ips_init (vlib_main_t * vm);
typedef struct ips_interface_enable_disable_args_
{
  u32 sw_if_index;
  int enable_disable;
} ips_interface_enable_disable_args_t;
int ips_interface_enable_disable (const ips_interface_enable_disable_args_t *args);

/* Rule management functions */
int ips_rule_add (ips_rule_t * rule);
int ips_rule_delete (u32 rule_id);
ips_rule_t *ips_rule_lookup (u32 rule_id);
int ips_rules_compile (void);

/* Detection functions */
clib_error_t *ips_detection_init (ips_main_t * im);
int ips_detect_patterns (ips_flow_t * flow, vlib_buffer_t * b);
int ips_rule_match (ips_rule_t * rule, ips_flow_t * flow, vlib_buffer_t * b);
void ips_generate_alert (ips_rule_t * rule, ips_flow_t * flow, vlib_buffer_t * b);
void ips_generate_log_entry (ips_rule_t *rule, ips_flow_t *flow, vlib_buffer_t *b);

/* Advanced detection functions */
int ips_match_rule_advanced (vlib_buffer_t *b, ips_flow_t *flow, ips_rule_t *rule, u32 thread_index);
void ips_detection_advanced_init (void);
int parse_advanced_rule_line (char *line, ips_rule_t *rule);

/* Multi-content support functions */
int parse_content_hex_to_content (char *content_str, ips_content_t *content);
int ips_rule_add_content (ips_rule_t *rule, const char *pattern, u32 pattern_len, u8 is_hex);
int ips_rule_set_content_modifiers (ips_rule_t *rule, u32 depth, u32 offset,
                                   u32 distance, u32 within, u8 nocase, u8 rawbytes);
u8 ips_rule_has_content (ips_rule_t *rule);
u32 ips_rule_get_content_count (ips_rule_t *rule);
ips_content_t *ips_rule_get_content (ips_rule_t *rule, u32 index);
void ips_rule_debug_print_contents (ips_rule_t *rule);

/* Response functions */
int ips_send_reject_response (ips_flow_t * flow, vlib_buffer_t * b);

/* TCP Reordering functions */
void ips_tcp_reorder_init_flow (ips_flow_t *flow);
void ips_tcp_reorder_cleanup_flow (ips_flow_t *flow);
int ips_tcp_reorder_process_packet (ips_flow_t *flow, vlib_buffer_t *b,
                                   u8 **ordered_data, u32 *ordered_len);
int ips_detect_patterns_with_reorder (ips_flow_t *flow, vlib_buffer_t *b);
int ips_detect_patterns_on_data (ips_flow_t *flow, const u8 *data, u32 data_len);
void ips_tcp_reorder_get_stats (ips_flow_t *flow, u32 *buffered_src, u32 *buffered_dst);

/* Flow management functions */
ips_flow_t *ips_flow_create (ips_per_thread_data_t * ptd, ips_flow_key_t * key);
void ips_flow_delete (ips_per_thread_data_t * ptd, ips_flow_t * flow);
ips_flow_t *ips_flow_lookup (ips_per_thread_data_t * ptd, ips_flow_key_t * key);
void ips_flow_update_tcp_state (ips_flow_t * flow, tcp_header_t * tcp, u8 is_to_server);
int ips_flow_is_expired (ips_flow_t * flow, f64 timeout);
void ips_flow_update_stats (ips_flow_t * flow, vlib_buffer_t * b, u8 is_to_server);
void ips_flow_cleanup_expired (ips_per_thread_data_t * ptd, f64 timeout);

/* Protocol parsing functions */
int ips_parse_ethernet (vlib_buffer_t * b, ips_flow_t * flow);
int ips_parse_ip4 (vlib_buffer_t * b, ips_flow_t * flow);
int ips_parse_ip6 (vlib_buffer_t * b, ips_flow_t * flow);
int ips_parse_tcp (vlib_buffer_t * b, ips_flow_t * flow);
int ips_parse_udp (vlib_buffer_t * b, ips_flow_t * flow);
int ips_parse_icmp (vlib_buffer_t * b, ips_flow_t * flow);
int ips_parse_icmpv6 (vlib_buffer_t * b, ips_flow_t * flow);
void ips_detect_app_protocol (ips_flow_t * flow);
int ips_parse_encapsulation (vlib_buffer_t * b, ips_flow_t * flow);
int ips_parse_from_ip_layer (vlib_buffer_t * b, ips_flow_t * flow, int is_ip6);

/* PCRE to Hyperscan support functions - re-enabled */
int ips_convert_pcre_to_hyperscan (const char *pcre_pattern, u8 **hs_pattern,
                                   unsigned int *hs_flags, u8 **error_msg);
void ips_free_converted_pattern (char *pattern);
int ips_validate_pcre_for_hyperscan (const char *pcre_pattern, u8 **error_msg);

/* Utility functions for string handling */
char *ips_strdup (const char *s);
char *ips_strtok_r (char *str, const char *delim, char **saveptr);

/* Node functions */
extern vlib_node_registration_t ips_input_node;

/* Format functions */
format_function_t format_ips_flow_key;
format_function_t format_ips_rule;


#endif /* __included_ips_h__ */
