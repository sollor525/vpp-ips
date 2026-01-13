/*
 * ips_suricata_inspect_node.c - Enhanced IPS Suricata Rule Inspection Node
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>

#include "../ips.h"
#include "../session/ips_session.h"
#include "../protocols/ips_protocol_detection.h"
#include "ips_suricata_engine.h"
#include "ips_suricata_rule_types.h"
#include "ips_flowbits.h"
#include "ips_byte_operations.h"
#include "ips_rule_index.h"
#include "../ips_logging.h"

/* Trace context for debugging */
typedef struct
{
    u32 next_index;
    u32 session_index;
    u32 thread_index;
    u32 packet_len;
    ips_protocol_t protocol;
    u16 src_port;
    u16 dst_port;
    u32 rules_examined;
    u32 rules_matched;
    u32 action;  /* 0=pass, 1=alert, 2=drop, 3=reject */
    f64 match_time;
    char matched_sids[256];  /* Comma-separated list of matched SIDs */
} ips_suricata_inspect_trace_t;

/* Next node indices - simplified for mirror traffic processing */
typedef enum
{
    IPS_SURICATA_INSPECT_NEXT_DROP,       /* Drop malformed/processed packets */
    IPS_SURICATA_INSPECT_NEXT_BLOCK,      /* Send to block node for action */
    IPS_SURICATA_INSPECT_N_NEXT,
} ips_suricata_inspect_next_t;

/* Per-thread statistics */
typedef struct
{
    u64 packets_processed;
    u64 rules_matched;
    u64 packets_blocked;
    u64 packets_alerted;
    u64 packets_passed;
    u64 packets_rejected;
    u64 total_inspect_time_ns;
    u64 max_inspect_time_ns;
    u64 session_timeouts;
    u64 flowbit_operations;
    u64 byte_operations;
    u64 content_matches;
} ips_suricata_inspect_stats_t;

/* Global statistics */
static ips_suricata_inspect_stats_t *suricata_inspect_stats;

/* Error strings */
static char *suricata_inspect_error_strings[] = {
#define _(sym,string) string,
    _(NONE, "No error")
    _(SESSION_TIMEOUT, "Session timeout")
    _(RULE_MATCH_ERROR, "Rule match error")
    _(FLOWBIT_ERROR, "Flowbit error")
    _(PARSE_ERROR, "Packet parse error")
#undef _
};

/* Static function prototypes */
// todo
static u8 *format_suricata_inspect_trace (u8 *s, va_list *args);
static uword suricata_inspect_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame);

VLIB_REGISTER_NODE (suricata_inspect_node) = {
    .name = "suricata-inspect",
    .function = suricata_inspect_node_fn,
    .vector_size = sizeof (u32),
    .format_trace = format_suricata_inspect_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,

    .n_errors = ARRAY_LEN(suricata_inspect_error_strings),
    .error_strings = suricata_inspect_error_strings,

    .n_next_nodes = IPS_SURICATA_INSPECT_N_NEXT,
    .next_nodes = {
        [IPS_SURICATA_INSPECT_NEXT_DROP] = "error-drop",
        [IPS_SURICATA_INSPECT_NEXT_BLOCK] = "ips-block-node"
    },
};

/**
 * @brief Format trace information
 */
static u8 *
format_suricata_inspect_trace (u8 *s, va_list *args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    ips_suricata_inspect_trace_t *t = va_arg (*args, ips_suricata_inspect_trace_t *);

    s = format (s, "SURICATA_INSPECT: session %d thread %d len %d proto %d ",
               t->session_index, t->thread_index, t->packet_len, t->protocol);
    s = format (s, "src %d dst %d rules_examined %d matched %d action %d time %.2fus",
               t->src_port, t->dst_port, t->rules_examined, t->rules_matched,
               t->action, t->match_time * 1000000);

    if (t->rules_matched > 0) {
        s = format (s, " matched_sids: %s", t->matched_sids);
    }

    return s;
}

/**
 * @brief Map VPP protocol to Suricata protocol
 */
static ips_protocol_t
ips_map_vpp_to_suricata_protocol(u8 vpp_proto)
{
    switch (vpp_proto) {
    case IP_PROTOCOL_TCP:
        return IPS_PROTO_TCP;
    case IP_PROTOCOL_UDP:
        return IPS_PROTO_UDP;
    case IP_PROTOCOL_ICMP:
        return IPS_PROTO_ICMP;
    default:
        return IPS_PROTO_IP;
    }
}

/**
 * @brief Extract packet information
 */
static int
ips_extract_packet_info(vlib_buffer_t *b, ips_packet_context_t *ctx,
                        ip4_header_t **ip4_hdr, ip6_header_t **ip6_hdr,
                        tcp_header_t **tcp_hdr, udp_header_t **udp_hdr)
{
    u8 *packet_data = vlib_buffer_get_current(b);
    u32 packet_len = b->current_length;

    if (packet_len < sizeof(ip4_header_t))
        return -1;

    /* Initialize pointers */
    *ip4_hdr = NULL;
    *ip6_hdr = NULL;
    *tcp_hdr = NULL;
    *udp_hdr = NULL;

    /* Check IP version */
    ip4_header_t *ip4 = (ip4_header_t *)packet_data;
    if ((ip4->ip_version_and_header_length & 0xF0) == 0x40) {
        /* IPv4 */
        *ip4_hdr = ip4;
        u32 ip_hdr_len = (ip4->ip_version_and_header_length & 0x0F) * 4;

        if (packet_len < ip_hdr_len)
            return -1;

        u8 *payload = packet_data + ip_hdr_len;
        u32 payload_len = packet_len - ip_hdr_len;

        if (ip4->protocol == IP_PROTOCOL_TCP && payload_len >= sizeof(tcp_header_t)) {
            *tcp_hdr = (tcp_header_t *)payload;
        } else if (ip4->protocol == IP_PROTOCOL_UDP && payload_len >= sizeof(udp_header_t)) {
            *udp_hdr = (udp_header_t *)payload;
        }

        ctx->protocol = ips_map_vpp_to_suricata_protocol(ip4->protocol);
        ctx->src_ip.ip4 = ip4->src_address;
        ctx->dst_ip.ip4 = ip4->dst_address;

    } else if ((ip4->ip_version_and_header_length & 0xF0) == 0x60) {
        /* IPv6 */
        ip6_header_t *ip6 = (ip6_header_t *)packet_data;
        *ip6_hdr = ip6;

        u8 *payload = packet_data + sizeof(ip6_header_t);
        u32 payload_len = packet_len - sizeof(ip6_header_t);

        if (ip6->protocol == IP_PROTOCOL_TCP && payload_len >= sizeof(tcp_header_t)) {
            *tcp_hdr = (tcp_header_t *)payload;
        } else if (ip6->protocol == IP_PROTOCOL_UDP && payload_len >= sizeof(udp_header_t)) {
            *udp_hdr = (udp_header_t *)payload;
        }

        ctx->protocol = ips_map_vpp_to_suricata_protocol(ip6->protocol);
        ctx->src_ip.ip6 = ip6->src_address;
        ctx->dst_ip.ip6 = ip6->dst_address;

    } else {
        return -1;  /* Invalid IP version */
    }

    /* Extract ports */
    if (*tcp_hdr) {
        ctx->src_port = clib_net_to_host_u16((*tcp_hdr)->src_port);
        ctx->dst_port = clib_net_to_host_u16((*tcp_hdr)->dst_port);
        ctx->tcp_flags = (*tcp_hdr)->flags;
        ctx->seq = clib_net_to_host_u32((*tcp_hdr)->seq_number);
        ctx->ack = clib_net_to_host_u32((*tcp_hdr)->ack_number);
        ctx->window = clib_net_to_host_u16((*tcp_hdr)->window);
    } else if (*udp_hdr) {
        ctx->src_port = clib_net_to_host_u16((*udp_hdr)->src_port);
        ctx->dst_port = clib_net_to_host_u16((*udp_hdr)->dst_port);
    }

    ctx->packet_data = packet_data;
    ctx->packet_len = packet_len;

    return 0;
}

/**
 * @brief Execute rule action and update statistics
 */
static int
ips_execute_rule_action(ips_suricata_rule_t *rule,
                        ips_suricata_inspect_trace_t *trace,
                        u32 thread_index)
{
    ips_suricata_inspect_stats_t *stats = &suricata_inspect_stats[thread_index];

    switch (rule->action) {
    case IPS_ACTION_ALERT:
        stats->packets_alerted++;
        trace->action = 1;  /* Alert */

        ips_log_system_async(IPS_LOG_LEVEL_INFO,
                            "ALERT: SID:%u Rev:%u GID:%u Msg:%s",
                            rule->sid, rule->rev, rule->gid, rule->msg);
        return 0;  /* Allow packet */

    case IPS_ACTION_DROP:
        stats->packets_blocked++;
        trace->action = 2;  /* Drop */

        ips_log_system_async(IPS_LOG_LEVEL_INFO,
                            "DROP: SID:%u Rev:%u GID:%u Msg:%s",
                            rule->sid, rule->rev, rule->gid, rule->msg);
        return 1;  /* Block packet */

    case IPS_ACTION_REJECT:
        stats->packets_rejected++;
        trace->action = 3;  /* Reject */

        ips_log_system_async(IPS_LOG_LEVEL_INFO,
                            "REJECT: SID:%u Rev:%u GID:%u Msg:%s",
                            rule->sid, rule->rev, rule->gid, rule->msg);
        return 1;  /* Block packet */

    case IPS_ACTION_LOG:
        ips_log_system_async(IPS_LOG_LEVEL_INFO,
                            "LOG: SID:%u Rev:%u GID:%u Msg:%s",
                            rule->sid, rule->rev, rule->gid, rule->msg);
        return 0;  /* Allow packet */

    case IPS_ACTION_PASS:
        stats->packets_passed++;
        return 0;  /* Allow packet */

    default:
        return 0;  /* Default to allow */
    }
}

/**
 * @brief Main inspection node function
 */
static uword
suricata_inspect_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame) {
    u32 node_index = node->node_index;
    ips_suricata_inspect_trace_t *t = NULL;
    CLIB_UNUSED (u32 *from) = vlib_frame_vector_args (frame);
    vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
    u16 n_left_from;
    CLIB_UNUSED (u16 n_left_to_next);

    u32 thread_index = vm->thread_index;
    ips_suricata_inspect_stats_t *stats = &suricata_inspect_stats[thread_index];

    n_left_from = frame->n_vectors;
    b = bufs;
    n_left_to_next = node->cached_next_index;

    while (n_left_from > 0) {
        u32 next0 = IPS_SURICATA_INSPECT_NEXT_DROP;  /* Default: drop processed mirror traffic */
        vlib_buffer_t *b0 = b[0];
        ips_session_t *session0 = NULL;
        int error = 0;

        /* Get session from buffer metadata */
        /* TODO: Get session from VPP buffer or session manager */
        /* For now, we'll create a temporary session for testing */
        static ips_session_t temp_session;
        clib_memset(&temp_session, 0, sizeof(temp_session));
        session0 = &temp_session;
        session0->session_index = b0->error;  /* Using error field temporarily */
        session0->packet_count_src++;

        /* Create trace record */
        if (b0->flags & VLIB_BUFFER_IS_TRACED) {
            t = vlib_add_trace(vm, node, b0, sizeof(*t));
            clib_memset(t, 0, sizeof(*t));
            t->thread_index = thread_index;
            t->session_index = session0->session_index;
            t->packet_len = b0->current_length;
        }

        f64 start_time = vlib_time_now(vm);

        /* Extract packet information */
        ips_packet_context_t ctx = {0};
        ip4_header_t *ip4_hdr = NULL;
        ip6_header_t *ip6_hdr = NULL;
        tcp_header_t *tcp_hdr = NULL;
        udp_header_t *udp_hdr = NULL;

        if (ips_extract_packet_info(b0, &ctx, &ip4_hdr, &ip6_hdr,
                                   &tcp_hdr, &udp_hdr) < 0) {
            error = 4;  /* PARSE_ERROR */
            stats->packets_processed++;
            goto trace;
        }

        /* Update trace with packet info */
        if (t) {
            t->protocol = ctx.protocol;
            t->src_port = ctx.src_port;
            t->dst_port = ctx.dst_port;
        }

        /* Initialize Suricata engine if not already done */
        if (!ips_suricata_engine_is_initialized()) {
            clib_error_t *error = ips_suricata_engine_init(NULL);
            if (error) {
                ips_log_system_async(IPS_LOG_LEVEL_ERROR,
                                   "Failed to initialize Suricata engine");
            } else {
                ips_rule_index_init();
                ips_flowbits_init();
            }
        }

        /* Match packet against rules */
        int match_result = ips_suricata_engine_match_packet(session0, b0, &ctx);
        if (match_result > 0) {
            /* Rules matched, evaluate actions */
            if (t) {
                t->rules_matched = match_result;
            }
            stats->rules_matched += match_result;

            /* Process first matching rule (highest priority) */
            for (u32 i = 0; i < match_result && i < ctx.matches_found; i++) {
                ips_suricata_rule_t *rule = ctx.matched_rules[i];
                if (!rule->enabled)
                    continue;

                /* Update trace with matched SID */
                if (t) {
                    if (strlen(t->matched_sids) > 0) {
                        strncat(t->matched_sids, ",", sizeof(t->matched_sids) - strlen(t->matched_sids) - 1);
                    }
                    char sid_str[32];
                    snprintf(sid_str, sizeof(sid_str), "%u", rule->sid);
                    strncat(t->matched_sids, sid_str, sizeof(t->matched_sids) - strlen(t->matched_sids) - 1);
                }

                /* Execute action */
                int action_result = ips_execute_rule_action(rule, t, thread_index);

                if (action_result > 0) {
                    /* Block packet */
                    next0 = IPS_SURICATA_INSPECT_NEXT_BLOCK;
                    break;
                }
            }
        }

        /* Update session flowbits */
        if (ctx.proto_detect_ctx && ctx.proto_detect_ctx->detected_protocol != IPS_ALPROTO_UNKNOWN) {
            ips_flowbit_cleanup_expired(thread_index, vlib_time_now(vm));
        }

        /* Update statistics */
        f64 end_time = vlib_time_now(vm);
        f64 inspect_time = end_time - start_time;
        if (t) {
            t->match_time = inspect_time;
        }

        stats->packets_processed++;
        u64 inspect_time_ns = inspect_time * 1000000000;
        stats->total_inspect_time_ns += inspect_time_ns;
        if (inspect_time_ns > stats->max_inspect_time_ns) {
            stats->max_inspect_time_ns = inspect_time_ns;
        }

    trace:
        b[0]->error = node->errors[error];
        if (t && (b[0]->flags & VLIB_BUFFER_IS_TRACED)) {
            t->next_index = next0;
        }

        /* Enqueue to next node */
        vlib_set_next_frame_buffer(vm, node, next0, b[0] - bufs[0]);
        n_left_to_next++;
        n_left_from--;
        b++;
    }

    vlib_put_frame_to_node(vm, node_index, frame);
    return frame->n_vectors;
}

/**
 * @brief Initialize Suricata inspect node
 */
static clib_error_t *
ips_suricata_inspect_init (vlib_main_t *vm)
{
    /* Allocate per-thread statistics */
    vec_validate(suricata_inspect_stats, vlib_get_n_threads() - 1);

    /* Initialize statistics */
    for (u32 i = 0; i < vlib_get_n_threads(); i++) {
        clib_memset(&suricata_inspect_stats[i], 0, sizeof(ips_suricata_inspect_stats_t));
    }

    return 0;
}

VLIB_INIT_FUNCTION (ips_suricata_inspect_init);

/**
 * @brief Get statistics
 */
void
ips_suricata_inspect_get_stats(u32 thread_index, ips_suricata_inspect_stats_t *stats)
{
    if (thread_index >= vec_len(suricata_inspect_stats))
        return;

    if (stats)
        *stats = suricata_inspect_stats[thread_index];
}

/**
 * @brief Reset statistics
 */
void
ips_suricata_inspect_reset_stats(u32 thread_index)
{
    if (thread_index >= vec_len(suricata_inspect_stats))
        return;

    clib_memset(&suricata_inspect_stats[thread_index], 0,
                sizeof(ips_suricata_inspect_stats_t));
}