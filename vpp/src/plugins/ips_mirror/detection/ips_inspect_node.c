/*
 * ips_inspect_node.c - IPS Rule Inspection Node
 *
 * Copyright (c) 2024 VPP IPS Project
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>

#include "../ips.h"
#include "../session/ips_session.h"
#include "../protocols/ips_protocol_detection.h"

typedef struct
{
    u32 next_index;
    u32 session_index;
    ips_alproto_t protocol;
    u32 rule_matches;
    u32 action;  /* 0=pass, 1=alert, 2=drop */
} ips_inspect_trace_t;

/* Next node indices - simplified for mirror traffic */
typedef enum
{
    IPS_INSPECT_NEXT_DROP,
    IPS_INSPECT_NEXT_BLOCK,      /* Send to block node for TCP reset */
    IPS_INSPECT_N_NEXT,
} ips_inspect_next_t;

/* Note: Statistics now use VPP's unified counter system via ips_main.counters */

static u8 *
format_ips_inspect_trace (u8 *s, va_list *args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    ips_inspect_trace_t *t = va_arg (*args, ips_inspect_trace_t *);

    const char *action_str = t->action == 2 ? "DROP" :
                            t->action == 1 ? "ALERT" : "PASS";
    
    s = format (s, "IPS-INSPECT: session=%u protocol=%s matches=%u action=%s next=%u",
                t->session_index,
                ips_alproto_to_string(t->protocol),
                t->rule_matches,
                action_str,
                t->next_index);
    return s;
}

/**
 * @brief Build IPv4 session key
 */
static_always_inline void
build_session_key4(ips_session_key4_t *key, ip4_header_t *ip4h, tcp_header_t *tcph)
{
    clib_memset(key, 0, sizeof(*key));
    key->src_ip = ip4h->src_address;
    key->dst_ip = ip4h->dst_address;
    key->src_port = tcph->src_port;
    key->dst_port = tcph->dst_port;
    key->protocol = ip4h->protocol;
}

/**
 * @brief Build IPv6 session key
 */
static_always_inline void
build_session_key6(ips_session_key6_t *key, ip6_header_t *ip6h, tcp_header_t *tcph)
{
    clib_memset(key, 0, sizeof(*key));
    key->src_ip = ip6h->src_address;
    key->dst_ip = ip6h->dst_address;
    key->src_port = tcph->src_port;
    key->dst_port = tcph->dst_port;
    key->protocol = ip6h->protocol;
}

/**
 * @brief Perform IPS rule inspection on packet
 * @return 0=pass, 1=alert, 2=drop
 */
static_always_inline u32
ips_inspect_packet (ips_session_t *session, 
                   vlib_buffer_t *b,
                   ips_alproto_t proto,
                   u32 *rule_matches)
{
    ips_main_t *im = &ips_main;
    *rule_matches = 0;
    
    /* Skip if no rules loaded */
    if (!im->rules || vec_len(im->rules) == 0)
        return 0;  /* Pass */
    
    /* TODO: Implement actual rule matching based on protocol
     * For now, we'll do a simple placeholder check */
    
    /* Check protocol-specific rules */
    u32 action = 0;  /* Default: pass */
    
    /* Iterate through rules and check if they match */
    for (u32 i = 0; i < vec_len(im->rules); i++)
    {
        ips_rule_t *rule = &im->rules[i];
        
        /* Skip disabled rules */
        if (!(rule->flags & IPS_RULE_FLAG_ENABLED))
            continue;
        
        /* Check if rule applies to this protocol */
        /* TODO: Add protocol filtering based on rule metadata
         * For now, apply all rules to all protocols */
        
        /* Simple IP/port matching for now */
        int matches = 1;  /* Assume match */
        
        /* TODO: Add proper pattern matching here */
        /* This would involve:
         * 1. Content matching (Hyperscan)
         * 2. PCRE matching
         * 3. Protocol-specific field matching
         */
        
        if (matches)
        {
            (*rule_matches)++;
            
            /* Determine action based on rule */
            if (rule->action == IPS_ACTION_DROP || 
                rule->action == IPS_ACTION_REJECT)
            {
                action = 2;  /* Drop */
                break;  /* Stop on first drop rule */
            }
            else if (rule->action == IPS_ACTION_ALERT)
            {
                if (action < 1)
                    action = 1;  /* Alert */
                /* Continue checking other rules */
            }
        }
    }
    
    return action;
}

/**
 * @brief IPS inspect node function
 */
static uword
ips_inspect_node_fn (vlib_main_t *vm,
                    vlib_node_runtime_t *node,
                    vlib_frame_t *frame)
{
    u32 n_left_from, *from;
    u32 thread_index = vm->thread_index;

    /* Local counters for the entire frame */
    u32 inspection_performed_count = 0;
    u32 rule_matches_count = 0;
    u32 rules_triggered_count = 0;
    u32 alerts_generated_count = 0;
    u32 packets_dropped_count = 0;
    u32 packets_passed_count = 0;
    u32 sessions_not_found_count = 0;

    from = vlib_frame_vector_args (frame);
    n_left_from = frame->n_vectors;

    while (n_left_from > 0)
    {
        u32 bi0;
        vlib_buffer_t *b0;
        u32 next0 = IPS_INSPECT_NEXT_DROP;  /* Default: drop for mirror traffic */

        bi0 = from[0];
        b0 = vlib_get_buffer (vm, bi0);

        /* Counters will be incremented after processing the entire frame */

        /* Try to get session from cached session_index first (performance optimization) */
        ips_session_t *session = NULL;
        u32 session_index = vnet_buffer(b0)->unused[0];

        /* Get session manager data for direct pool access */
        ips_session_manager_t *sm = &ips_session_manager;
        ips_session_per_thread_data_t *ptd = &sm->per_thread_data[thread_index];

        /* Try direct pool access using cached session_index */
        if (session_index != ~0 &&  /* Check if session_index is valid */
            PREDICT_TRUE(session_index < pool_len(ptd->session_pool) &&
                         !pool_is_free_index(ptd->session_pool, session_index)))
        {
            session = pool_elt_at_index(ptd->session_pool, session_index);

            /* Validate session matches */
            if (PREDICT_FALSE(session->session_index != session_index ||
                               session->thread_index != thread_index))
            {
                session = NULL; /* Session reused or invalid */
            }
        }

        /* Fallback to hash lookup if direct access failed or session_index not cached */
        if (PREDICT_FALSE(session == NULL))
        {
            u8 *ip_start = vlib_buffer_get_current (b0);
            if (b0->current_length >= sizeof(ip4_header_t))
            {
                ip4_header_t *ip4h = (ip4_header_t *)ip_start;

                if ((ip4h->ip_version_and_header_length & 0xF0) == 0x40)  /* IPv4 */
                {
                    if (ip4h->protocol == IP_PROTOCOL_TCP)
                    {
                        u32 ip_header_len = (ip4h->ip_version_and_header_length & 0x0f) * 4;
                        tcp_header_t *tcph = (tcp_header_t *)((u8 *)ip4h + ip_header_len);
                        ips_session_key4_t key4;
                        build_session_key4(&key4, ip4h, tcph);
                        session = ips_session_lookup_ipv4(thread_index, &key4);
                    }
                }
                else if ((ip4h->ip_version_and_header_length & 0xF0) == 0x60)  /* IPv6 */
                {
                    ip6_header_t *ip6h = (ip6_header_t *)ip4h;
                    if (ip6h->protocol == IP_PROTOCOL_TCP)
                    {
                        tcp_header_t *tcph = (tcp_header_t *)((u8 *)ip6h + sizeof(ip6_header_t));
                        ips_session_key6_t key6;
                        build_session_key6(&key6, ip6h, tcph);
                        session = ips_session_lookup_ipv6(thread_index, &key6);
                    }
                }
            }
        }
        
        if (session)
        {
            /* Increment local inspection counter */
            inspection_performed_count++;

            /* Get detected protocol */
            ips_proto_detect_ctx_t *proto_ctx = ips_get_proto_detect_ctx(session);
            ips_alproto_t proto = proto_ctx ? proto_ctx->detected_protocol : IPS_ALPROTO_UNKNOWN;

            /* Perform IPS rule inspection */
            u32 rule_matches = 0;
            u32 action = ips_inspect_packet(session, b0, proto, &rule_matches);

            /* Increment local rule match counters */
            rule_matches_count += rule_matches;

            /* Determine next node based on action */
            if (action == 2)  /* Drop */
            {
                /* Mark session as blocked and send to block node */
                session->flags |= IPS_SESSION_FLAG_BLOCKED;
                next0 = IPS_INSPECT_NEXT_BLOCK;
                packets_dropped_count++;
                rules_triggered_count++;
            }
            else if (action == 1)  /* Alert */
            {
                /* Generate alert but drop packet (mirror traffic) */
                /* TODO: Add alert logging */
                next0 = IPS_INSPECT_NEXT_DROP;
                alerts_generated_count++;
                rules_triggered_count++;
            }
            else  /* Pass */
            {
                next0 = IPS_INSPECT_NEXT_DROP;  /* Drop for mirror traffic */
                packets_passed_count++;
            }
            
            /* Add trace if enabled */
            if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
            {
                ips_inspect_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
                t->next_index = next0;
                t->session_index = session->session_index;
                t->protocol = proto;
                t->rule_matches = rule_matches;
                t->action = action;
            }
        }
        else
        {
            /* No session - drop for mirror traffic */
            next0 = IPS_INSPECT_NEXT_DROP;

            /* Increment local session not found counter */
            sessions_not_found_count++;
        }
        
        /* Enqueue packet to next node */
        vlib_set_next_frame_buffer (vm, node, next0, bi0);
        
        from += 1;
        n_left_from -= 1;
    }

    /* Increment counters for the entire frame */
    if (frame->n_vectors > 0) {
        vlib_increment_simple_counter(&ips_main.counters, thread_index, IPS_COUNTER_PACKETS_RECEIVED,
                                      frame->n_vectors);

        /* Calculate total bytes - use original frame pointer */
        u32 *original_from = vlib_frame_vector_args (frame);
        if (frame->n_vectors > 0) {
            u32 first_bi = original_from[0];
            vlib_buffer_t *first_b = vlib_get_buffer(vm, first_bi);
            vlib_increment_simple_counter(&ips_main.counters, thread_index, IPS_COUNTER_BYTES_RECEIVED,
                                          first_b->current_length * frame->n_vectors);
        }

        vlib_increment_simple_counter(&ips_main.counters, thread_index, IPS_COUNTER_INSPECTION_PROCESSED,
                                      frame->n_vectors);

        /* Increment inspection-specific counters */
        if (inspection_performed_count > 0) {
            vlib_increment_simple_counter(&ips_main.counters, thread_index, IPS_COUNTER_INSPECTION_PERFORMED,
                                          inspection_performed_count);
        }
        if (rule_matches_count > 0) {
            vlib_increment_simple_counter(&ips_main.counters, thread_index, IPS_COUNTER_RULE_MATCHES,
                                          rule_matches_count);
        }
        if (rules_triggered_count > 0) {
            vlib_increment_simple_counter(&ips_main.counters, thread_index, IPS_COUNTER_RULES_TRIGGERED,
                                          rules_triggered_count);
        }
        if (alerts_generated_count > 0) {
            vlib_increment_simple_counter(&ips_main.counters, thread_index, IPS_COUNTER_ALERTS_GENERATED,
                                          alerts_generated_count);
        }
        if (packets_dropped_count > 0) {
            vlib_increment_simple_counter(&ips_main.counters, thread_index, IPS_COUNTER_PACKETS_DROPPED,
                                          packets_dropped_count);
        }
        if (packets_passed_count > 0) {
            vlib_increment_simple_counter(&ips_main.counters, thread_index, IPS_COUNTER_PACKETS_PASSED,
                                          packets_passed_count);
        }
        if (sessions_not_found_count > 0) {
            vlib_increment_simple_counter(&ips_main.counters, thread_index, IPS_COUNTER_SESSION_NOT_FOUND,
                                          sessions_not_found_count);
        }
    }

    return frame->n_vectors;
}

VLIB_REGISTER_NODE (ips_inspect_node) = {
    .function = ips_inspect_node_fn,
    .name = "ips-inspect",
    .vector_size = sizeof (u32),
    .format_trace = format_ips_inspect_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,

    .n_next_nodes = IPS_INSPECT_N_NEXT,
    .next_nodes = {
        [IPS_INSPECT_NEXT_DROP] = "error-drop",
        [IPS_INSPECT_NEXT_BLOCK] = "ips-block-node",
    },
    
};

