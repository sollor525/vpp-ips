/*
 * ips_detection_advanced.c - Advanced Detection Engine for Suricata Rules
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/tcp/tcp.h>
#include <vnet/udp/udp.h>
#include <string.h>

#include "ips.h"
#include "detection/ips_detection.h"

/* Helper functions for memory operations */
static u8 *
simple_memmem (const u8 *haystack, u32 haystack_len, const u8 *needle, u32 needle_len)
{
  if (needle_len == 0)
    return (u8 *) haystack;

  if (needle_len > haystack_len)
    return NULL;

  for (u32 i = 0; i <= haystack_len - needle_len; i++)
  {
    if (memcmp (haystack + i, needle, needle_len) == 0)
      return (u8 *) (haystack + i);
  }

  return NULL;
}



/* Flow bits storage per thread */
typedef struct
{
  uword *flowbits_hash; /* Hash table for flow bits */
  u32 *flowbits_pool;   /* Pool of flow bit indices */
} ips_flowbits_t;

/* Threshold tracking */
typedef struct
{
  u32 count;
  f64 first_time;
  f64 last_time;
} ips_threshold_entry_t;

static ips_flowbits_t *flowbits_per_thread = NULL;
static uword *threshold_hash = NULL;
static ips_threshold_entry_t *threshold_pool = NULL;

/**
 * @brief Check flow state against rule requirements
 */
static int
check_flow_state (ips_flow_t *flow, ips_rule_options_t *options)
{
  if (!flow || !options)
    return 0;

  /* Check flow direction */
  if (options->flow_to_client && flow->direction != IPS_FLOW_DIR_TO_CLIENT)
    return 0;
  if (options->flow_to_server && flow->direction != IPS_FLOW_DIR_TO_SERVER)
    return 0;
  if (options->flow_from_client && flow->direction != IPS_FLOW_DIR_FROM_CLIENT)
    return 0;
  if (options->flow_from_server && flow->direction != IPS_FLOW_DIR_FROM_SERVER)
    return 0;

  /* Check flow establishment state */
  if (options->flow_established && !(flow->flags & IPS_FLOW_FLAG_ESTABLISHED))
    return 0;
  if (options->flow_not_established && (flow->flags & IPS_FLOW_FLAG_ESTABLISHED))
    return 0;
  if (options->flow_stateless && !(flow->flags & IPS_FLOW_FLAG_STATELESS))
    return 0;

  return 1;
}

/**
 * @brief Check packet size against dsize requirements
 */
static int
check_packet_size (vlib_buffer_t *b, ips_rule_options_t *options)
{
  u32 packet_size = vlib_buffer_length_in_chain (vlib_get_main (), b);

  if (options->dsize_operator == 0) /* equal */
  {
    return (packet_size == options->dsize_min);
  }
  else if (options->dsize_operator == 1) /* greater than */
  {
    return (packet_size > options->dsize_min);
  }
  else if (options->dsize_operator == 2) /* less than */
  {
    return (packet_size < options->dsize_max);
  }
  else if (options->dsize_operator == 3) /* range */
  {
    return (packet_size >= options->dsize_min && packet_size <= options->dsize_max);
  }

  return 1;
}

/**
 * @brief Perform byte test on packet data
 */
static int
check_byte_test (vlib_buffer_t *b, ips_flow_t *flow, ips_rule_options_t *options)
{
  u8 *data;
  u32 offset;
  u32 value = 0;
  u32 i;

  if (!options->byte_test_enabled)
    return 1;

  /* Determine data pointer and offset */
  if (options->byte_test_relative && flow->app_header)
  {
    data = flow->app_header;
    offset = options->byte_test_offset;
  }
  else
  {
    data = vlib_buffer_get_current (b);
    offset = options->byte_test_offset;
  }

  /* Check bounds */
  if (offset + options->byte_test_bytes > vlib_buffer_length_in_chain (vlib_get_main (), b))
    return 0;

  /* Extract value based on byte count */
  for (i = 0; i < options->byte_test_bytes && i < 4; i++)
  {
    value = (value << 8) | data[offset + i];
  }

  /* Apply operator */
  switch (options->byte_test_operator)
  {
  case 0: /* equal */
    return (value == options->byte_test_value);
  case 1: /* greater than */
    return (value > options->byte_test_value);
  case 2: /* less than */
    return (value < options->byte_test_value);
  case 3: /* bitwise AND */
    return ((value & options->byte_test_value) != 0);
  case 4: /* bitwise OR */
    return ((value | options->byte_test_value) != 0);
  default:
    return 0;
  }
}

/**
 * @brief Check data availability at specified position
 */
static int
check_isdataat (vlib_buffer_t *b, ips_flow_t *flow, ips_rule_options_t *options)
{
  u8 *data;
  u32 offset;
  u32 available_data;

  if (!options->isdataat_enabled)
    return 1;

  /* Determine data pointer and offset */
  if (options->isdataat_relative && flow->app_header)
  {
    data = flow->app_header;
    offset = options->isdataat_size;
    available_data = flow->app_len;
  }
  else
  {
    data = vlib_buffer_get_current (b);
    offset = options->isdataat_size;
    available_data = vlib_buffer_length_in_chain (vlib_get_main (), b);
  }

  return (offset <= available_data);
}

/**
 * @brief Enhanced content matching with advanced options
 */
static int
match_content_advanced (vlib_buffer_t *b, ips_flow_t *flow, ips_rule_t *rule)
{
  u8 *data;
  u32 data_len;
  u32 search_start = 0;
  u32 search_end;
  u8 *pattern;
  u32 pattern_len;
  u32 i, j;
  int case_sensitive = 1;

  if (!rule->content && !rule->content_hex)
    return 1;

  /* Determine search data */
  if (rule->options.http_uri && flow->app_proto == IPS_APP_PROTO_HTTP)
  {
    /* Search in HTTP URI - simplified for now */
    data = flow->app_header;
    data_len = flow->app_len;
  }
  else if (rule->options.rawbytes || !flow->app_header)
  {
    /* Search in raw packet data */
    data = vlib_buffer_get_current (b);
    data_len = vlib_buffer_length_in_chain (vlib_get_main (), b);
  }
  else
  {
    /* Search in application data */
    data = flow->app_header;
    data_len = flow->app_len;
  }

  if (!data || data_len == 0)
    return 0;

  /* Apply offset */
  if (rule->options.offset > 0)
  {
    if (rule->options.offset >= data_len)
      return 0;
    search_start = rule->options.offset;
  }

  /* Apply depth */
  if (rule->options.depth > 0)
  {
    search_end = clib_min (search_start + rule->options.depth, data_len);
  }
  else
  {
    search_end = data_len;
  }

  /* Determine pattern to search */
  if (rule->content_hex)
  {
    pattern = rule->content_hex;
    pattern_len = rule->content_hex_len;
  }
  else
  {
    pattern = rule->content;
    pattern_len = rule->content_len;
  }

  if (!pattern || pattern_len == 0)
    return 0;

  /* Case sensitivity */
  case_sensitive = !rule->options.nocase;

  /* Search for pattern */
  for (i = search_start; i <= search_end - pattern_len; i++)
  {
    int match = 1;
    for (j = 0; j < pattern_len; j++)
    {
      u8 data_byte = data[i + j];
      u8 pattern_byte = pattern[j];

      if (!case_sensitive)
      {
        /* Simple case-insensitive comparison */
        if (data_byte >= 'A' && data_byte <= 'Z')
          data_byte += 32;
        if (pattern_byte >= 'A' && pattern_byte <= 'Z')
          pattern_byte += 32;
      }

      if (data_byte != pattern_byte)
      {
        match = 0;
        break;
      }
    }

    if (match)
    {
      /* Apply distance and within constraints for multiple content matches */
      if (rule->options.distance > 0 || rule->options.within > 0)
      {
        /* This would require tracking previous match positions */
        /* Simplified implementation for now */
      }
      return 1;
    }
  }

  return 0;
}

/**
 * @brief Check threshold limits
 */
static int
check_threshold (ips_rule_t *rule, ips_flow_t *flow, u32 src_ip, u32 dst_ip)
{
  ips_threshold_entry_t *entry;
  uword *p;
  u32 key;
  f64 now = vlib_time_now (vlib_get_main ());

  if (!rule->options.threshold_count)
    return 1;

  /* Generate threshold key based on tracking type */
  switch (rule->options.threshold_track)
  {
  case 0: /* by_src */
    key = src_ip;
    break;
  case 1: /* by_dst */
    key = dst_ip;
    break;
  case 2: /* by_rule */
    key = rule->rule_id;
    break;
  default:
    return 1;
  }

  /* Lookup or create threshold entry */
  if (!threshold_hash)
    threshold_hash = hash_create (0, sizeof (uword));

  p = hash_get (threshold_hash, key);
  if (!p)
  {
    /* Create new entry */
    pool_get (threshold_pool, entry);
    clib_memset (entry, 0, sizeof (*entry));
    entry->first_time = now;
    entry->last_time = now;
    entry->count = 1;
    hash_set (threshold_hash, key, entry - threshold_pool);
    return 1;
  }

  entry = pool_elt_at_index (threshold_pool, p[0]);

  /* Check if time window has expired */
  if (now - entry->first_time > rule->options.threshold_seconds)
  {
    /* Reset counter */
    entry->first_time = now;
    entry->count = 1;
    entry->last_time = now;
    return 1;
  }

  /* Update counter */
  entry->count++;
  entry->last_time = now;

  /* Apply threshold logic */
  switch (rule->options.threshold_type)
  {
  case 0: /* limit */
    return (entry->count <= rule->options.threshold_count);
  case 1: /* threshold */
    return (entry->count >= rule->options.threshold_count);
  case 2: /* both */
    return (entry->count == rule->options.threshold_count);
  default:
    return 1;
  }
}

/**
 * @brief Check and manage flow bits
 */
static int
check_flowbits (ips_flow_t *flow, ips_rule_options_t *options, u32 thread_index)
{
  ips_flowbits_t *fb;
  uword *p;
  u32 bit_hash;

  if (!options->flowbits_name)
    return 1;

  /* Initialize flow bits for this thread if needed */
  if (!flowbits_per_thread)
  {
    vec_validate (flowbits_per_thread, vlib_get_n_threads () - 1);
  }

  fb = &flowbits_per_thread[thread_index];
  if (!fb->flowbits_hash)
    fb->flowbits_hash = hash_create_string (0, sizeof (uword));

  /* Generate hash for flow bit name */
  bit_hash = hash_string ((char *) options->flowbits_name);

  switch (options->flowbits_cmd)
  {
  case 0: /* set */
    hash_set (fb->flowbits_hash, bit_hash, 1);
    return 1;
  case 1: /* isset */
    p = hash_get (fb->flowbits_hash, bit_hash);
    return (p != NULL);
  case 2: /* isnotset */
    p = hash_get (fb->flowbits_hash, bit_hash);
    return (p == NULL);
  case 3: /* toggle */
    p = hash_get (fb->flowbits_hash, bit_hash);
    if (p)
      hash_unset (fb->flowbits_hash, bit_hash);
    else
      hash_set (fb->flowbits_hash, bit_hash, 1);
    return 1;
  case 4: /* unset */
    hash_unset (fb->flowbits_hash, bit_hash);
    return 1;
  case 5: /* noalert */
    return 1; /* Always pass, but suppress alert */
  default:
    return 1;
  }
}

/**
 * @brief Check TCP flags against rule requirements
 */
static int
check_tcp_flags (vlib_buffer_t *b, ips_flow_t *flow, ips_rule_options_t *options)
{
  tcp_header_t *tcp;
  u8 packet_flags;

  if (!options->tcp_flags_enabled)
    return 1;

  /* Only check TCP packets */
  if (flow->key.protocol != 6)
    return 1;

  tcp = (tcp_header_t *) flow->l4_header;
  if (!tcp)
    return 0;

  packet_flags = tcp->flags;

  /* Apply mask and compare */
  u8 masked_packet_flags = packet_flags & options->tcp_flags_mask;
  u8 expected_flags = options->tcp_flags_value & options->tcp_flags_mask;

  int match = (masked_packet_flags == expected_flags);

  /* Apply negation if specified */
  if (options->tcp_flags_not)
    match = !match;

  return match;
}

/**
 * @brief Check TTL/Hop limit against rule requirements
 */
static int
check_ttl (vlib_buffer_t *b, ips_flow_t *flow, ips_rule_options_t *options)
{
  u8 packet_ttl;

  if (!options->ttl_enabled)
    return 1;

  if (flow->key.is_ip6)
  {
    ip6_header_t *ip6 = (ip6_header_t *) flow->l3_header;
    if (!ip6)
      return 0;
    packet_ttl = ip6->hop_limit;
  }
  else
  {
    ip4_header_t *ip4 = (ip4_header_t *) flow->l3_header;
    if (!ip4)
      return 0;
    packet_ttl = ip4->ttl;
  }

  switch (options->ttl_operator)
  {
  case 0: /* equal */
    return (packet_ttl == options->ttl_value);
  case 1: /* greater than */
    return (packet_ttl > options->ttl_value);
  case 2: /* less than */
    return (packet_ttl < options->ttl_value);
  default:
    return 0;
  }
}

/**
 * @brief Check TOS/Traffic class against rule requirements
 */
static int
check_tos (vlib_buffer_t *b, ips_flow_t *flow, ips_rule_options_t *options)
{
  u8 packet_tos;

  if (!options->tos_enabled)
    return 1;

  if (flow->key.is_ip6)
  {
    ip6_header_t *ip6 = (ip6_header_t *) flow->l3_header;
    if (!ip6)
      return 0;
    packet_tos = (ip6->ip_version_traffic_class_and_flow_label >> 20) & 0xFF;
  }
  else
  {
    ip4_header_t *ip4 = (ip4_header_t *) flow->l3_header;
    if (!ip4)
      return 0;
    packet_tos = ip4->tos;
  }

  u8 masked_tos = packet_tos & options->tos_mask;
  u8 expected_tos = options->tos_value & options->tos_mask;

  int match = (masked_tos == expected_tos);

  if (options->tos_not)
    match = !match;

  return match;
}

/**
 * @brief Check fragment bits against rule requirements
 */
static int
check_fragbits (vlib_buffer_t *b, ips_flow_t *flow, ips_rule_options_t *options)
{
  u8 packet_fragbits = 0;

  if (!options->fragbits_enabled)
    return 1;

  /* Only check IPv4 fragments for now */
  if (flow->key.is_ip6)
    return 1; /* Skip IPv6 for simplicity */

  ip4_header_t *ip4 = (ip4_header_t *) flow->l3_header;
  if (!ip4)
    return 0;

  u16 flags_and_fragment_offset = clib_net_to_host_u16 (ip4->flags_and_fragment_offset);

  /* Extract fragment flags */
  if (flags_and_fragment_offset & 0x4000) /* Don't Fragment */
    packet_fragbits |= 0x02;
  if (flags_and_fragment_offset & 0x2000) /* More Fragments */
    packet_fragbits |= 0x01;
  if (flags_and_fragment_offset & 0x8000) /* Reserved */
    packet_fragbits |= 0x04;

  u8 masked_fragbits = packet_fragbits & options->fragbits_mask;
  u8 expected_fragbits = options->fragbits_value & options->fragbits_mask;

  int match = (masked_fragbits == expected_fragbits);

  if (options->fragbits_not)
    match = !match;

  return match;
}

/**
 * @brief Check sequence number against rule requirements
 */
static int
check_sequence_number (vlib_buffer_t *b, ips_flow_t *flow, ips_rule_options_t *options)
{
  tcp_header_t *tcp;
  u32 packet_seq;

  if (!options->seq_enabled)
    return 1;

  /* Only check TCP packets */
  if (flow->key.protocol != 6)
    return 1;

  tcp = (tcp_header_t *) flow->l4_header;
  if (!tcp)
    return 0;

  packet_seq = clib_net_to_host_u32 (tcp->seq_number);

  return (packet_seq == options->seq_value);
}

/**
 * @brief Check acknowledgment number against rule requirements
 */
static int
check_ack_number (vlib_buffer_t *b, ips_flow_t *flow, ips_rule_options_t *options)
{
  tcp_header_t *tcp;
  u32 packet_ack;

  if (!options->ack_enabled)
    return 1;

  /* Only check TCP packets */
  if (flow->key.protocol != 6)
    return 1;

  tcp = (tcp_header_t *) flow->l4_header;
  if (!tcp)
    return 0;

  packet_ack = clib_net_to_host_u32 (tcp->ack_number);

  return (packet_ack == options->ack_value);
}

/**
 * @brief Check ICMP type/code against rule requirements
 */
static int
check_icmp_type_code (vlib_buffer_t *b, ips_flow_t *flow, ips_rule_options_t *options)
{
  icmp46_header_t *icmp;

  if (!options->icmp_type_enabled && !options->icmp_code_enabled)
    return 1;

  /* Only check ICMP packets */
  if (flow->key.protocol != 1 && flow->key.protocol != 58)
    return 1;

  icmp = (icmp46_header_t *) flow->l4_header;
  if (!icmp)
    return 0;

  if (options->icmp_type_enabled && icmp->type != options->icmp_type)
    return 0;

  if (options->icmp_code_enabled && icmp->code != options->icmp_code)
    return 0;

  return 1;
}

/**
 * @brief Enhanced HTTP content matching
 */
static int
match_http_content (vlib_buffer_t *b, ips_flow_t *flow, ips_rule_t *rule)
{
  u8 *data;
  u32 data_len;
  u8 *search_data = NULL;
  u32 search_len = 0;

  if (flow->app_proto != IPS_APP_PROTO_HTTP)
    return 1;

  data = flow->app_header;
  data_len = flow->app_len;

  if (!data || data_len == 0)
    return 0;

  /* Parse HTTP headers and extract relevant parts */
  if (rule->options.http_uri)
  {
    /* Simple URI extraction - look for GET/POST line */
    u8 *uri_start = simple_memmem (data, data_len, (u8 *)" /", 2);
    if (uri_start)
    {
      uri_start += 1; /* Skip space */
      u8 *uri_end = simple_memmem (uri_start, data_len - (uri_start - data), (u8 *)" HTTP", 5);
      if (uri_end)
      {
        search_data = uri_start;
        search_len = uri_end - uri_start;
      }
    }
  }
  else if (rule->options.http_host)
  {
    /* Extract Host header */
    u8 *host_start = simple_memmem (data, data_len, (u8 *)"Host: ", 6);
    if (host_start)
    {
      host_start += 6;
      u8 *host_end = simple_memmem (host_start, data_len - (host_start - data), (u8 *)"\r\n", 2);
      if (host_end)
      {
        search_data = host_start;
        search_len = host_end - host_start;
      }
    }
  }
  else if (rule->options.http_user_agent)
  {
    /* Extract User-Agent header */
    u8 *ua_start = simple_memmem (data, data_len, (u8 *)"User-Agent: ", 12);
    if (ua_start)
    {
      ua_start += 12;
      u8 *ua_end = simple_memmem (ua_start, data_len - (ua_start - data), (u8 *)"\r\n", 2);
      if (ua_end)
      {
        search_data = ua_start;
        search_len = ua_end - ua_start;
      }
    }
  }
  else if (rule->options.http_cookie)
  {
    /* Extract Cookie header */
    u8 *cookie_start = simple_memmem (data, data_len, (u8 *)"Cookie: ", 8);
    if (cookie_start)
    {
      cookie_start += 8;
      u8 *cookie_end = simple_memmem (cookie_start, data_len - (cookie_start - data), (u8 *)"\r\n", 2);
      if (cookie_end)
      {
        search_data = cookie_start;
        search_len = cookie_end - cookie_start;
      }
    }
  }
  else
  {
    /* Default to full HTTP data */
    search_data = data;
    search_len = data_len;
  }

  if (!search_data || search_len == 0)
    return 0;

  /* Perform content matching on extracted data */
  if (rule->content && rule->content_len > 0)
  {
    u8 *pattern = rule->content;
    u32 pattern_len = rule->content_len;

    if (search_len < pattern_len)
      return 0;

    for (u32 i = 0; i <= search_len - pattern_len; i++)
    {
      int match = 1;
      for (u32 j = 0; j < pattern_len; j++)
      {
        u8 data_byte = search_data[i + j];
        u8 pattern_byte = pattern[j];

        if (rule->options.nocase)
        {
          if (data_byte >= 'A' && data_byte <= 'Z')
            data_byte += 32;
          if (pattern_byte >= 'A' && pattern_byte <= 'Z')
            pattern_byte += 32;
        }

        if (data_byte != pattern_byte)
        {
          match = 0;
          break;
        }
      }

      if (match)
        return 1;
    }
  }

  return 0;
}

/**
 * @brief Advanced rule matching with Suricata features
 */
int
ips_match_rule_advanced (vlib_buffer_t *b, ips_flow_t *flow, ips_rule_t *rule, u32 thread_index)
{
  u32 src_ip = 0, dst_ip = 0;

  if (!b || !flow || !rule)
    return 0;

  /* Extract IP addresses for threshold tracking */
  if (!flow->key.is_ip6)
  {
    src_ip = flow->key.src_ip4.as_u32;
    dst_ip = flow->key.dst_ip4.as_u32;
  }

  /* Check if this rule uses advanced features - if not, skip advanced checks */
  int uses_advanced_features = (
    rule->options.flow_to_client || rule->options.flow_to_server ||
    rule->options.flow_from_client || rule->options.flow_from_server ||
    rule->options.flow_established || rule->options.flow_not_established ||
    rule->options.flow_stateless || rule->options.dsize_operator ||
    rule->options.tcp_flags_enabled || rule->options.ttl_enabled ||
    rule->options.tos_enabled || rule->options.fragbits_enabled ||
    rule->options.seq_enabled || rule->options.ack_enabled ||
    rule->options.icmp_type_enabled || rule->options.icmp_code_enabled ||
    rule->options.byte_test_enabled || rule->options.isdataat_enabled ||
    rule->options.http_uri || rule->options.http_host ||
    rule->options.http_user_agent || rule->options.http_cookie ||
    rule->options.threshold_count || rule->options.flowbits_cmd ||
    rule->options.pcre_pattern /* PCRE pattern support */
  );

  /* For basic rules, only do minimal checks */
  if (!uses_advanced_features)
  {
    /* Rule matched - update stats */
    /* NOTE: Do NOT increment match_count here to avoid double counting.
     * The match_count will be incremented in ips_generate_detailed_log()
     * when the alert/log is actually generated. */
    rule->last_match_time = vlib_time_now (vlib_get_main ());
    return 1;
  }

  /* Apply advanced checks only for rules that use advanced features */

  /* Check flow state requirements */
  if (!check_flow_state (flow, &rule->options))
    return 0;

  /* Check packet size */
  if (!check_packet_size (b, &rule->options))
    return 0;

  /* Check TCP flags */
  if (!check_tcp_flags (b, flow, &rule->options))
    return 0;

  /* Check TTL/Hop limit */
  if (!check_ttl (b, flow, &rule->options))
    return 0;

  /* Check TOS/Traffic class */
  if (!check_tos (b, flow, &rule->options))
    return 0;

  /* Check fragment bits */
  if (!check_fragbits (b, flow, &rule->options))
    return 0;

  /* Check sequence number */
  if (!check_sequence_number (b, flow, &rule->options))
    return 0;

  /* Check acknowledgment number */
  if (!check_ack_number (b, flow, &rule->options))
    return 0;

  /* Check ICMP type/code */
  if (!check_icmp_type_code (b, flow, &rule->options))
    return 0;

  /* Check byte test */
  if (!check_byte_test (b, flow, &rule->options))
    return 0;

  /* Check data availability */
  if (!check_isdataat (b, flow, &rule->options))
    return 0;

  /* Check content with advanced options */
  if (rule->options.http_uri || rule->options.http_host ||
      rule->options.http_user_agent || rule->options.http_cookie)
  {
    if (!match_http_content (b, flow, rule))
      return 0;
  }
  else if (rule->options.offset || rule->options.depth || rule->options.distance || rule->options.within)
  {
    /* Only do advanced content matching if rule uses content modifiers */
    if (!match_content_advanced (b, flow, rule))
      return 0;
  }

  /* Check flow bits */
  if (!check_flowbits (flow, &rule->options, thread_index))
    return 0;

  /* Check threshold */
  if (!check_threshold (rule, flow, src_ip, dst_ip))
    return 0;

  /* Rule matched */
  /* NOTE: Do NOT increment match_count here to avoid double counting.
   * The match_count will be incremented in ips_generate_detailed_log()
   * when the alert/log is actually generated. */
  rule->last_match_time = vlib_time_now (vlib_get_main ());

  return 1;
}

/**
 * @brief Initialize advanced detection engine
 */
void
ips_detection_advanced_init (void)
{
  /* Initialize global data structures */
  threshold_hash = hash_create (0, sizeof (uword));

  clib_warning ("Advanced IPS detection engine initialized");
}



/* Note: Duplicate function definitions removed to fix linter errors.
 * These functions are already defined earlier in the file. */
