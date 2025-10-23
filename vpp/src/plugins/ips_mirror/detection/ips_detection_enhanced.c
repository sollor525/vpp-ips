/*
 * ips_detection_enhanced.c - Enhanced Detection Engine with Full Suricata Support
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/tcp/tcp.h>
#include <vnet/udp/udp.h>
#include <vppinfra/string.h>

#include "ips.h"
#include "detection/ips_detection.h"

/**
 * @brief Simple memory compare function
 */
static inline int
ips_memcmp (const u8 *s1, const u8 *s2, u32 n)
{
  for (u32 i = 0; i < n; i++)
  {
    if (s1[i] != s2[i])
      return (s1[i] < s2[i]) ? -1 : 1;
  }
  return 0;
}

/**
 * @brief Simple memory search function
 */
static u8 *
ips_memmem (const u8 *haystack, u32 haystack_len, const u8 *needle, u32 needle_len)
{
  if (needle_len == 0 || haystack_len < needle_len)
    return NULL;

  for (u32 i = 0; i <= haystack_len - needle_len; i++)
  {
    if (ips_memcmp (haystack + i, needle, needle_len) == 0)
      return (u8 *) (haystack + i);
  }

  return NULL;
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

  if (flow->key.protocol != 6) /* TCP */
    return 1;

  tcp = (tcp_header_t *) flow->l4_header;
  if (!tcp)
    return 0;

  packet_flags = tcp->flags;

  u8 masked_packet_flags = packet_flags & options->tcp_flags_mask;
  u8 expected_flags = options->tcp_flags_value & options->tcp_flags_mask;

  int match = (masked_packet_flags == expected_flags);

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
  case 0: return (packet_ttl == options->ttl_value);
  case 1: return (packet_ttl > options->ttl_value);
  case 2: return (packet_ttl < options->ttl_value);
  default: return 0;
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

  if (flow->key.is_ip6)
    return 1; /* Skip IPv6 for now */

  ip4_header_t *ip4 = (ip4_header_t *) flow->l3_header;
  if (!ip4)
    return 0;

  u16 flags_frag = clib_net_to_host_u16 (ip4->flags_and_fragment_offset);

  if (flags_frag & 0x4000) packet_fragbits |= 0x02; /* DF */
  if (flags_frag & 0x2000) packet_fragbits |= 0x01; /* MF */
  if (flags_frag & 0x8000) packet_fragbits |= 0x04; /* Reserved */

  u8 masked_fragbits = packet_fragbits & options->fragbits_mask;
  u8 expected_fragbits = options->fragbits_value & options->fragbits_mask;

  int match = (masked_fragbits == expected_fragbits);

  if (options->fragbits_not)
    match = !match;

  return match;
}

/**
 * @brief Check sequence number
 */
static int
check_sequence_number (vlib_buffer_t *b, ips_flow_t *flow, ips_rule_options_t *options)
{
  if (!options->seq_enabled || flow->key.protocol != 6)
    return 1;

  tcp_header_t *tcp = (tcp_header_t *) flow->l4_header;
  if (!tcp)
    return 0;

  u32 packet_seq = clib_net_to_host_u32 (tcp->seq_number);
  return (packet_seq == options->seq_value);
}

/**
 * @brief Check acknowledgment number
 */
static int
check_ack_number (vlib_buffer_t *b, ips_flow_t *flow, ips_rule_options_t *options)
{
  if (!options->ack_enabled || flow->key.protocol != 6)
    return 1;

  tcp_header_t *tcp = (tcp_header_t *) flow->l4_header;
  if (!tcp)
    return 0;

  u32 packet_ack = clib_net_to_host_u32 (tcp->ack_number);
  return (packet_ack == options->ack_value);
}

/**
 * @brief Check ICMP type/code
 */
static int
check_icmp_type_code (vlib_buffer_t *b, ips_flow_t *flow, ips_rule_options_t *options)
{
  if (!options->icmp_type_enabled && !options->icmp_code_enabled)
    return 1;

  if (flow->key.protocol != 1 && flow->key.protocol != 58) /* ICMP/ICMPv6 */
    return 1;

  icmp46_header_t *icmp = (icmp46_header_t *) flow->l4_header;
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
  u8 *data, *search_data = NULL;
  u32 data_len, search_len = 0;

  if (flow->app_proto != IPS_APP_PROTO_HTTP)
    return 1;

  data = flow->app_header;
  data_len = flow->app_len;

  if (!data || data_len == 0)
    return 0;

  /* Extract specific HTTP components */
  if (rule->options.http_uri)
  {
    u8 *uri_start = ips_memmem (data, data_len, (u8 *)" /", 2);
    if (uri_start)
    {
      uri_start += 1;
      u8 *uri_end = ips_memmem (uri_start, data_len - (uri_start - data), (u8 *)" HTTP", 5);
      if (uri_end)
      {
        search_data = uri_start;
        search_len = uri_end - uri_start;
      }
    }
  }
  else if (rule->options.http_host)
  {
    u8 *host_start = ips_memmem (data, data_len, (u8 *)"Host: ", 6);
    if (host_start)
    {
      host_start += 6;
      u8 *host_end = ips_memmem (host_start, data_len - (host_start - data), (u8 *)"\r\n", 2);
      if (host_end)
      {
        search_data = host_start;
        search_len = host_end - host_start;
      }
    }
  }
  else if (rule->options.http_user_agent)
  {
    u8 *ua_start = ips_memmem (data, data_len, (u8 *)"User-Agent: ", 12);
    if (ua_start)
    {
      ua_start += 12;
      u8 *ua_end = ips_memmem (ua_start, data_len - (ua_start - data), (u8 *)"\r\n", 2);
      if (ua_end)
      {
        search_data = ua_start;
        search_len = ua_end - ua_start;
      }
    }
  }
  else if (rule->options.http_cookie)
  {
    u8 *cookie_start = ips_memmem (data, data_len, (u8 *)"Cookie: ", 8);
    if (cookie_start)
    {
      cookie_start += 8;
      u8 *cookie_end = ips_memmem (cookie_start, data_len - (cookie_start - data), (u8 *)"\r\n", 2);
      if (cookie_end)
      {
        search_data = cookie_start;
        search_len = cookie_end - cookie_start;
      }
    }
  }
  else
  {
    search_data = data;
    search_len = data_len;
  }

  if (!search_data || search_len == 0)
    return 0;

  /* Perform content matching */
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
 * @brief Enhanced rule matching with all new features
 */
int
ips_match_rule_enhanced (vlib_buffer_t *b, ips_flow_t *flow, ips_rule_t *rule, u32 thread_index)
{
  if (!b || !flow || !rule)
    return 0;

  /* Check all new detection options */
  if (!check_tcp_flags (b, flow, &rule->options))
    return 0;

  if (!check_ttl (b, flow, &rule->options))
    return 0;

  if (!check_tos (b, flow, &rule->options))
    return 0;

  if (!check_fragbits (b, flow, &rule->options))
    return 0;

  if (!check_sequence_number (b, flow, &rule->options))
    return 0;

  if (!check_ack_number (b, flow, &rule->options))
    return 0;

  if (!check_icmp_type_code (b, flow, &rule->options))
    return 0;

  /* Enhanced HTTP content matching */
  if (rule->options.http_uri || rule->options.http_host ||
      rule->options.http_user_agent || rule->options.http_cookie)
  {
    if (!match_http_content (b, flow, rule))
      return 0;
  }

  /* Rule matched - update statistics */
  /* NOTE: Do NOT increment match_count here to avoid double counting.
   * The match_count will be incremented in ips_generate_detailed_log()
   * when the alert/log is actually generated. */
  rule->last_match_time = vlib_time_now (vlib_get_main ());

  return 1;
}
