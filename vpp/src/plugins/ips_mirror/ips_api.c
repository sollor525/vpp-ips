/*
 * ips_api.c - VPP IPS Plugin API
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

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vpp/app/version.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include "ips.h"

/* define message IDs */
#include <vnet/format_fns.h>
#include <ips/ips.api_enum.h>
#include <ips/ips.api_types.h>

/**
 * Base message ID for the plugin
 */
static u32 ips_base_msg_id;
#define REPLY_MSG_ID_BASE ips_base_msg_id

#include <vlibapi/api_helper_macros.h>

/**
 * @brief Enable/disable IPS on interface
 */
static void
vl_api_ips_interface_enable_disable_t_handler (
  vl_api_ips_interface_enable_disable_t *mp)
{
  vl_api_ips_interface_enable_disable_reply_t *rmp;
  int rv;

  VALIDATE_SW_IF_INDEX (mp);

  rv = ips_interface_enable_disable (ntohl (mp->sw_if_index),
				     mp->enable_disable);

BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_IPS_INTERFACE_ENABLE_DISABLE_REPLY);
}

/**
 * @brief Add IPS rule
 */
static void
vl_api_ips_rule_add_t_handler (vl_api_ips_rule_add_t *mp)
{
  vl_api_ips_rule_add_reply_t *rmp;
  ips_rule_t rule;
  int rv;

  clib_memset (&rule, 0, sizeof (rule));

  rule.rule_id = ntohl (mp->rule_id);
  rule.gid = ntohl (mp->gid);
  rule.sid = ntohl (mp->sid);
  rule.priority = ntohl (mp->priority);
  rule.action = mp->action;
  rule.protocol = mp->protocol;
  rule.direction = mp->direction;
  rule.flags = ntohl (mp->flags);

  /* Copy addresses */
  if (mp->is_ipv6)
    {
      clib_memcpy (&rule.src_addr.ip6, mp->src_address, 16);
      clib_memcpy (&rule.dst_addr.ip6, mp->dst_address, 16);
    }
  else
    {
      clib_memcpy (&rule.src_addr.ip4, mp->src_address, 4);
      clib_memcpy (&rule.dst_addr.ip4, mp->dst_address, 4);
    }

  rule.src_addr_mask = mp->src_prefix_len;
  rule.dst_addr_mask = mp->dst_prefix_len;
  rule.src_port_min = ntohs (mp->src_port_min);
  rule.src_port_max = ntohs (mp->src_port_max);
  rule.dst_port_min = ntohs (mp->dst_port_min);
  rule.dst_port_max = ntohs (mp->dst_port_max);

  /* Copy strings (fixed size arrays) */
  if (mp->msg[0])
    rule.msg = format (0, "%s%c", mp->msg, 0);
  if (mp->reference[0])
    rule.reference = format (0, "%s%c", mp->reference, 0);
  if (mp->classtype[0])
    rule.classtype = format (0, "%s%c", mp->classtype, 0);

  /* Copy content */
  if (mp->content_len > 0)
    {
      vec_validate (rule.content, mp->content_len - 1);
      clib_memcpy (rule.content, mp->content, mp->content_len);
      rule.content_len = mp->content_len;
    }

  rv = ips_rule_add (&rule);

  REPLY_MACRO (VL_API_IPS_RULE_ADD_REPLY);
}

/**
 * @brief Delete IPS rule
 */
static void
vl_api_ips_rule_delete_t_handler (vl_api_ips_rule_delete_t *mp)
{
  vl_api_ips_rule_delete_reply_t *rmp;
  int rv;

  rv = ips_rule_delete (ntohl (mp->rule_id));

  REPLY_MACRO (VL_API_IPS_RULE_DELETE_REPLY);
}

/**
 * @brief Compile IPS rules
 */
static void
vl_api_ips_rules_compile_t_handler (vl_api_ips_rules_compile_t *mp)
{
  vl_api_ips_rules_compile_reply_t *rmp;
  int rv;

  rv = ips_rules_compile ();

  REPLY_MACRO (VL_API_IPS_RULES_COMPILE_REPLY);
}

/**
 * @brief Get IPS statistics
 */
static void
vl_api_ips_stats_get_t_handler (vl_api_ips_stats_get_t *mp)
{
  vl_api_ips_stats_get_reply_t *rmp;
  ips_main_t *im = &ips_main;
  int rv = 0;
  u64 total_packets = 0;
  u64 total_bytes = 0;
  u64 dropped_packets = 0;
  u64 alerted_packets = 0;

  /* Aggregate statistics from all threads */
  for (u32 i = 0; i < vec_len (im->per_thread_data); i++)
    {
      ips_per_thread_data_t *ptd = &im->per_thread_data[i];
      total_packets += ptd->total_packets;
      total_bytes += ptd->total_bytes;
      dropped_packets += ptd->dropped_packets;
      alerted_packets += ptd->alerted_packets;
    }

  REPLY_MACRO2 (VL_API_IPS_STATS_GET_REPLY, ({
		  rmp->total_packets = clib_host_to_net_u64 (total_packets);
		  rmp->total_bytes = clib_host_to_net_u64 (total_bytes);
		  rmp->dropped_packets =
		    clib_host_to_net_u64 (dropped_packets);
		  rmp->alerted_packets =
		    clib_host_to_net_u64 (alerted_packets);
		  rmp->rule_count = clib_host_to_net_u32 (im->rule_count);
		  rmp->enabled_interfaces =
		    clib_host_to_net_u32 (im->enabled_interface_count);
		}));
}

/* API definitions */
#include <ips/ips.api.c>

/**
 * @brief Plugin API initialization
 */
static clib_error_t *
ips_api_init (vlib_main_t *vm)
{
  ips_main_t *im = &ips_main;

  /* Ask for a correctly-sized block of API message decode slots */
  im->msg_id_base = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (ips_api_init);
