/*
 * ips.c - VPP IPS Plugin Main Implementation
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
#include <vnet/feature/feature.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/error.h>
#include <sys/stat.h>

#include "ips.h"
#include "ips_logging.h"
#include "session/ips_session.h"
#include "session/ips_session_timer.h"
#include "block/ips_block.h"

/* Global log level - default to WARNING level */
ips_log_level_t ips_global_log_level = IPS_LOG_LEVEL_WARNING;

/* Module headers */
#include "detection/ips_detection_module.h"
#include "rules/ips_rules_module.h"

/* Global IPS main structure */
ips_main_t ips_main;

/* Plugin registration */
VLIB_PLUGIN_REGISTER () = {
  .version = IPS_PLUGIN_BUILD_VER,
  .description = "VPP Intrusion Prevention System",
};

/**
 * @brief IPS plugin initialization
 */
clib_error_t *
ips_init (vlib_main_t *vm)
{
  ips_main_t *im = &ips_main;
  clib_error_t *error = 0;

  im->vlib_main = vm;
  im->vnet_main = vnet_get_main ();

  /* Initialize per-thread data */
  vec_validate_aligned (im->per_thread_data, vlib_num_workers (),
			CLIB_CACHE_LINE_BYTES);

  /* Initialize simple counters for vlib_increment_simple_counter */
  u32 num_threads = vlib_num_workers () + 1;  /* Include main thread */
  vec_validate_aligned (im->counters, num_threads,
                       CLIB_CACHE_LINE_BYTES);
  for (u32 i = 0; i < num_threads; i++)
  {
    vec_validate_aligned (im->counters[i].counters, IPS_COUNTER_MAX,
                         CLIB_CACHE_LINE_BYTES);
  }

  /* Initialize rule storage */
  im->rules = 0;
  im->rule_index_by_id = hash_create (0, sizeof (uword));
  im->rule_count = 0;
  im->enabled_interface_count = 0;

  /* Initialize configuration with defaults */
  im->session_timeout = 300;    /* 5 minutes */
  im->cleanup_interval = 60;    /* 1 minute */
  im->promiscuous_mode = 1;     /* Enabled by default for mirror traffic */
  im->rules_compiled = 0;
  im->rules_dirty = 0;

  /* Initialize logging system */
  error = ips_logging_init (vm);
  if (error)
    return error;

  /* Initialize detection engine module */
  error = ips_detection_module_init (im);
  if (error)
    return error;

  /* Initialize session manager (includes timer manager) */
  error = ips_session_manager_init (vm);
  if (error)
    return error;

  /* Initialize protocol detection module */
  extern clib_error_t *ips_protocol_detection_init(void);
  error = ips_protocol_detection_init();
  if (error)
    return error;

  /* Initialize blocking module */
  error = ips_block_init (vm);
  if (error)
    return error;

  /* Initialize rules module */
  error = ips_rules_module_init ();
  if (error)
    return error;

  /* Enable session timer process node
   * This process periodically wakes up worker threads to process their timers.
   * It does NOT access session data directly - it only sends interrupt signals
   * to worker threads, which then process their own timers in their own context.
   * This ensures thread safety while allowing timers to expire even without traffic.
   */
  vlib_node_set_state (vm, ips_session_timer_process_node.index,
                       VLIB_NODE_STATE_POLLING);

  return 0;
}

VLIB_INIT_FUNCTION (ips_init);

/**
 * @brief Apply ACLs to all enabled IPS interfaces
 */
void
ips_apply_acls_to_all_interfaces(void)
{
  ips_main_t *im = &ips_main;
  u32 sw_if_index;
  
  extern int ips_acl_apply_to_interface(u32 sw_if_index);
  
  vec_foreach_index(sw_if_index, im->interface_enabled)
  {
      if (im->interface_enabled[sw_if_index])
      {
          ips_acl_apply_to_interface(sw_if_index);
      }
  }
}

/**
 * @brief Enable/disable IPS on an interface
 */
int
ips_interface_enable_disable (const ips_interface_enable_disable_args_t *args)
{
  ips_main_t *im = &ips_main;
  vnet_main_t *vnm = im->vnet_main;
  vnet_sw_interface_t *sw;
  int rv = 0;

  if (!args)
    return VNET_API_ERROR_INVALID_VALUE;

  u32 sw_if_index = args->sw_if_index;
  int enable_disable = args->enable_disable;

  /* Validate interface */
  if (pool_is_free_index (vnm->interface_main.sw_interfaces, sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  sw = vnet_get_sw_interface (vnm, sw_if_index);

  /* Extend interface array if needed */
  vec_validate_init_empty (im->interface_enabled, sw_if_index, 0);

  if (enable_disable)
    {
      if (!im->interface_enabled[sw_if_index])
	{
	  /* Enable IPS on this interface */
	  im->interface_enabled[sw_if_index] = 1;
	  im->enabled_interface_count++;

	  /* Enable promiscuous mode if configured */
	  if (im->promiscuous_mode)
	    {
	      ethernet_interface_t *ei;
	      ei = ethernet_get_interface (&ethernet_main, sw->hw_if_index);
	      if (ei)
		{
		  ethernet_set_flags (vnm, sw->hw_if_index,
				      ETHERNET_INTERFACE_FLAG_ACCEPT_ALL);
		}
	    }

	  /* Enable feature arc */
	  vnet_feature_enable_disable ("ip4-unicast", "ips-input-ip4",
				       sw_if_index, 1, 0, 0);
	  vnet_feature_enable_disable ("ip6-unicast", "ips-input-ip6",
				       sw_if_index, 1, 0, 0);

	  /* Apply all ACLs to this interface
	   * This ensures ACL rules take effect when interface is enabled
	   */
	  extern int ips_acl_apply_to_interface(u32 sw_if_index);
	  ips_acl_apply_to_interface(sw_if_index);

	  IPS_INFO ("IPS enabled on interface %u", sw_if_index);
	}
    }
  else
    {
      if (im->interface_enabled[sw_if_index])
	{
	  /* Disable IPS on this interface */
	  im->interface_enabled[sw_if_index] = 0;
	  im->enabled_interface_count--;

	  /* Disable feature arc */
	  vnet_feature_enable_disable ("ip4-unicast", "ips-input-ip4",
				       sw_if_index, 0, 0, 0);
	  vnet_feature_enable_disable ("ip6-unicast", "ips-input-ip6",
				       sw_if_index, 0, 0, 0);

	  IPS_INFO ("IPS disabled on interface %u", sw_if_index);
	}
    }

  return rv;
}

/**
 * @brief Cleanup expired flows
 */
static void
ips_cleanup_expired_flows (ips_per_thread_data_t *ptd)
{
  ips_main_t *im = &ips_main;
  f64 now = vlib_time_now (im->vlib_main);
  f64 timeout = (f64) im->session_timeout;
  ips_flow_t *flow;
  u32 *expired_flows = 0;
  u32 i;

  /* Find expired flows */
  pool_foreach (flow, ptd->flows)
    {
      if ((now - flow->last_packet_time) > timeout)
	{
	  vec_add1 (expired_flows, flow - ptd->flows);
	}
    }

  /* Delete expired flows */
  for (i = 0; i < vec_len (expired_flows); i++)
    {
      flow = pool_elt_at_index (ptd->flows, expired_flows[i]);

      /* Remove from hash table */
      hash_unset (ptd->flow_hash, flow->flow_hash);

      /* Return to free list */
      pool_put (ptd->flows, flow);
    }

  vec_free (expired_flows);
  ptd->last_cleanup_time = now;
}

/**
 * @brief Periodic process for IPS maintenance
 */
static uword
ips_process (vlib_main_t *vm, vlib_node_runtime_t * __clib_unused rt, vlib_frame_t * __clib_unused f)
{
  ips_main_t *im = &ips_main;
  f64 timeout = 10.0;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, timeout);
      vlib_process_get_events (vm, NULL);

      /* Cleanup expired flows on all threads */
      for (u32 i = 0; i < vec_len (im->per_thread_data); i++)
	{
	  ips_per_thread_data_t *ptd = &im->per_thread_data[i];
	  f64 now = vlib_time_now (vm);

	  if ((now - ptd->last_cleanup_time) > im->cleanup_interval)
	    {
	      ips_cleanup_expired_flows (ptd);
	    }
	}

      /* Recompile rules if needed */
      if (im->rules_dirty && !im->rules_compiled)
	{
	  ips_rules_compile ();
	}
    }

  return 0;
}

VLIB_REGISTER_NODE (ips_process_node) = {
  .function = ips_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "ips-process",
  .process_log2_n_stack_bytes = 17,
};

/**
 * @brief Format flow key for display
 */
u8 *
format_ips_flow_key (u8 *s, va_list *args)
{
  ips_flow_key_t *key = va_arg (*args, ips_flow_key_t *);

  if (key->is_ip6)
    {
      s = format (s, "%U:%u -> %U:%u proto %u",
		  format_ip6_address, &key->src_ip6, key->src_port,
		  format_ip6_address, &key->dst_ip6, key->dst_port,
		  key->protocol);
    }
  else
    {
      s = format (s, "%U:%u -> %U:%u proto %u",
		  format_ip4_address, &key->src_ip4, key->src_port,
		  format_ip4_address, &key->dst_ip4, key->dst_port,
		  key->protocol);
    }

  return s;
}

/**
 * @brief Format rule for display
 */
u8 *
format_ips_rule (u8 *s, va_list *args)
{
  ips_rule_t *rule = va_arg (*args, ips_rule_t *);

  s = format (s, "Rule %u: %s %s", rule->rule_id,
	      rule->action == IPS_ACTION_DROP	 ? "DROP" :
	      rule->action == IPS_ACTION_ALERT	 ? "ALERT" :
	      rule->action == IPS_ACTION_REJECT	 ? "REJECT" :
	      rule->action == IPS_ACTION_LOG	 ? "LOG" :
				       "PASS",
	      rule->msg ? (char *) rule->msg : "No message");

  return s;
}
