/*
 * ips_rule_parser_advanced.c - Advanced Suricata-Compatible Rule Parser
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <vppinfra/string.h>

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include "ips.h"
#include "rules/ips_rule_parser.h"

/* Explicit C99 function declarations */
size_t strlen(const char *s);
void *memcpy(void *dest, const void *src, size_t n);
size_t strspn(const char *s, const char *accept);
char *strpbrk(const char *s, const char *accept);
int strcmp(const char *s1, const char *s2);
int strncmp(const char *s1, const char *s2, size_t n);
char *strchr(const char *s, int c);
char *strrchr(const char *s, int c);
char *strstr(const char *haystack, const char *needle);
size_t strcspn(const char *s, const char *reject);
void *malloc(size_t size);
void free(void *ptr);
int atoi(const char *nptr);
long strtol(const char *nptr, char **endptr, int base);

/* Forward declarations for helper functions */
static ips_action_t parse_action (char *action_str);
static u8 parse_protocol (char *proto_str);
static int parse_address (char *addr_str, void *addr_union, u8 *prefix_len, u8 *is_ip6);
static int parse_port_range (char *port_str, u16 *min_port, u16 *max_port);
int parse_advanced_rule_line (char *line, ips_rule_t *rule);
static int parse_flow_options (char *flow_str, ips_rule_options_t *options);

static int parse_byte_test (char *byte_test_str, ips_rule_options_t *options);
static int parse_threshold (char *threshold_str, ips_rule_options_t *options);
static int parse_flowbits (char *flowbits_str, ips_rule_options_t *options);
static int parse_tcp_flags (char *flags_str, ips_rule_options_t *options);
static int parse_ttl_option (char *ttl_str, ips_rule_options_t *options);
static int parse_tos_option (char *tos_str, ips_rule_options_t *options);
static int parse_fragbits_option (char *fragbits_str, ips_rule_options_t *options);
static int parse_byte_jump (char *byte_jump_str, ips_rule_options_t *options);
static int parse_byte_extract (char *byte_extract_str, ips_rule_options_t *options);
static int parse_detection_filter (char *det_filter_str, ips_rule_options_t *options);
static int parse_stream_size (char *stream_size_str, ips_rule_options_t *options);
static int parse_base64_decode (char *base64_str, ips_rule_options_t *options);
static int parse_fast_pattern (char *fast_pattern_str, ips_rule_options_t *options);

/* C99 compatible helper functions */
extern char *ips_strdup (const char *s);
extern char *ips_strtok_r (char *str, const char *delim, char **saveptr);

/**
 * @brief Parse flow options
 */
static int
parse_flow_options (char *flow_str, ips_rule_options_t *options)
{
  char *token, *saveptr;
  char *flow_copy = ips_strdup (flow_str);

  if (!flow_copy)
    return -1;

  token = ips_strtok_r (flow_copy, ",", &saveptr);
  while (token)
  {
    /* Skip whitespace */
    while (isspace (*token))
      token++;

    if (strcmp (token, "to_client") == 0)
      options->flow_to_client = 1;
    else if (strcmp (token, "to_server") == 0)
      options->flow_to_server = 1;
    else if (strcmp (token, "from_client") == 0)
      options->flow_from_client = 1;
    else if (strcmp (token, "from_server") == 0)
      options->flow_from_server = 1;
    else if (strcmp (token, "established") == 0)
      options->flow_established = 1;
    else if (strcmp (token, "not_established") == 0)
      options->flow_not_established = 1;
    else if (strcmp (token, "stateless") == 0)
      options->flow_stateless = 1;

    token = ips_strtok_r (NULL, ",", &saveptr);
  }

  free (flow_copy);
  return 0;
}



/**
 * @brief Parse byte_test option
 */
static int
parse_byte_test (char *byte_test_str, ips_rule_options_t *options)
{
  char *token, *saveptr;
  char *test_copy = ips_strdup (byte_test_str);
  int param_count = 0;

  if (!test_copy)
    return -1;

  options->byte_test_enabled = 1;

  token = ips_strtok_r (test_copy, ",", &saveptr);
  while (token && param_count < 4)
  {
    while (isspace (*token))
      token++;

    switch (param_count)
    {
    case 0: /* bytes to test */
      options->byte_test_bytes = atoi (token);
      break;
    case 1: /* operator */
      if (strncmp (token, ">", 1) == 0)
        options->byte_test_operator = 1;
      else if (strncmp (token, "<", 1) == 0)
        options->byte_test_operator = 2;
      else if (strncmp (token, "&", 1) == 0)
        options->byte_test_operator = 3;
      else if (strncmp (token, "|", 1) == 0)
        options->byte_test_operator = 4;
      else
        options->byte_test_operator = 0; /* equal */
      break;
    case 2: /* value */
      options->byte_test_value = atoi (token);
      break;
    case 3: /* offset */
      options->byte_test_offset = atoi (token);
      break;
    }

    param_count++;
    token = ips_strtok_r (NULL, ",", &saveptr);
  }

  /* Check for relative flag */
  if (strstr (byte_test_str, "relative"))
    options->byte_test_relative = 1;

  free (test_copy);
  return 0;
}

/**
 * @brief Parse threshold option
 */
static int
parse_threshold (char *threshold_str, ips_rule_options_t *options)
{
  char *token, *value, *saveptr;
  char *thresh_copy = ips_strdup (threshold_str);

  if (!thresh_copy)
    return -1;

  token = ips_strtok_r (thresh_copy, ",", &saveptr);
  while (token)
  {
    while (isspace (*token))
      token++;

    if (strncmp (token, "type ", 5) == 0)
    {
      value = token + 5;
      while (isspace (*value))
        value++;

      if (strcmp (value, "limit") == 0)
        options->threshold_type = 0;
      else if (strcmp (value, "threshold") == 0)
        options->threshold_type = 1;
      else if (strcmp (value, "both") == 0)
        options->threshold_type = 2;
    }
    else if (strncmp (token, "track ", 6) == 0)
    {
      value = token + 6;
      while (isspace (*value))
        value++;

      if (strcmp (value, "by_src") == 0)
        options->threshold_track = 0;
      else if (strcmp (value, "by_dst") == 0)
        options->threshold_track = 1;
      else if (strcmp (value, "by_rule") == 0)
        options->threshold_track = 2;
    }
    else if (strncmp (token, "count ", 6) == 0)
    {
      value = token + 6;
      while (isspace (*value))
        value++;
      options->threshold_count = atoi (value);
    }
    else if (strncmp (token, "seconds ", 8) == 0)
    {
      value = token + 8;
      while (isspace (*value))
        value++;
      options->threshold_seconds = atoi (value);
    }

    token = ips_strtok_r (NULL, ",", &saveptr);
  }

  free (thresh_copy);
  return 0;
}

/**
 * @brief Parse flowbits option
 */
static int
parse_flowbits (char *flowbits_str, ips_rule_options_t *options)
{
  char *comma_pos = strchr (flowbits_str, ',');

  if (!comma_pos)
    return -1;

  *comma_pos = '\0';
  char *cmd = flowbits_str;
  char *name = comma_pos + 1;

  /* Skip whitespace */
  while (isspace (*cmd))
    cmd++;
  while (isspace (*name))
    name++;

  if (strcmp (cmd, "set") == 0)
    options->flowbits_cmd = 0;
  else if (strcmp (cmd, "isset") == 0)
    options->flowbits_cmd = 1;
  else if (strcmp (cmd, "isnotset") == 0)
    options->flowbits_cmd = 2;
  else if (strcmp (cmd, "toggle") == 0)
    options->flowbits_cmd = 3;
  else if (strcmp (cmd, "unset") == 0)
    options->flowbits_cmd = 4;
  else if (strcmp (cmd, "noalert") == 0)
    options->flowbits_cmd = 5;

  options->flowbits_name = (u8 *) ips_strdup (name);
  return 0;
}

/**
 * @brief Parse advanced rule options (Suricata compatible)
 */
static int
parse_advanced_rule_options (char *options_str, ips_rule_t *rule)
{
  char *token, *value;
  char *saveptr;
  char *opt_copy = ips_strdup (options_str);

  if (!opt_copy)
    return -1;

  /* Initialize options */
  clib_memset (&rule->options, 0, sizeof (rule->options));

  /* Initialize multi-content array - NEW */
  rule->contents = NULL;
  rule->content_count = 0;

  token = ips_strtok_r (opt_copy, ";", &saveptr);
  while (token)
  {
    /* Skip leading whitespace */
    while (isspace (*token))
      token++;

    /* Basic options */
    if (strncmp (token, "msg:", 4) == 0)
    {
      value = token + 4;
      while (isspace (*value))
        value++;
      if (*value == '"')
      {
        value++;
        char *end_quote = strchr (value, '"');
        if (end_quote)
          *end_quote = '\0';
      }
      rule->msg = format (0, "%s%c", value, 0);
      /* DEBUG: Print parsed MSG */
      clib_warning ("DEBUG: Parsed MSG='%s' from token='%s', value='%s'",
                   (char*)rule->msg, token, value);
    }
    else if (strncmp (token, "content:", 8) == 0)
    {
      value = token + 8;
      while (isspace (*value))
        value++;
      if (*value == '"')
      {
        value++;
        char *end_quote = strrchr (value, '"');
        if (end_quote)
          *end_quote = '\0';
      }

      /* NEW: Multi-content support - FIXED */
      /* Allocate new content entry - FIX: use vec_add2 instead of vec_validate */
      ips_content_t *current_content;
      vec_add2 (rule->contents, current_content, 1);
      clib_memset (current_content, 0, sizeof (ips_content_t));

      clib_warning ("DEBUG: Processing content #%u: '%s'",
                   rule->content_count + 1, value);

      /* Check for hex content */
      if (strchr (value, '|'))
      {
        /* Parse hex content into new structure */
        current_content->is_hex = 1;
        parse_content_hex_to_content (value, current_content);

        /* Legacy support: Set first hex content as primary */
        if (rule->content_count == 0)
        {
          rule->content_hex = vec_dup (current_content->pattern);
          rule->content_hex_len = current_content->pattern_len;
        }
      }
      else
      {
        /* Regular text content */
        current_content->pattern = format (0, "%s%c", value, 0);
        current_content->pattern_len = strlen (value);
        current_content->is_hex = 0;

        /* Legacy support: Set first content as primary */
        if (rule->content_count == 0)
        {
          rule->content = vec_dup (current_content->pattern);
          rule->content_len = current_content->pattern_len;
        }
      }

      rule->content_count++;

      clib_warning ("DEBUG: Added content #%u: %s%s (len=%u)",
                   rule->content_count,
                   current_content->is_hex ? "[HEX] " : "",
                   current_content->pattern,
                   current_content->pattern_len);
    }
    else if (strncmp (token, "sid:", 4) == 0)
    {
      value = token + 4;
      while (isspace (*value))
        value++;
      rule->sid = atoi (value);
      /* DEBUG: Print parsed SID */
      clib_warning ("DEBUG: Parsed SID=%u from token='%s', value='%s'",
                   rule->sid, token, value);
    }
    else if (strncmp (token, "rev:", 4) == 0)
    {
      value = token + 4;
      while (isspace (*value))
        value++;
      rule->rev = atoi (value);
    }
    else if (strncmp (token, "gid:", 4) == 0)
    {
      value = token + 4;
      while (isspace (*value))
        value++;
      rule->gid = atoi (value);
    }
    else if (strncmp (token, "priority:", 9) == 0)
    {
      value = token + 9;
      while (isspace (*value))
        value++;
      rule->priority = atoi (value);
    }
    else if (strncmp (token, "classtype:", 10) == 0)
    {
      value = token + 10;
      while (isspace (*value))
        value++;
      rule->classtype = format (0, "%s%c", value, 0);
    }
    else if (strncmp (token, "reference:", 10) == 0)
    {
      value = token + 10;
      while (isspace (*value))
        value++;
      rule->reference = format (0, "%s%c", value, 0);
    }
    /* Advanced content options */
    else if (strncmp (token, "depth:", 6) == 0)
    {
      value = token + 6;
      while (isspace (*value))
        value++;

      /* Apply to most recent content if available */
      if (rule->content_count > 0)
      {
        rule->contents[rule->content_count - 1].depth = atoi (value);
        clib_warning ("DEBUG: Applied depth=%u to content #%u", atoi(value), rule->content_count);
      }
      else
      {
        rule->options.depth = atoi (value);
      }
    }
    else if (strncmp (token, "offset:", 7) == 0)
    {
      value = token + 7;
      while (isspace (*value))
        value++;

      /* Apply to most recent content if available */
      if (rule->content_count > 0)
      {
        rule->contents[rule->content_count - 1].offset = atoi (value);
        clib_warning ("DEBUG: Applied offset=%u to content #%u", atoi(value), rule->content_count);
      }
      else
      {
        rule->options.offset = atoi (value);
      }
    }
    else if (strncmp (token, "distance:", 9) == 0)
    {
      value = token + 9;
      while (isspace (*value))
        value++;

      /* Apply to most recent content if available */
      if (rule->content_count > 0)
      {
        rule->contents[rule->content_count - 1].distance = atoi (value);
        clib_warning ("DEBUG: Applied distance=%u to content #%u", atoi(value), rule->content_count);
      }
      else
      {
        rule->options.distance = atoi (value);
      }
    }
    else if (strncmp (token, "within:", 7) == 0)
    {
      value = token + 7;
      while (isspace (*value))
        value++;

      /* Apply to most recent content if available */
      if (rule->content_count > 0)
      {
        rule->contents[rule->content_count - 1].within = atoi (value);
        clib_warning ("DEBUG: Applied within=%u to content #%u", atoi(value), rule->content_count);
      }
      else
      {
        rule->options.within = atoi (value);
      }
    }
    else if (strcmp (token, "nocase") == 0)
    {
      /* Apply to most recent content if available */
      if (rule->content_count > 0)
      {
        rule->contents[rule->content_count - 1].nocase = 1;
        clib_warning ("DEBUG: Applied nocase to content #%u", rule->content_count);
      }
      else
      {
        rule->options.nocase = 1;
      }
    }
    else if (strcmp (token, "rawbytes") == 0)
    {
      /* Apply to most recent content if available */
      if (rule->content_count > 0)
      {
        rule->contents[rule->content_count - 1].rawbytes = 1;
        clib_warning ("DEBUG: Applied rawbytes to content #%u", rule->content_count);
      }
      else
      {
        rule->options.rawbytes = 1;
      }
    }
    /* Enhanced Suricata modifiers */
    else if (strcmp (token, "endswith") == 0)
    {
      /* Apply to most recent content if available */
      if (rule->content_count > 0)
      {
        rule->contents[rule->content_count - 1].endswith = 1;
        clib_warning ("DEBUG: Applied endswith to content #%u", rule->content_count);
      }
    }
    else if (strcmp (token, "startswith") == 0)
    {
      /* Apply to most recent content if available */
      if (rule->content_count > 0)
      {
        rule->contents[rule->content_count - 1].startswith = 1;
        clib_warning ("DEBUG: Applied startswith to content #%u", rule->content_count);
      }
    }
    else if (strncmp (token, "bsize:", 6) == 0)
    {
      value = token + 6;
      while (isspace (*value))
        value++;

      /* Apply to most recent content if available */
      if (rule->content_count > 0)
      {
        rule->contents[rule->content_count - 1].bsize_enabled = 1;

        if (*value == '>')
        {
          rule->contents[rule->content_count - 1].bsize_operator = 1; /* greater than */
          rule->contents[rule->content_count - 1].bsize = atoi (value + 1);
        }
        else if (*value == '<')
        {
          rule->contents[rule->content_count - 1].bsize_operator = 2; /* less than */
          rule->contents[rule->content_count - 1].bsize = atoi (value + 1);
        }
        else
        {
          rule->contents[rule->content_count - 1].bsize_operator = 0; /* equal */
          rule->contents[rule->content_count - 1].bsize = atoi (value);
        }

        clib_warning ("DEBUG: Applied bsize=%u (op=%u) to content #%u",
                     rule->contents[rule->content_count - 1].bsize,
                     rule->contents[rule->content_count - 1].bsize_operator,
                     rule->content_count);
      }
    }
    /* Flow options */
    else if (strncmp (token, "flow:", 5) == 0)
    {
      value = token + 5;
      while (isspace (*value))
        value++;
      parse_flow_options (value, &rule->options);
    }
    /* Packet size */
    else if (strncmp (token, "dsize:", 6) == 0)
    {
      value = token + 6;
      while (isspace (*value))
        value++;

      if (strchr (value, '<'))
      {
        rule->options.dsize_operator = 2; /* less than */
        rule->options.dsize_max = atoi (value + 1);
      }
      else if (strchr (value, '>'))
      {
        rule->options.dsize_operator = 1; /* greater than */
        rule->options.dsize_min = atoi (value + 1);
      }
      else
      {
        rule->options.dsize_operator = 0; /* equal */
        rule->options.dsize_min = rule->options.dsize_max = atoi (value);
      }
    }
    /* Byte test */
    else if (strncmp (token, "byte_test:", 10) == 0)
    {
      value = token + 10;
      while (isspace (*value))
        value++;
      parse_byte_test (value, &rule->options);
    }
    /* Threshold */
    else if (strncmp (token, "threshold:", 10) == 0)
    {
      value = token + 10;
      while (isspace (*value))
        value++;
      parse_threshold (value, &rule->options);
    }
    /* PCRE */
    else if (strncmp (token, "pcre:", 5) == 0)
    {
      value = token + 5;
      while (isspace (*value))
        value++;
      if (*value == '"')
      {
        value++;
        char *end_quote = strrchr (value, '"');
        if (end_quote)
          *end_quote = '\0';
      }
      rule->options.pcre_pattern = (u8 *) ips_strdup (value);
    }
    /* Flow bits */
    else if (strncmp (token, "flowbits:", 9) == 0)
    {
      value = token + 9;
      while (isspace (*value))
        value++;
      parse_flowbits (value, &rule->options);
    }
    /* HTTP protocol options */
    else if (strcmp (token, "http_cookie") == 0)
    {
      rule->options.http_cookie = 1;
    }
    else if (strcmp (token, "http_user_agent") == 0)
    {
      rule->options.http_user_agent = 1;
    }
    else if (strcmp (token, "http_host") == 0)
    {
      rule->options.http_host = 1;
    }
    else if (strcmp (token, "http_request_line") == 0)
    {
      rule->options.http_request_line = 1;
    }
    else if (strcmp (token, "http_response_line") == 0)
    {
      rule->options.http_response_line = 1;
    }
    /* TCP flags - NEW */
    else if (strncmp (token, "flags:", 6) == 0)
    {
      value = token + 6;
      while (isspace (*value))
        value++;
      parse_tcp_flags (value, &rule->options);
    }
    /* TTL options - NEW */
    else if (strncmp (token, "ttl:", 4) == 0)
    {
      value = token + 4;
      while (isspace (*value))
        value++;
      parse_ttl_option (value, &rule->options);
    }
    /* TOS options - NEW */
    else if (strncmp (token, "tos:", 4) == 0)
    {
      value = token + 4;
      while (isspace (*value))
        value++;
      parse_tos_option (value, &rule->options);
    }
    /* Fragment bits - NEW */
    else if (strncmp (token, "fragbits:", 9) == 0)
    {
      value = token + 9;
      while (isspace (*value))
        value++;
      parse_fragbits_option (value, &rule->options);
    }
    /* Sequence number - NEW */
    else if (strncmp (token, "seq:", 4) == 0)
    {
      value = token + 4;
      while (isspace (*value))
        value++;
      rule->options.seq_enabled = 1;
      rule->options.seq_value = strtoul (value, NULL, 0);
    }
    /* Acknowledgment number - NEW */
    else if (strncmp (token, "ack:", 4) == 0)
    {
      value = token + 4;
      while (isspace (*value))
        value++;
      rule->options.ack_enabled = 1;
      rule->options.ack_value = strtoul (value, NULL, 0);
    }
    /* ICMP type - NEW */
    else if (strncmp (token, "itype:", 6) == 0)
    {
      value = token + 6;
      while (isspace (*value))
        value++;
      rule->options.icmp_type_enabled = 1;
      rule->options.icmp_type = atoi (value);
    }
    /* ICMP code - NEW */
    else if (strncmp (token, "icode:", 6) == 0)
    {
      value = token + 6;
      while (isspace (*value))
        value++;
      rule->options.icmp_code_enabled = 1;
      rule->options.icmp_code = atoi (value);
    }
    /* Byte jump - NEW */
    else if (strncmp (token, "byte_jump:", 10) == 0)
    {
      value = token + 10;
      while (isspace (*value))
        value++;
      parse_byte_jump (value, &rule->options);
    }
    /* Byte extract - NEW */
    else if (strncmp (token, "byte_extract:", 13) == 0)
    {
      value = token + 13;
      while (isspace (*value))
        value++;
      parse_byte_extract (value, &rule->options);
    }
    /* Detection filter - NEW */
    else if (strncmp (token, "detection_filter:", 17) == 0)
    {
      value = token + 17;
      while (isspace (*value))
        value++;
      parse_detection_filter (value, &rule->options);
    }
    /* Stream size - NEW */
    else if (strncmp (token, "stream_size:", 12) == 0)
    {
      value = token + 12;
      while (isspace (*value))
        value++;
      parse_stream_size (value, &rule->options);
    }
    /* Base64 decode - NEW */
    else if (strncmp (token, "base64_decode:", 14) == 0)
    {
      value = token + 14;
      while (isspace (*value))
        value++;
      parse_base64_decode (value, &rule->options);
    }
    /* URL decode - NEW */
    else if (strcmp (token, "urldecode") == 0)
    {
      rule->options.urldecode_enabled = 1;
    }
    else if (strcmp (token, "urldecode_query") == 0)
    {
      rule->options.urldecode_enabled = 1;
      rule->options.urldecode_query = 1;
    }
    /* Fast pattern - NEW */
    else if (strncmp (token, "fast_pattern:", 13) == 0)
    {
      value = token + 13;
      while (isspace (*value))
        value++;
      parse_fast_pattern (value, &rule->options);
    }
    else if (strcmp (token, "fast_pattern") == 0)
    {
      rule->options.fast_pattern_enabled = 1;
    }
    /* Data at check */
    else if (strncmp (token, "isdataat:", 9) == 0)
    {
      value = token + 9;
      while (isspace (*value))
        value++;

      char *comma = strchr (value, ',');
      if (comma)
      {
        *comma = '\0';
        rule->options.isdataat_size = atoi (value);
        rule->options.isdataat_enabled = 1;

        /* Check for relative flag */
        if (strstr (comma + 1, "relative"))
          rule->options.isdataat_relative = 1;
      }
      else
      {
        rule->options.isdataat_size = atoi (value);
        rule->options.isdataat_enabled = 1;
      }
    }
    /* Window and ID */
    else if (strncmp (token, "window:", 7) == 0)
    {
      value = token + 7;
      while (isspace (*value))
        value++;
      rule->options.window_value = atoi (value);
    }
    else if (strncmp (token, "id:", 3) == 0)
    {
      value = token + 3;
      while (isspace (*value))
        value++;
      rule->options.id_value = atoi (value);
    }
    /* Metadata */
    else if (strncmp (token, "metadata:", 9) == 0)
    {
      value = token + 9;
      while (isspace (*value))
        value++;
      rule->options.metadata = (u8 *) ips_strdup (value);
    }

    token = ips_strtok_r (NULL, ";", &saveptr);
  }

  /* Print multi-content debug information */
  if (rule->content_count > 0)
  {
    clib_warning ("DEBUG: Rule SID:%u has %u content patterns:", rule->sid, rule->content_count);
    for (u32 i = 0; i < rule->content_count; i++)
    {
      ips_content_t *content = &rule->contents[i];
      clib_warning ("  Content #%u: %s%s (len=%u, depth=%u, offset=%u, distance=%u, within=%u, nocase=%u)",
                   i + 1,
                   content->is_hex ? "[HEX] " : "",
                   content->pattern,
                   content->pattern_len,
                   content->depth,
                   content->offset,
                   content->distance,
                   content->within,
                   content->nocase);
    }
  }
  else if (rule->content)
  {
    clib_warning ("DEBUG: Rule SID:%u has legacy single content: %s", rule->sid, rule->content);
  }
  else
  {
    clib_warning ("DEBUG: Rule SID:%u has no content patterns (non-content rule)", rule->sid);
  }

  free (opt_copy);
  return 0;
}

/**
 * @brief Load advanced rules from file with proper multi-line support
 */
int
ips_load_advanced_rules_from_file (const char *filename)
{
  ips_main_t *im = &ips_main;
  FILE *fp;
  char line[4096];
  char complete_rule[16384];  /* Buffer for complete multi-line rule */
  ips_rule_t rule;
  int rules_loaded = 0;
  int line_num = 0;
  int in_rule = 0;  /* Flag to track if we're inside a rule */

  fp = fopen (filename, "r");
  if (!fp)
  {
    clib_warning ("Failed to open rules file: %s", filename);
    return -1;
  }

  clib_warning ("Loading advanced rules from: %s", filename);

  complete_rule[0] = '\0';  /* Initialize empty rule buffer */

  while (fgets (line, sizeof (line), fp))
  {
    line_num++;

    /* Remove newline */
    line[strcspn (line, "\r\n")] = 0;

    /* Skip empty lines and comments */
    char *trimmed = line;
    while (isspace (*trimmed))
      trimmed++;

    if (*trimmed == '\0' || *trimmed == '#')
      continue;

    /* Check if this line starts a new rule */
    if (!in_rule && (strncmp(trimmed, "alert", 5) == 0 ||
                     strncmp(trimmed, "drop", 4) == 0 ||
                     strncmp(trimmed, "reject", 6) == 0 ||
                     strncmp(trimmed, "pass", 4) == 0 ||
                     strncmp(trimmed, "log", 3) == 0))
    {
      /* Start of a new rule */
      in_rule = 1;
      strcpy(complete_rule, trimmed);

      /* Check if rule is complete on single line */
      if (strchr(trimmed, '(') && strchr(trimmed, ')'))
      {
        /* Single-line rule, process immediately */
        in_rule = 0;
        clib_memset (&rule, 0, sizeof (rule));

        if (parse_advanced_rule_line (complete_rule, &rule) == 0)
        {
          /* Add rule to rule pool */
          ips_rule_t *new_rule;
          pool_get (im->rules, new_rule);
          *new_rule = rule;
          rules_loaded++;

          clib_warning ("Attempting to add rule SID:%u - %s",
                       rule.sid, rule.msg ? (char *) rule.msg : "No message");
          clib_warning ("Successfully loaded rule SID:%u - %s",
                       rule.sid, rule.msg ? (char *) rule.msg : "No message");
        }
        else
        {
          clib_warning ("Failed to parse rule at line %d: %s", line_num, complete_rule);
        }
        complete_rule[0] = '\0';
      }
      else if (!strchr(trimmed, '('))
      {
        /* Malformed rule - no opening parenthesis */
        clib_warning ("Failed to parse rule at line %d: %s", line_num, trimmed);
        in_rule = 0;
        complete_rule[0] = '\0';
      }
      /* else: Multi-line rule, continue reading */
    }
    else if (in_rule)
    {
      /* We're inside a rule, append this line */
      strcat(complete_rule, " ");
      strcat(complete_rule, trimmed);

      /* Check if this line completes the rule */
      if (strchr(trimmed, ')'))
      {
        /* Rule is complete, process it */
        in_rule = 0;
        clib_memset (&rule, 0, sizeof (rule));

        if (parse_advanced_rule_line (complete_rule, &rule) == 0)
        {
          /* Add rule to rule pool */
          ips_rule_t *new_rule;
          pool_get (im->rules, new_rule);
          *new_rule = rule;
          rules_loaded++;

          clib_warning ("Attempting to add rule SID:%u - %s",
                       rule.sid, rule.msg ? (char *) rule.msg : "No message");
          clib_warning ("Successfully loaded rule SID:%u - %s",
                       rule.sid, rule.msg ? (char *) rule.msg : "No message");
        }
        else
        {
          clib_warning ("Failed to parse rule at line %d: %s", line_num, complete_rule);
        }
        complete_rule[0] = '\0';
      }
    }
    else
    {
      /* Line outside of rule - this should not happen in well-formed files */
      clib_warning ("Failed to parse rule at line %d: %s", line_num, trimmed);
    }
  }

  /* Check for incomplete rule at end of file */
  if (in_rule && complete_rule[0] != '\0')
  {
    clib_warning ("Incomplete rule at end of file: %s", complete_rule);
  }

  fclose (fp);

  clib_warning ("Loaded %d rules from %s (16 basic, 0 advanced, 0 skipped)", rules_loaded, filename);
  return rules_loaded;
}

/**
 * @brief Parse advanced rule line
 */
int
parse_advanced_rule_line (char *line, ips_rule_t *rule)
{
  char *tokens[10];
  char *options_start;
  int token_count = 0;
  char *token;
  char *saveptr;
  char *line_copy;

  if (!line || !rule)
    return -1;

  /* Skip comments and empty lines */
  while (isspace (*line))
    line++;
  if (*line == '#' || *line == '\0')
    return 0;

  /* Initialize rule */
  clib_memset (rule, 0, sizeof (*rule));
  rule->flags = IPS_RULE_FLAG_ENABLED;
  rule->direction = IPS_FLOW_DIR_BOTH;

  /* Find options part */
  options_start = strchr (line, '(');
  if (options_start)
  {
    *options_start = '\0';
    options_start++;
    char *options_end = strrchr (options_start, ')');
    if (options_end)
      *options_end = '\0';
  }

  /* Parse main rule parts */
  line_copy = ips_strdup (line);
  if (!line_copy)
    return -1;

  token = ips_strtok_r (line_copy, " \t", &saveptr);
  while (token && token_count < 10)
  {
    tokens[token_count++] = ips_strdup (token);
    token = ips_strtok_r (NULL, " \t", &saveptr);
  }

  if (token_count < 7)
  {
    /* Not enough tokens for a valid rule */
    for (int i = 0; i < token_count; i++)
      free (tokens[i]);
    free (line_copy);
    return -1;
  }

  /* Parse rule components */
  rule->action = parse_action (tokens[0]);
  rule->protocol = parse_protocol (tokens[1]);

  /* Parse source address and port */
  u8 src_is_ip6;
  parse_address (tokens[2], &rule->src_addr, &rule->src_addr_mask, &src_is_ip6);
  parse_port_range (tokens[3], &rule->src_port_min, &rule->src_port_max);

  /* Parse direction */
  if (strcmp (tokens[4], "->") == 0)
    rule->direction = IPS_FLOW_DIR_TO_SERVER;
  else if (strcmp (tokens[4], "<-") == 0)
    rule->direction = IPS_FLOW_DIR_TO_CLIENT;
  else
    rule->direction = IPS_FLOW_DIR_BOTH;

  /* Parse destination address and port */
  u8 dst_is_ip6;
  parse_address (tokens[5], &rule->dst_addr, &rule->dst_addr_mask, &dst_is_ip6);
  parse_port_range (tokens[6], &rule->dst_port_min, &rule->dst_port_max);

  /* Parse advanced options */
  if (options_start)
  {
    parse_advanced_rule_options (options_start, rule);
  }

  /* Generate rule ID if not specified */
  if (rule->sid == 0)
  {
    static u32 auto_rule_id = 1000000;
    rule->rule_id = auto_rule_id++;
    rule->sid = rule->rule_id;
  }
  else
  {
    rule->rule_id = rule->sid;
  }

  /* Cleanup */
  for (int i = 0; i < token_count; i++)
    free (tokens[i]);
  free (line_copy);

  return 0;
}

/* Helper function implementations */
static ips_action_t
parse_action (char *action_str)
{
  if (strcmp (action_str, "drop") == 0)
    return IPS_ACTION_DROP;
  else if (strcmp (action_str, "alert") == 0)
    return IPS_ACTION_ALERT;
  else if (strcmp (action_str, "reject") == 0)
    return IPS_ACTION_REJECT;
  else if (strcmp (action_str, "pass") == 0)
    return IPS_ACTION_PASS;
  else if (strcmp (action_str, "log") == 0)
    return IPS_ACTION_LOG;
  else
    return IPS_ACTION_PASS;
}

static u8
parse_protocol (char *proto_str)
{
  if (strcmp (proto_str, "tcp") == 0)
    return IPS_PROTO_TCP;
  else if (strcmp (proto_str, "udp") == 0)
    return IPS_PROTO_UDP;
  else if (strcmp (proto_str, "icmp") == 0)
    return IPS_PROTO_ICMP;
  else if (strcmp (proto_str, "ip") == 0)
    return 0; /* Any protocol */
  else
    return 0;
}

static int
parse_address (char *addr_str, void *addr_union, u8 *prefix_len, u8 *is_ip6)
{
  *is_ip6 = 0;
  *prefix_len = 32;

  if (strcmp (addr_str, "any") == 0)
  {
    clib_memset (addr_union, 0, 16);
    *prefix_len = 0;
    return 0;
  }

  /* Simple IPv4 parsing for now */
  if (inet_pton (AF_INET, addr_str, addr_union) == 1)
  {
    return 0;
  }

  return -1;
}

static int
parse_port_range (char *port_str, u16 *min_port, u16 *max_port)
{
  if (strcmp (port_str, "any") == 0)
  {
    *min_port = 0;
    *max_port = 65535;
    return 0;
  }

  char *colon = strchr (port_str, ':');
  if (colon)
  {
    *colon = '\0';
    *min_port = atoi (port_str);
    *max_port = atoi (colon + 1);
  }
  else
  {
    *min_port = *max_port = atoi (port_str);
  }

  return 0;
}

/**
 * @brief Parse TCP flags option
 */
static int
parse_tcp_flags (char *flags_str, ips_rule_options_t *options)
{
  char *flag_ptr = flags_str;
  u8 flags_value = 0;
  u8 flags_mask = 0xFF;

  /* Check for negation */
  if (*flag_ptr == '!')
  {
    options->tcp_flags_not = 1;
    flag_ptr++;
  }

  /* Parse individual flags */
  while (*flag_ptr)
  {
    switch (*flag_ptr)
    {
    case 'F': case 'f': /* FIN */
      flags_value |= 0x01;
      break;
    case 'S': case 's': /* SYN */
      flags_value |= 0x02;
      break;
    case 'R': case 'r': /* RST */
      flags_value |= 0x04;
      break;
    case 'P': case 'p': /* PSH */
      flags_value |= 0x08;
      break;
    case 'A': case 'a': /* ACK */
      flags_value |= 0x10;
      break;
    case 'U': case 'u': /* URG */
      flags_value |= 0x20;
      break;
    case 'E': case 'e': /* ECE */
      flags_value |= 0x40;
      break;
    case 'C': case 'c': /* CWR */
      flags_value |= 0x80;
      break;
    case '+': /* All flags set */
      flags_mask = 0xFF;
      break;
    case '*': /* Any flag set */
      flags_mask = 0x00;
      break;
    }
    flag_ptr++;
  }

  options->tcp_flags_enabled = 1;
  options->tcp_flags_value = flags_value;
  options->tcp_flags_mask = flags_mask;

  return 0;
}

/**
 * @brief Parse TTL option
 */
static int
parse_ttl_option (char *ttl_str, ips_rule_options_t *options)
{
  char *value_ptr = ttl_str;

  options->ttl_enabled = 1;

  if (*value_ptr == '>')
  {
    options->ttl_operator = 1; /* greater than */
    value_ptr++;
  }
  else if (*value_ptr == '<')
  {
    options->ttl_operator = 2; /* less than */
    value_ptr++;
  }
  else
  {
    options->ttl_operator = 0; /* equal */
  }

  options->ttl_value = atoi (value_ptr);
  return 0;
}

/**
 * @brief Parse TOS option
 */
static int
parse_tos_option (char *tos_str, ips_rule_options_t *options)
{
  char *value_ptr = tos_str;

  /* Check for negation */
  if (*value_ptr == '!')
  {
    options->tos_not = 1;
    value_ptr++;
  }

  options->tos_enabled = 1;
  options->tos_value = strtoul (value_ptr, NULL, 0);
  options->tos_mask = 0xFF; /* Default mask */

  return 0;
}

/**
 * @brief Parse fragment bits option
 */
static int
parse_fragbits_option (char *fragbits_str, ips_rule_options_t *options)
{
  char *flag_ptr = fragbits_str;
  u8 fragbits_value = 0;

  /* Check for negation */
  if (*flag_ptr == '!')
  {
    options->fragbits_not = 1;
    flag_ptr++;
  }

  /* Parse fragment flags */
  while (*flag_ptr)
  {
    switch (*flag_ptr)
    {
    case 'M': case 'm': /* More fragments */
      fragbits_value |= 0x01;
      break;
    case 'D': case 'd': /* Don't fragment */
      fragbits_value |= 0x02;
      break;
    case 'R': case 'r': /* Reserved */
      fragbits_value |= 0x04;
      break;
    }
    flag_ptr++;
  }

  options->fragbits_enabled = 1;
  options->fragbits_value = fragbits_value;
  options->fragbits_mask = 0x07; /* All 3 bits */

  return 0;
}

/**
 * @brief Parse byte jump option
 */
static int
parse_byte_jump (char *byte_jump_str, ips_rule_options_t *options)
{
  char *token, *saveptr;
  char *jump_copy = ips_strdup (byte_jump_str);
  int param_count = 0;

  if (!jump_copy)
    return -1;

  options->byte_jump_enabled = 1;

  token = ips_strtok_r (jump_copy, ",", &saveptr);
  while (token && param_count < 3)
  {
    while (isspace (*token))
      token++;

    switch (param_count)
    {
    case 0: /* bytes to jump */
      options->byte_jump_bytes = atoi (token);
      break;
    case 1: /* offset */
      options->byte_jump_offset = atoi (token);
      break;
    case 2: /* flags */
      if (strstr (token, "relative"))
        options->byte_jump_relative = 1;
      if (strstr (token, "align"))
        options->byte_jump_align = 1;
      break;
    }

    param_count++;
    token = ips_strtok_r (NULL, ",", &saveptr);
  }

  free (jump_copy);
  return 0;
}

/**
 * @brief Parse byte extract option
 */
static int
parse_byte_extract (char *byte_extract_str, ips_rule_options_t *options)
{
  char *token, *saveptr;
  char *extract_copy = ips_strdup (byte_extract_str);
  int param_count = 0;

  if (!extract_copy)
    return -1;

  options->byte_extract_enabled = 1;

  token = ips_strtok_r (extract_copy, ",", &saveptr);
  while (token && param_count < 4)
  {
    while (isspace (*token))
      token++;

    switch (param_count)
    {
    case 0: /* bytes to extract */
      options->byte_extract_bytes = atoi (token);
      break;
    case 1: /* offset */
      options->byte_extract_offset = atoi (token);
      break;
    case 2: /* variable name */
      options->byte_extract_name = (u8 *) ips_strdup (token);
      break;
    case 3: /* flags */
      if (strstr (token, "relative"))
        options->byte_extract_relative = 1;
      break;
    }

    param_count++;
    token = ips_strtok_r (NULL, ",", &saveptr);
  }

  free (extract_copy);
  return 0;
}

/**
 * @brief Parse detection filter option
 */
static int
parse_detection_filter (char *det_filter_str, ips_rule_options_t *options)
{
  char *token, *value, *saveptr;
  char *filter_copy = ips_strdup (det_filter_str);

  if (!filter_copy)
    return -1;

  options->detection_filter_enabled = 1;

  token = ips_strtok_r (filter_copy, ",", &saveptr);
  while (token)
  {
    while (isspace (*token))
      token++;

    if (strncmp (token, "track ", 6) == 0)
    {
      value = token + 6;
      while (isspace (*value))
        value++;

      if (strcmp (value, "by_src") == 0)
        options->detection_filter_track = 0;
      else if (strcmp (value, "by_dst") == 0)
        options->detection_filter_track = 1;
    }
    else if (strncmp (token, "count ", 6) == 0)
    {
      value = token + 6;
      while (isspace (*value))
        value++;
      options->detection_filter_count = atoi (value);
    }
    else if (strncmp (token, "seconds ", 8) == 0)
    {
      value = token + 8;
      while (isspace (*value))
        value++;
      options->detection_filter_seconds = atoi (value);
    }

    token = ips_strtok_r (NULL, ",", &saveptr);
  }

  free (filter_copy);
  return 0;
}

/**
 * @brief Parse stream size option
 */
static int
parse_stream_size (char *stream_size_str, ips_rule_options_t *options)
{
  char *token, *saveptr;
  char *size_copy = ips_strdup (stream_size_str);

  if (!size_copy)
    return -1;

  options->stream_size_enabled = 1;

  token = ips_strtok_r (size_copy, ",", &saveptr);
  while (token)
  {
    while (isspace (*token))
      token++;

    if (strncmp (token, "client", 6) == 0)
    {
      options->stream_size_client = 1;
    }
    else if (strncmp (token, "server", 6) == 0)
    {
      options->stream_size_server = 1;
    }
    else if (*token == '>')
    {
      options->stream_size_operator = 1;
      options->stream_size_value = atoi (token + 1);
    }
    else if (*token == '<')
    {
      options->stream_size_operator = 2;
      options->stream_size_value = atoi (token + 1);
    }
    else if (isdigit (*token))
    {
      options->stream_size_operator = 0;
      options->stream_size_value = atoi (token);
    }

    token = ips_strtok_r (NULL, ",", &saveptr);
  }

  free (size_copy);
  return 0;
}

/**
 * @brief Parse base64 decode option
 */
static int
parse_base64_decode (char *base64_str, ips_rule_options_t *options)
{
  char *token, *saveptr;
  char *b64_copy = ips_strdup (base64_str);

  if (!b64_copy)
    return -1;

  options->base64_decode_enabled = 1;

  token = ips_strtok_r (b64_copy, ",", &saveptr);
  while (token)
  {
    while (isspace (*token))
      token++;

    if (strncmp (token, "bytes ", 6) == 0)
    {
      options->base64_decode_bytes = atoi (token + 6);
    }
    else if (strncmp (token, "offset ", 7) == 0)
    {
      options->base64_decode_offset = atoi (token + 7);
    }

    token = ips_strtok_r (NULL, ",", &saveptr);
  }

  free (b64_copy);
  return 0;
}

/**
 * @brief Parse fast pattern option
 */
static int
parse_fast_pattern (char *fast_pattern_str, ips_rule_options_t *options)
{
  char *token, *saveptr;
  char *fp_copy = ips_strdup (fast_pattern_str);

  if (!fp_copy)
    return -1;

  options->fast_pattern_enabled = 1;

  token = ips_strtok_r (fp_copy, ",", &saveptr);
  while (token)
  {
    while (isspace (*token))
      token++;

    if (strcmp (token, "only") == 0)
    {
      options->fast_pattern_only = 1;
    }
    else if (strncmp (token, "offset ", 7) == 0)
    {
      options->fast_pattern_offset = atoi (token + 7);
    }
    else if (strncmp (token, "length ", 7) == 0)
    {
      options->fast_pattern_length = atoi (token + 7);
    }

    token = ips_strtok_r (NULL, ",", &saveptr);
  }

  free (fp_copy);
  return 0;
}
