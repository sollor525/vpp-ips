/*
 * ips_pcre_support.c - VPP IPS Plugin PCRE to Hyperscan Conversion
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include "ips.h"
#include <vppinfra/clib.h>
#include <vppinfra/error.h>
#include <string.h>
#include <ctype.h>

/**
 * @brief Convert PCRE pattern to Hyperscan compatible pattern
 */
int
ips_convert_pcre_to_hyperscan (const char *pcre_pattern, u8 **hs_pattern,
                              unsigned int *hs_flags, u8 **error_msg)
{
  if (!pcre_pattern || !hs_pattern)
    return -1;

  /* For now, most PCRE patterns are directly compatible with Hyperscan */
  /* This is a simplified implementation - in practice, more complex conversion may be needed */

  size_t pattern_len = strlen (pcre_pattern);
  u8 *converted = clib_mem_alloc (pattern_len + 1);
  if (!converted)
  {
    if (error_msg)
      *error_msg = format (0, "Memory allocation failed%c", 0);
    return -1;
  }

  strcpy ((char *)converted, pcre_pattern);

  /* Convert ASCII character classes like |28| to \x1c, |29| to \x1d, etc. */
  char *pos = strstr ((char *)converted, "|28|");
  while (pos) {
    /* Replace |28| with \x1c */
    memmove (pos + 4, pos + 4, strlen (pos + 4) + 1);
    memcpy (pos, "\\x1c", 4);
    pos = strstr ((char *)converted, "|28|");
  }

  pos = strstr ((char *)converted, "|29|");
  while (pos) {
    /* Replace |29| with \x1d */
    memmove (pos + 4, pos + 4, strlen (pos + 4) + 1);
    memcpy (pos, "\\x1d", 4);
    pos = strstr ((char *)converted, "|29|");
  }

  /* Set default Hyperscan flags */
  if (hs_flags)
  {
    *hs_flags = 0;

    /* Check for case-insensitive flag in pattern */
    if (strstr ((char *)converted, "(?i)"))
      *hs_flags |= HS_FLAG_CASELESS;

    /* Check for multiline flag */
    if (strstr ((char *)converted, "(?m)"))
      *hs_flags |= HS_FLAG_MULTILINE;

    /* Check for dotall flag */
    if (strstr ((char *)converted, "(?s)"))
      *hs_flags |= HS_FLAG_DOTALL;

    /* Remove flag patterns from converted string */
    char *flag_pos;
    while ((flag_pos = strstr ((char *)converted, "(?i)")) != NULL)
    {
      memmove (flag_pos, flag_pos + 4, strlen (flag_pos + 4) + 1);
    }
    while ((flag_pos = strstr ((char *)converted, "(?m)")) != NULL)
    {
      memmove (flag_pos, flag_pos + 4, strlen (flag_pos + 4) + 1);
    }
    while ((flag_pos = strstr ((char *)converted, "(?s)")) != NULL)
    {
      memmove (flag_pos, flag_pos + 4, strlen (flag_pos + 4) + 1);
    }
  }

  *hs_pattern = converted;

  clib_warning ("PCRE to Hyperscan conversion: '%s' -> '%s' (flags: 0x%x)",
               pcre_pattern, converted, hs_flags ? *hs_flags : 0);

  return 0;
}

/**
 * @brief Free converted pattern memory
 */
void
ips_free_converted_pattern (u8 *pattern)
{
  if (pattern)
    clib_mem_free (pattern);
}

/**
 * @brief Validate PCRE pattern for Hyperscan compatibility
 */
int
ips_validate_pcre_for_hyperscan (const char *pcre_pattern, u8 **error_msg)
{
  if (!pcre_pattern)
  {
    if (error_msg)
      *error_msg = format (0, "NULL pattern%c", 0);
    return -1;
  }

  /* Check length */
  if (strlen (pcre_pattern) > 8192)
  {
    if (error_msg)
      *error_msg = format (0, "Pattern too long (max 8192 chars)%c", 0);
    return -1;
  }

  /* Basic validation - most PCRE patterns work with Hyperscan */
  /* Complex lookahead/lookbehind patterns may not be supported */
  if (strstr (pcre_pattern, "(?=") || strstr (pcre_pattern, "(?!") ||
      strstr (pcre_pattern, "(?<=") || strstr (pcre_pattern, "(?<!"))
  {
    clib_warning ("PCRE pattern contains lookahead/lookbehind which may not be fully supported");
    return -1;
  }

  return 0;
}
