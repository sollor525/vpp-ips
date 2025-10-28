/*
 * ips_suricata_enhanced_parser.h - VPP IPS Enhanced Suricata Rule Parser
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

#ifndef __IPS_SURICATA_ENHANCED_PARSER_H__
#define __IPS_SURICATA_ENHANCED_PARSER_H__

#include <vlib/vlib.h>
#include "ips_suricata_rule_types.h"

/* Parser context for error reporting */
typedef struct
{
    const char *input;
    const char *filename;
    u32 line_number;
    u32 char_position;
    char error_msg[512];
    u8 has_error;
} ips_suricata_parser_context_t;

/* Parser token types */
typedef enum
{
    IPS_TOKEN_EOF = 0,
    IPS_TOKEN_ACTION,
    IPS_TOKEN_PROTOCOL,
    IPS_TOKEN_IP_ADDRESS,
    IPS_TOKEN_IP_NETWORK,
    IPS_TOKEN_PORT,
    IPS_TOKEN_PORT_RANGE,
    IPS_TOKEN_DIRECTION,
    IPS_TOKEN_KEYWORD,
    IPS_TOKEN_COLON,
    IPS_TOKEN_SEMICOLON,
    IPS_TOKEN_OPEN_PAREN,
    IPS_TOKEN_CLOSE_PAREN,
    IPS_TOKEN_EQUAL,
    IPS_TOKEN_STRING,
    IPS_TOKEN_NUMBER,
    IPS_TOKEN_HEX_STRING,
    IPS_TOKEN_QUOTED_STRING,
    IPS_TOKEN_ERROR
} ips_suricata_token_type_t;

/* Parser token */
typedef struct
{
    ips_suricata_token_type_t type;
    const char *text;
    u32 length;
    u32 line;
    u32 column;
} ips_suricata_token_t;

/* Parse state */
typedef enum
{
    IPS_PARSE_START = 0,
    IPS_PARSE_RULE_HEADER,
    IPS_PARSE_RULE_OPTIONS,
    IPS_PARSE_OPTION_NAME,
    IPS_PARSE_OPTION_VALUE,
    IPS_PARSE_ERROR,
    IPS_PARSE_COMPLETE
} ips_suricata_parse_state_t;

/* Enhanced parser configuration */
typedef struct
{
    u8 strict_parsing;          /* Strict parsing mode */
    u8 allow_comments;          /* Allow rule comments */
    u8 validate_content;        /* Validate content patterns */
    u8 optimize_rules;          /* Optimize rules after parsing */
    u32 max_rule_length;        /* Maximum rule length */
    u32 max_content_length;     /* Maximum content length */
    u32 max_pcre_length;        /* Maximum PCRE pattern length */
} ips_suricata_parser_config_t;

/* Global parser state */
typedef struct
{
    ips_suricata_parser_config_t config;
    ips_suricata_parser_context_t *current_context;
    ips_suricata_rule_table_t *rule_table;
    u32 rules_parsed;
    u32 rules_loaded;
    u32 rules_with_errors;
    u64 parse_time;
} ips_suricata_parser_state_t;

/* Function prototypes */

/**
 * @brief Initialize the enhanced Suricata parser
 * @param config Parser configuration (can be NULL for defaults)
 * @return 0 on success, -1 on error
 */
int ips_suricata_parser_init(const ips_suricata_parser_config_t *config);

/**
 * @brief Cleanup parser state
 */
void ips_suricata_parser_cleanup(void);

/**
 * @brief Parse a single Suricata rule
 * @param rule_text Rule text to parse
 * @param filename Optional filename for error reporting
 * @param line_number Optional line number for error reporting
 * @return Parsed rule or NULL on error
 */
ips_suricata_rule_t *ips_suricata_parse_rule(const char *rule_text,
                                             const char *filename,
                                             u32 line_number);

/**
 * @brief Parse rules from a file
 * @param filename Path to rules file
 * @param rule_table Rule table to store parsed rules
 * @return Number of rules parsed, or -1 on error
 */
int ips_suricata_parse_rules_file(const char *filename,
                                  ips_suricata_rule_table_t *rule_table);

/**
 * @brief Parse rules from a string buffer
 * @param rules_string String containing rules
 * @param rule_table Rule table to store parsed rules
 * @return Number of rules parsed, or -1 on error
 */
int ips_suricata_parse_rules_string(const char *rules_string,
                                   ips_suricata_rule_table_t *rule_table);

/**
 * @brief Validate and optimize a parsed rule
 * @param rule Rule to validate and optimize
 * @return 0 on success, -1 on error
 */
int ips_suricata_validate_and_optimize_rule(ips_suricata_rule_t *rule);

/**
 * @brief Get parser statistics
 * @param rules_parsed Number of rules parsed
 * @param rules_loaded Number of rules successfully loaded
 * @param rules_with_errors Number of rules with parsing errors
 * @param parse_time Total parsing time in seconds
 */
void ips_suricata_parser_get_stats(u32 *rules_parsed,
                                  u32 *rules_loaded,
                                  u32 *rules_with_errors,
                                  f64 *parse_time);

/**
 * @brief Set parser error
 * @param ctx Parser context
 * @param format Printf-style format string
 * @param ... Format arguments
 */
void ips_suricata_parser_set_error(ips_suricata_parser_context_t *ctx,
                                   const char *format, ...);

/**
 * @brief Clear parser error
 * @param ctx Parser context
 */
void ips_suricata_parser_clear_error(ips_suricata_parser_context_t *ctx);

/* Low-level parsing functions */

/**
 * @brief Tokenize rule text
 * @param ctx Parser context
 * @param text Text to tokenize
 * @return Vector of tokens or NULL on error
 */
ips_suricata_token_t *ips_suricata_tokenize_rule(ips_suricata_parser_context_t *ctx,
                                                const char *text);

/**
 * @brief Parse rule header (action protocol src_ip src_port -> dst_ip dst_port)
 * @param ctx Parser context
 * @param rule_text Rule text to parse
 * @param char_index Current character index (updated)
 * @param rule Rule to populate
 * @return 0 on success, -1 on error
 */
int ips_suricata_parse_rule_header(ips_suricata_parser_context_t *ctx,
                                   const char *rule_text,
                                   u32 *char_index,
                                   ips_suricata_rule_t *rule);

/**
 * @brief Parse rule options (everything in parentheses)
 * @param ctx Parser context
 * @param tokens Token vector
 * @param token_index Current token index (updated)
 * @param rule Rule to populate
 * @return 0 on success, -1 on error
 */
int ips_suricata_parse_rule_options(ips_suricata_parser_context_t *ctx,
                                   ips_suricata_token_t *tokens,
                                   u32 *token_index,
                                   ips_suricata_rule_t *rule);

/* Option-specific parsing functions */

/**
 * @brief Parse content option
 * @param ctx Parser context
 * @param value Option value
 * @param rule Rule to populate
 * @return 0 on success, -1 on error
 */
int ips_suricata_parse_content_option(ips_suricata_parser_context_t *ctx,
                                      const char *value,
                                      ips_suricata_rule_t *rule);

/**
 * @brief Parse pcre option
 * @param ctx Parser context
 * @param value Option value
 * @param rule Rule to populate
 * @return 0 on success, -1 on error
 */
int ips_suricata_parse_pcre_option(ips_suricata_parser_context_t *ctx,
                                   const char *value,
                                   ips_suricata_rule_t *rule);

/**
 * @brief Parse byte_test option
 * @param ctx Parser context
 * @param value Option value
 * @param rule Rule to populate
 * @return 0 on success, -1 on error
 */
int ips_suricata_parse_byte_test_option(ips_suricata_parser_context_t *ctx,
                                        const char *value,
                                        ips_suricata_rule_t *rule);

/**
 * @brief Parse byte_jump option
 * @param ctx Parser context
 * @param value Option value
 * @param rule Rule to populate
 * @return 0 on success, -1 on error
 */
int ips_suricata_parse_byte_jump_option(ips_suricata_parser_context_t *ctx,
                                        const char *value,
                                        ips_suricata_rule_t *rule);

/**
 * @brief Parse flowbits option
 * @param ctx Parser context
 * @param value Option value
 * @param rule Rule to populate
 * @return 0 on success, -1 on error
 */
int ips_suricata_parse_flowbits_option(ips_suricata_parser_context_t *ctx,
                                       const char *value,
                                       ips_suricata_rule_t *rule);

/**
 * @brief Parse threshold option
 * @param ctx Parser context
 * @param value Option value
 * @param rule Rule to populate
 * @return 0 on success, -1 on error
 */
int ips_suricata_parse_threshold_option(ips_suricata_parser_context_t *ctx,
                                        const char *value,
                                        ips_suricata_rule_t *rule);

/**
 * @brief Parse flow option
 * @param ctx Parser context
 * @param value Option value
 * @param rule Rule to populate
 * @return 0 on success, -1 on error
 */
int ips_suricata_parse_flow_option(ips_suricata_parser_context_t *ctx,
                                   const char *value,
                                   ips_suricata_rule_t *rule);

/* Utility functions */

/**
 * @brief Convert hex string to bytes
 * @param hex_str Hex string
 * @param bytes Output buffer
 * @param max_bytes Maximum bytes to convert
 * @return Number of bytes converted, or -1 on error
 */
int ips_suricata_hex_to_bytes(const char *hex_str, u8 *bytes, u32 max_bytes);

/**
 * @brief Escape and unescape strings
 * @param str String to process
 * @param escaped Output buffer
 * @param max_len Maximum output length
 * @return 0 on success, -1 on error
 */
int ips_suricata_unescape_string(const char *str, char *escaped, u32 max_len);

/**
 * @brief Parse IP address/network specification
 * @param spec IP specification string
 * @param ip_spec Output IP specification
 * @return 0 on success, -1 on error
 */
int ips_suricata_parse_ip_spec(const char *spec, ips_ip_spec_t *ip_spec);

/**
 * @brief Parse port specification
 * @param spec Port specification string
 * @param port_spec Output port specification
 * @return 0 on success, -1 on error
 */
int ips_suricata_parse_port_spec(const char *spec, ips_port_spec_t *port_spec);

/**
 * @brief Check if a string represents a valid keyword
 * @param str String to check
 * @return 1 if valid keyword, 0 otherwise
 */
int ips_suricata_is_valid_keyword(const char *str);

#endif /* __IPS_SURICATA_ENHANCED_PARSER_H__ */