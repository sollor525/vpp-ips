/*
 * ips_http_parser.h - VPP IPS HTTP Protocol Parser
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

#ifndef __IPS_HTTP_PARSER_H__
#define __IPS_HTTP_PARSER_H__

#include <vlib/vlib.h>
#include "ips_protocol_detection.h"

/* HTTP parsing state */
typedef enum
{
    IPS_HTTP_STATE_NONE = 0,
    IPS_HTTP_STATE_REQUEST_LINE,
    IPS_HTTP_STATE_RESPONSE_LINE,
    IPS_HTTP_STATE_HEADERS,
    IPS_HTTP_STATE_BODY,
    IPS_HTTP_STATE_CHUNKED,
    IPS_HTTP_STATE_COMPLETE
} ips_http_state_t;

/* HTTP method types */
typedef enum
{
    IPS_HTTP_METHOD_UNKNOWN = 0,
    IPS_HTTP_METHOD_GET,
    IPS_HTTP_METHOD_POST,
    IPS_HTTP_METHOD_PUT,
    IPS_HTTP_METHOD_DELETE,
    IPS_HTTP_METHOD_HEAD,
    IPS_HTTP_METHOD_OPTIONS,
    IPS_HTTP_METHOD_PATCH,
    IPS_HTTP_METHOD_CONNECT,
    IPS_HTTP_METHOD_TRACE,
    IPS_HTTP_METHOD_MAX
} ips_http_method_t;

/* HTTP parsing flags */
typedef enum
{
    IPS_HTTP_FLAG_NONE = 0,
    IPS_HTTP_FLAG_HAS_HEADERS = 0x01,
    IPS_HTTP_FLAG_HAS_BODY = 0x02,
    IPS_HTTP_FLAG_CHUNKED = 0x04,
    IPS_HTTP_FLAG_KEEP_ALIVE = 0x08,
    IPS_HTTP_FLAG_UPGRADE = 0x10,
    IPS_HTTP_FLAG_TLS = 0x20,
    IPS_HTTP_FLAG_HTTP2 = 0x40,
    IPS_HTTP_FLAG_ANOMALY = 0x80
} ips_http_flags_t;

/* HTTP parser state structure */
typedef struct
{
    /* Current parsing state */
    ips_http_state_t state;

    /* HTTP method for requests */
    ips_http_method_t method;

    /* HTTP status code for responses */
    u16 status_code;

    /* HTTP version */
    u8 version_major;
    u8 version_minor;

    /* Parsing flags */
    ips_http_flags_t flags;

    /* Header parsing */
    u32 header_offset;
    u32 header_len;
    u8 headers_complete;

    /* Body parsing */
    u32 content_length;
    u32 body_bytes_read;
    u8 chunk_size_parsed;
    u32 current_chunk_size;

    /* URL and host tracking */
    u32 url_offset;
    u32 url_len;
    u32 host_offset;
    u32 host_len;

    /* User-Agent tracking */
    u32 user_agent_offset;
    u32 user_agent_len;

    /* Statistics */
    u32 request_count;
    u32 response_count;
    u32 header_count;
    u64 total_bytes;

} ips_http_parser_state_t;

/* HTTP method strings */
extern const char *ips_http_method_strings[];

/* Function prototypes */
void *ips_http_parser_init(void);
void ips_http_parser_free(void *state);
u8 ips_http_probe(u8 *data, u32 len, u8 direction);
int ips_http_parse(void *parser_state, u8 *data, u32 len, u8 direction,
                   ips_proto_state_t *proto_state, ips_proto_flags_t *flags);
int ips_http_get_metadata(void *parser_state, char *buffer, u32 buffer_len);
int ips_http_check_anomaly(void *parser_state, u8 *data, u32 len, u8 direction);

/* Utility functions */
const char *ips_http_method_to_string(ips_http_method_t method);
ips_http_method_t ips_http_parse_method(const u8 *data, u32 len);
int ips_http_is_valid_header_name(const u8 *data, u32 len);
int ips_http_is_valid_status_code(u16 code);

#endif /* __IPS_HTTP_PARSER_H__ */