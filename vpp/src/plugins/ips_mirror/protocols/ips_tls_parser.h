/*
 * ips_tls_parser.h - VPP IPS TLS/SSL Protocol Parser
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

#ifndef __IPS_TLS_PARSER_H__
#define __IPS_TLS_PARSER_H__

#include <vlib/vlib.h>
#include "ips_protocol_detection.h"

/* TLS record content types */
typedef enum
{
    IPS_TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC = 20,
    IPS_TLS_CONTENT_TYPE_ALERT = 21,
    IPS_TLS_CONTENT_TYPE_HANDSHAKE = 22,
    IPS_TLS_CONTENT_TYPE_APPLICATION_DATA = 23,
    IPS_TLS_CONTENT_TYPE_HEARTBEAT = 24
} ips_tls_content_type_t;

/* TLS handshake message types */
typedef enum
{
    IPS_TLS_HANDSHAKE_HELLO_REQUEST = 0,
    IPS_TLS_HANDSHAKE_CLIENT_HELLO = 1,
    IPS_TLS_HANDSHAKE_SERVER_HELLO = 2,
    IPS_TLS_HANDSHAKE_CERTIFICATE = 11,
    IPS_TLS_HANDSHAKE_SERVER_KEY_EXCHANGE = 12,
    IPS_TLS_HANDSHAKE_CERTIFICATE_REQUEST = 13,
    IPS_TLS_HANDSHAKE_SERVER_HELLO_DONE = 14,
    IPS_TLS_HANDSHAKE_CERTIFICATE_VERIFY = 15,
    IPS_TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE = 16,
    IPS_TLS_HANDSHAKE_FINISHED = 20
} ips_tls_handshake_type_t;

/* TLS parsing state */
typedef enum
{
    IPS_TLS_STATE_NONE = 0,
    IPS_TLS_STATE_HANDSHAKE,
    IPS_TLS_STATE_ESTABLISHED,
    IPS_TLS_STATE_CLOSED,
    IPS_TLS_STATE_ERROR
} ips_tls_state_t;

/* TLS parsing flags */
typedef enum
{
    IPS_TLS_FLAG_NONE = 0,
    IPS_TLS_FLAG_CLIENT_HELLO_SEEN = 0x01,
    IPS_TLS_FLAG_SERVER_HELLO_SEEN = 0x02,
    IPS_TLS_FLAG_CERTIFICATE_SEEN = 0x04,
    IPS_TLS_FLAG_ENCRYPTED = 0x08,
    IPS_TLS_FLAG_RESUMPTION = 0x10,
    IPS_TLS_FLAG_ANOMALY = 0x80
} ips_tls_flags_t;

/* TLS version */
typedef struct
{
    u8 major;
    u8 minor;
} ips_tls_version_t;

/* TLS cipher suite information */
typedef struct
{
    u16 cipher_suite;
    u8 key_exchange_method;
    u8 cipher;
    u8 mac;
    u8 exportable;
} ips_tls_cipher_suite_t;

/* TLS parser state structure */
typedef struct
{
    /* Current parsing state */
    ips_tls_state_t state;

    /* TLS version information */
    ips_tls_version_t version;
    ips_tls_version_t max_version;
    ips_tls_version_t min_version;

    /* Parsing flags */
    ips_tls_flags_t flags;

    /* Handshake information */
    u32 handshake_messages_seen;
    u64 handshake_bytes;

    /* Cipher suite information */
    u16 selected_cipher_suite;
    u8 compression_method;

    /* Certificate information */
    u32 certificate_count;
    u32 certificate_chain_length;

    /* Session information */
    u8 session_id[32];
    u8 session_id_length;

    /* Random values (for detection of anomalies) */
    u8 client_random[32];
    u8 server_random[32];

    /* SNI (Server Name Indication) */
    u8 sni[256];
    u8 sni_length;

    /* ALPN (Application-Layer Protocol Negotiation) */
    u8 alpn[64];
    u8 alpn_length;

    /* Statistics */
    u32 records_processed;
    u32 encrypted_records;
    u32 application_data_records;
    u64 total_bytes;

} ips_tls_parser_state_t;

/* TLS version strings */
extern const char *ips_tls_version_strings[];

/* Function prototypes */
void *ips_tls_parser_init(void);
void ips_tls_parser_free(void *state);
u8 ips_tls_probe(u8 *data, u32 len, u8 direction);
int ips_tls_parse(void *parser_state, u8 *data, u32 len, u8 direction,
                  ips_proto_state_t *proto_state, ips_proto_flags_t *flags);
int ips_tls_get_metadata(void *parser_state, char *buffer, u32 buffer_len);
int ips_tls_check_anomaly(void *parser_state, u8 *data, u32 len, u8 direction);

/* Utility functions */
const char *ips_tls_version_to_string(ips_tls_version_t version);
const char *ips_tls_content_type_to_string(u8 content_type);
const char *ips_tls_handshake_type_to_string(u8 handshake_type);
int ips_tls_is_valid_version(u8 major, u8 minor);
int ips_tls_is_valid_cipher_suite(u16 cipher_suite);
int ips_tls_extract_sni(const u8 *data, u32 len, u8 *sni, u8 *sni_len);

#endif /* __IPS_TLS_PARSER_H__ */