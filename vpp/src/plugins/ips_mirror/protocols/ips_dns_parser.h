/*
 * ips_dns_parser.h - VPP IPS DNS Protocol Parser
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

#ifndef __IPS_DNS_PARSER_H__
#define __IPS_DNS_PARSER_H__

#include <vlib/vlib.h>
#include "ips_protocol_detection.h"

/* DNS record types */
typedef enum
{
    IPS_DNS_TYPE_A = 1,
    IPS_DNS_TYPE_NS = 2,
    IPS_DNS_TYPE_CNAME = 5,
    IPS_DNS_TYPE_SOA = 6,
    IPS_DNS_TYPE_PTR = 12,
    IPS_DNS_TYPE_MX = 15,
    IPS_DNS_TYPE_TXT = 16,
    IPS_DNS_TYPE_AAAA = 28,
    IPS_DNS_TYPE_SRV = 33,
    IPS_DNS_TYPE_DNSKEY = 48,
    IPS_DNS_TYPE_RRSIG = 46,
    IPS_DNS_TYPE_NSEC = 47,
    IPS_DNS_TYPE_DNSSEC_OK = 32768
} ips_dns_type_t;

/* DNS response codes */
typedef enum
{
    IPS_DNS_RCODE_NOERROR = 0,
    IPS_DNS_RCODE_FORMERR = 1,
    IPS_DNS_RCODE_SERVFAIL = 2,
    IPS_DNS_RCODE_NXDOMAIN = 3,
    IPS_DNS_RCODE_NOTIMP = 4,
    IPS_DNS_RCODE_REFUSED = 5,
    IPS_DNS_RCODE_YXDOMAIN = 6,
    IPS_DNS_RCODE_YXRRSET = 7,
    IPS_DNS_RCODE_NXRRSET = 8,
    IPS_DNS_RCODE_NOTAUTH = 9,
    IPS_DNS_RCODE_NOTZONE = 10
} ips_dns_rcode_t;

/* DNS parsing flags */
typedef enum
{
    IPS_DNS_FLAG_NONE = 0,
    IPS_DNS_FLAG_QUERY = 0x01,
    IPS_DNS_FLAG_RESPONSE = 0x02,
    IPS_DNS_FLAG_TRUNCATED = 0x04,
    IPS_DNS_FLAG_RECURSION_DESIRED = 0x08,
    IPS_DNS_FLAG_RECURSION_AVAILABLE = 0x10,
    IPS_DNS_FLAG_AUTHENTICATED = 0x20,
    IPS_DNS_FLAG_CHECKING_DISABLED = 0x40,
    IPS_DNS_FLAG_ANOMALY = 0x80
} ips_dns_flags_t;

/* DNS question structure */
typedef struct
{
    char qname[256];     /* Query name */
    u16 qtype;           /* Query type */
    u16 qclass;          /* Query class */
} ips_dns_question_t;

/* DNS parser state structure */
typedef struct
{
    /* Parsing flags */
    ips_dns_flags_t flags;

    /* DNS header information */
    u16 id;              /* Transaction ID */
    u8 opcode;           /* Operation code */
    u8 rcode;            /* Response code */
    u16 qdcount;         /* Questions count */
    u16 ancount;         /* Answers count */
    u16 nscount;         /* Authority records count */
    u16 arcount;         /* Additional records count */

    /* Question information */
    ips_dns_question_t questions[8];  /* Support multiple questions */
    u8 question_count;

    /* Response information */
    u16 answer_types[16];  /* Types of answers received */
    u8 answer_count;

    /* Domain name tracking */
    char last_query[256];
    char last_response[256];

    /* Statistics */
    u32 queries_seen;
    u32 responses_seen;
    u32 total_questions;
    u32 total_answers;
    u64 total_bytes;

} ips_dns_parser_state_t;

/* DNS type strings */
extern const char *ips_dns_type_strings[];

/* Function prototypes */
void *ips_dns_parser_init(void);
void ips_dns_parser_free(void *state);
u8 ips_dns_probe(u8 *data, u32 len, u8 direction);
int ips_dns_parse(void *parser_state, u8 *data, u32 len, u8 direction,
                  ips_proto_state_t *proto_state, ips_proto_flags_t *flags);
int ips_dns_get_metadata(void *parser_state, char *buffer, u32 buffer_len);
int ips_dns_check_anomaly(void *parser_state, u8 *data, u32 len, u8 direction);

/* Utility functions */
const char *ips_dns_type_to_string(u16 type);
const char *ips_dns_rcode_to_string(u8 rcode);
int ips_dns_is_valid_domain_name(const char *name, u32 len);
int ips_dns_extract_domain_name(const u8 *data, u32 len, char *name, u32 name_len);
int ips_dns_is_query_response_pair(const u8 *query, u32 query_len,
                                  const u8 *response, u32 response_len);

#endif /* __IPS_DNS_PARSER_H__ */