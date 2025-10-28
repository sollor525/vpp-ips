/*
 * ips_dns_parser.c - VPP IPS DNS Protocol Parser Implementation
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include <vlib/vlib.h>
#include <vppinfra/string.h>
#include <ctype.h>

#include "ips_dns_parser.h"
#include "../ips_logging.h"

/* DNS type strings */
const char *ips_dns_type_strings[] = {
    [IPS_DNS_TYPE_A] = "A",
    [IPS_DNS_TYPE_NS] = "NS",
    [IPS_DNS_TYPE_CNAME] = "CNAME",
    [IPS_DNS_TYPE_SOA] = "SOA",
    [IPS_DNS_TYPE_PTR] = "PTR",
    [IPS_DNS_TYPE_MX] = "MX",
    [IPS_DNS_TYPE_TXT] = "TXT",
    [IPS_DNS_TYPE_AAAA] = "AAAA",
    [IPS_DNS_TYPE_SRV] = "SRV",
    [IPS_DNS_TYPE_DNSKEY] = "DNSKEY",
    [IPS_DNS_TYPE_RRSIG] = "RRSIG",
    [IPS_DNS_TYPE_NSEC] = "NSEC",
};

/**
 * @brief Initialize DNS parser state
 */
void *
ips_dns_parser_init(void)
{
    ips_dns_parser_state_t *state = clib_mem_alloc(sizeof(ips_dns_parser_state_t));
    if (!state)
        return NULL;

    clib_memset(state, 0, sizeof(*state));
    return state;
}

/**
 * @brief Free DNS parser state
 */
void
ips_dns_parser_free(void *state)
{
    if (state)
        clib_mem_free(state);
}

/**
 * @brief Convert DNS type to string
 */
const char *
ips_dns_type_to_string(u16 type)
{
    if (type < ARRAY_LEN(ips_dns_type_strings) && ips_dns_type_strings[type])
        return ips_dns_type_strings[type];
    return "UNKNOWN";
}

/**
 * @brief Convert DNS response code to string
 */
const char *
ips_dns_rcode_to_string(u8 rcode)
{
    switch (rcode)
    {
    case IPS_DNS_RCODE_NOERROR: return "NOERROR";
    case IPS_DNS_RCODE_FORMERR: return "FORMERR";
    case IPS_DNS_RCODE_SERVFAIL: return "SERVFAIL";
    case IPS_DNS_RCODE_NXDOMAIN: return "NXDOMAIN";
    case IPS_DNS_RCODE_NOTIMP: return "NOTIMP";
    case IPS_DNS_RCODE_REFUSED: return "REFUSED";
    default: return "UNKNOWN";
    }
}

/**
 * @brief Check if domain name is valid
 */
int
ips_dns_is_valid_domain_name(const char *name, u32 len)
{
    if (!name || len == 0 || len > 255)
        return 0;

    u32 label_len = 0;
    for (u32 i = 0; i < len; i++)
    {
        u8 c = name[i];

        if (c == '.')
        {
            if (label_len == 0 || label_len > 63)
                return 0;
            label_len = 0;
        }
        else
        {
            if (!isalnum(c) && c != '-')
                return 0;
            label_len++;
        }
    }

    return label_len <= 63;
}

/**
 * @brief Extract domain name from DNS packet
 */
int
ips_dns_extract_domain_name(const u8 *data, u32 len, char *name, u32 name_len)
{
    if (!data || len < 2 || !name || name_len < 2)
        return -1;

    u32 offset = 0;
    u32 name_offset = 0;
    u8 jumped = 0;
    u8 compression_ptr = 0;

    while (offset < len && name_offset < name_len - 1)
    {
        u8 label_len = data[offset];

        /* Check for compression pointer */
        if ((label_len & 0xC0) == 0xC0)
        {
            if (!jumped)
                compression_ptr = offset + 2;

            u16 ptr = ((label_len & 0x3F) << 8) | data[offset + 1];
            if (ptr >= len)
                return -1;

            offset = ptr;
            jumped = 1;
            continue;
        }

        offset++;

        if (label_len == 0)
        {
            /* End of domain name */
            name[name_offset] = '\0';
            return jumped ? compression_ptr : offset;
        }

        if (label_len > 63 || offset + label_len > len)
            return -1;

        /* Add dot separator if not first label */
        if (name_offset > 0)
        {
            name[name_offset++] = '.';
            if (name_offset >= name_len - 1)
                break;
        }

        /* Copy label */
        for (u32 i = 0; i < label_len && name_offset < name_len - 1; i++)
        {
            char c = data[offset + i];
            /* Convert to lowercase and validate */
            if (isupper(c))
                c = tolower(c);
            else if (!isalnum(c) && c != '-')
                c = '?';  /* Replace invalid chars */

            name[name_offset++] = c;
        }

        offset += label_len;
    }

    name[name_offset] = '\0';
    return -1;
}

/**
 * @brief DNS protocol probe function
 */
u8
ips_dns_probe(u8 *data, u32 len, u8 __clib_unused direction)
{
    if (!data || len < 12)  /* DNS header is 12 bytes */
        return 0;

    /* DNS header structure:
     * 0-1: Transaction ID
     * 2: Flags (QR, Opcode, AA, TC, RD, RA, Z, RCODE)
     * 3: Flags continuation
     * 4-5: QDCOUNT (questions)
     * 6-7: ANCOUNT (answers)
     * 8-9: NSCOUNT (authority records)
     * 10-11: ARCOUNT (additional records)
     */

    u16 qdcount = (data[4] << 8) | data[5];
    u16 ancount = (data[6] << 8) | data[7];
    u16 nscount = (data[8] << 8) | data[9];
    u16 arcount = (data[10] << 8) | data[11];

    /* Basic validation */
    if (qdcount > 20 || ancount > 50 || nscount > 20 || arcount > 50)
        return 0;  /* Unreasonable counts */

    /* Check total record count */
    u16 total_records = qdcount + ancount + nscount + arcount;
    if (total_records == 0 || total_records > 100)
        return 0;

    /* Check if we have reasonable packet length */
    if (qdcount > 0 && len < 13)  /* Need at least 1 byte for domain name */
        return 0;

    /* Additional validation: check opcode */
    u8 opcode = (data[2] >> 3) & 0x0F;
    if (opcode > 2)  /* Only QUERY (0), IQUERY (1), STATUS (2) are common */
        return 0;

    /* High confidence for standard DNS */
    return 80;
}

/**
 * @brief Main DNS parsing function
 */
int
ips_dns_parse(void *parser_state, u8 *data, u32 len, u8 direction,
               ips_proto_state_t *proto_state, ips_proto_flags_t *flags)
{
    ips_dns_parser_state_t *state = (ips_dns_parser_state_t *)parser_state;

    if (!state || !data || len < 12 || !proto_state || !flags)
        return -1;

    state->total_bytes += len;

    /* Parse DNS header */
    state->id = (data[0] << 8) | data[1];

    /* Parse flags */
    u8 byte2 = data[2];
    u8 byte3 = data[3];

    u8 qr = (byte2 >> 7) & 0x01;
    state->opcode = (byte2 >> 3) & 0x0F;
    state->flags = 0;

    if (qr)
    {
        state->flags |= IPS_DNS_FLAG_RESPONSE;
        state->responses_seen++;
    }
    else
    {
        state->flags |= IPS_DNS_FLAG_QUERY;
        state->queries_seen++;
    }

    if (byte2 & 0x02)  /* TC bit */
        state->flags |= IPS_DNS_FLAG_TRUNCATED;
    if (byte2 & 0x01)  /* RD bit */
        state->flags |= IPS_DNS_FLAG_RECURSION_DESIRED;
    if (byte3 & 0x80)  /* RA bit */
        state->flags |= IPS_DNS_FLAG_RECURSION_AVAILABLE;
    if (byte3 & 0x10)  /* AD bit */
        state->flags |= IPS_DNS_FLAG_AUTHENTICATED;
    if (byte3 & 0x01)  /* CD bit */
        state->flags |= IPS_DNS_FLAG_CHECKING_DISABLED;

    state->rcode = byte3 & 0x0F;

    /* Parse record counts */
    state->qdcount = (data[4] << 8) | data[5];
    state->ancount = (data[6] << 8) | data[7];
    state->nscount = (data[8] << 8) | data[9];
    state->arcount = (data[10] << 8) | data[11];

    state->total_questions += state->qdcount;
    state->total_answers += state->ancount;

    /* Extract domain name from first question */
    if (state->qdcount > 0 && len > 12)
    {
        char domain_name[256];
        if (ips_dns_extract_domain_name(&data[12], len - 12,
                                       domain_name, sizeof(domain_name)) > 0)
        {
            if (qr)  /* Response */
            {
                clib_memcpy(state->last_response, domain_name,
                           clib_min(strlen(domain_name), 255));
            }
            else  /* Query */
            {
                clib_memcpy(state->last_query, domain_name,
                           clib_min(strlen(domain_name), 255));
            }
        }
    }

    *proto_state = IPS_PROTO_STATE_ESTABLISHED;
    return 0;
}

/**
 * @brief Check for DNS protocol anomalies
 */
int
ips_dns_check_anomaly(void *parser_state, u8 *data, u32 len, u8 direction)
{
    ips_dns_parser_state_t *state = (ips_dns_parser_state_t *)parser_state;

    if (!state || !data || len < 12)
        return 0;

    /* Check for common DNS anomalies */

    /* 1. Unreasonable record counts */
    u16 qdcount = (data[4] << 8) | data[5];
    u16 ancount = (data[6] << 8) | data[7];
    u16 nscount = (data[8] << 8) | data[9];
    u16 arcount = (data[10] << 8) | data[11];

    u16 total_records = qdcount + ancount + nscount + arcount;
    if (total_records > 100)  /* Very high record count */
        return 1;

    /* 2. Suspicious opcode */
    u8 opcode = (data[2] >> 3) & 0x0F;
    if (opcode > 2 && opcode != 15)  /* Allow standard opcodes and UPDATE */
        return 1;

    /* 3. Response without query (DNS amplification) */
    if ((state->flags & IPS_DNS_FLAG_RESPONSE) && state->queries_seen == 0)
        return 1;

    /* 4. NXDOMAIN responses to many different domains (possible DNS tunneling) */
    if (state->rcode == IPS_DNS_RCODE_NXDOMAIN && state->responses_seen > 10)
    {
        if (state->responses_seen > state->queries_seen * 2)
            return 1;
    }

    /* 5. Very long domain names (DNS tunneling) */
    if (len > 12)
    {
        char domain_name[256];
        if (ips_dns_extract_domain_name(&data[12], len - 12,
                                       domain_name, sizeof(domain_name)) > 0)
        {
            if (strlen(domain_name) > 100)  /* Very long domain name */
                return 1;
        }
    }

    return 0;
}

/**
 * @brief Get DNS metadata for logging
 */
int
ips_dns_get_metadata(void *parser_state, char *buffer, u32 buffer_len)
{
    ips_dns_parser_state_t *state = (ips_dns_parser_state_t *)parser_state;

    if (!state || !buffer || buffer_len < 64)
        return -1;

    int written = 0;

    /* Basic DNS info */
    written += snprintf(buffer + written, buffer_len - written,
                       "DNS %s rcode:%s q:%u r:%u",
                       (state->flags & IPS_DNS_FLAG_QUERY) ? "Q" : "R",
                       ips_dns_rcode_to_string(state->rcode),
                       state->queries_seen,
                       state->responses_seen);

    /* Add last query domain if available */
    if (state->last_query[0] != '\0')
    {
        written += snprintf(buffer + written, buffer_len - written,
                           " query:%s", state->last_query);
    }

    /* Add flags */
    if (state->flags & IPS_DNS_FLAG_TRUNCATED)
        written += snprintf(buffer + written, buffer_len - written, " TC");
    if (state->flags & IPS_DNS_FLAG_AUTHENTICATED)
        written += snprintf(buffer + written, buffer_len - written, " AD");
    if (state->flags & IPS_DNS_FLAG_ANOMALY)
        written += snprintf(buffer + written, buffer_len - written, " ANOMALY");

    return written;
}