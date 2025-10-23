#include <vppinfra/types.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include "ips_session.h"
#include <stdio.h>
int main() { printf("ips_session_t size: %zu bytes\n", sizeof(ips_session_t)); return 0; }
