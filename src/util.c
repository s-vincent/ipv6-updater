/*
	 Copyright (C) 2006-2008 Sebastien Vincent.

	 Permission to use, copy, modify, and distribute this software for any
	 purpose with or without fee is hereby granted, provided that the above
	 copyright notice and this permission notice appear in all copies.

	 THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
	 REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
	 AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
	 INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
	 LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
	 OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
	 PERFORMANCE OF THIS SOFTWARE.
*/

/**
 * \file util.c
 * \brief Some functions.
 * \author Sebastien Vincent
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>

#include <ifaddrs.h>

#include "util.h"

#ifdef __cplusplus
extern "C"
{
#endif

	int connect_socket_tcp(const char* server, uint16_t port)
	{
		int sock=-1;
		struct addrinfo addr;
		struct addrinfo *res=NULL;
		struct addrinfo *res2=NULL;
		char tcp_port[8];

		memset(&addr, 0x00, sizeof(addr));
		addr.ai_family=AF_UNSPEC;
		addr.ai_socktype=SOCK_STREAM;

		sprintf(tcp_port, "%d", port);
		if (getaddrinfo(server, tcp_port, &addr, &res)>0)
		{
			return -1;
		}

		res2=res;

		while (res)
		{
			sock=socket(res->ai_family, res->ai_socktype, res->ai_protocol);
			if (sock==-1)
			{
				res=res->ai_next;
				continue;
			}

			if (connect(sock, res->ai_addr, res->ai_addrlen)==-1)
			{
				close(sock);
				sock=-1;
			}
			else
			{
				break;
			}

			res=res->ai_next;
		}

		freeaddrinfo(res2);

		return sock;
	}

	int is_valid_ip(int af, char* ip)
	{
		char tmp[64];
		int rep=0;

		rep=inet_pton(af, ip, tmp);

		if (rep<=0)
		{
			return 0;
		}
		else
		{
			return 1;
		}
	}

	char* get_global_ipv6_addr(char* dev)
	{
		char* ipv6=NULL;
		struct ifaddrs* ifa=NULL;
		struct ifaddrs* ifa2=NULL;
		struct sockaddr_in6* addr6=NULL;

		if (getifaddrs(&ifa)==-1)
		{
			return NULL;
		}
		ifa2=ifa;

		for (;ifa;ifa=ifa->ifa_next)
		{
			if (!strcmp(ifa->ifa_name, dev))
			{
				/* teredo interface */
				if(!ifa->ifa_addr)
				{
					continue;
				}

				if (ifa->ifa_addr->sa_family==AF_INET6)
				{
					addr6=(struct sockaddr_in6*)ifa->ifa_addr;
					ipv6=malloc(sizeof(char)*INET6_ADDRSTRLEN);

					if (!ipv6 || inet_ntop(AF_INET6, &addr6->sin6_addr, ipv6, INET6_ADDRSTRLEN )==NULL)
					{
						free(ipv6);
						freeifaddrs(ifa2);
						return NULL;
					}
					else
					{
						/* check that IPv6 address is global  */
						if (!(!IN6_IS_ADDR_UNSPECIFIED(&addr6->sin6_addr) && !IN6_IS_ADDR_LOOPBACK(&addr6->sin6_addr) && !IN6_IS_ADDR_MULTICAST(&addr6->sin6_addr) && !IN6_IS_ADDR_LINKLOCAL(&addr6->sin6_addr) && !IN6_IS_ADDR_SITELOCAL(&addr6->sin6_addr)))
						{
							free(ipv6);
							ipv6=NULL;
						}
						freeifaddrs(ifa2);
						return ipv6;

					}
				}

			}
		}

		freeifaddrs(ifa2);
		return NULL;
	}

#ifdef __cplusplus
}
#endif

