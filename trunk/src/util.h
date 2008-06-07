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
 * \file util.h
 * \brief Some helper functions.
 * \author Sebastien Vincent
 * \note Some network functions comes from libsockvs.
 */
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

  /**
   * \brief Get a TCP socket directly useable.
   * \param server IP address or DNS name
   * \param port TCP port
   * \return the socket or -1 if error
   */
	int connect_socket_tcp(const char* server, uint16_t port);

  /**
   * \brief Get first Global IPv6 address.
   * \param dev interface name
   * \return ipv6 on success, NULL otherwise
   */
	char* get_global_ipv6_addr(char* dev);

  /**
   * \brief Test if an IP address (v4 or v6) is valid.
   * \param af af family
   * \param ip IP address to test
   * \return 1 if valid, 0 otherwise
   */
	int is_valid_ip(int af, char* ip);
#ifdef __cplusplus
}
#endif

