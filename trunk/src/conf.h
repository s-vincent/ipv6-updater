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
 * \file conf.h
 * \brief Config option.
 * \author Sebastien Vincent
 */

#ifndef CONF_H
#define	CONF_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/**
 * \def IPV6UPDATER_AUTH_LOGIN
 * \brief Authentication with login/pass.
 */
#define IPV6UPDATER_AUTH_LOGIN 	1

/**
 * \def IPV6UPDATER_AUTH_KEY
 * \brief Authentication with key.
 */
#define IPV6UPDATER_AUTH_KEY 	2

/**
 * \def IPV6UPDATER_IP_STATIC
 * \brief Update with a static IPv6 address.
 */
#define IPV6UPDATER_IP_STATIC	1

/**
 * \def IPV6UPDATER_IP_LOCAL
 * \brief Update with a local IPv6 address.
 * In case your IPv6 change i.e. 6to4 tunnel, ...
 */
#define IPV6UPDATER_IP_LOCAL	2

/**
 * \brief Parse config file.
 * \param file config file
 * \return 0 if success, negative integer otherwise
 */
int ipv6updater_cfg_parse(char* file);

/**
 * \brief Print the options.
 */
void ipv6updater_cfg_print(void);

/**
 * \brief Free resource.
 */
void ipv6updater_cfg_free(void);

/**
 * \brief Fork to the background on startup.
 * \return 1 if true, 0 otherwise
 */
int ipv6updater_cfg_daemon(void);

/**
 * \brief Server to update (default www.dns6.org).
 * \return server name
 */
char* ipv6updater_cfg_server(void);

/**
 * \brief Port to connect to the server (default 80).
 * \return port
 */
int ipv6updater_cfg_port(void);

/**
 * \brief Login.
 * \return login
 */
char* ipv6updater_cfg_login(void);

/**
 * \brief Password.
 * \return password
 */
char* ipv6updater_cfg_password(void);

/**
 * \brief Key (if you don't want to use login/pass).
 * \return key
 */
char* ipv6updater_cfg_key(void);

/**
 * \brief Time interval to update IP.
 * \return time interval
 */
unsigned long ipv6updater_cfg_update(void);

/**
 * \brief Host that should be updated.
 * \return host
 * \note "all" means all hosts.
 */
char* ipv6updater_cfg_host(void);

/**
 * \brief If you have a static IPv6 address.
 * \return ipv6
 */
char* ipv6updater_cfg_ipv6(void);

/**
 * \brief Method to authentificate (login/pass or key).
 * \return IPV6UPDATER_AUTH_LOGIN or IPV6UPDATER_AUTH_KEY
 */
int ipv6updater_cfg_auth_method(void);

/**
 * \brief Method to obtain IP (static or retrieve local IP).
 * \return IPV6UPDATER_IP_STATIC or IPV6UPDATER_IP_LOCAL
 */
int ipv6updater_cfg_ip_method(void);

/**
 * \brief Get interface name.
 * \return interface name
 */
char* ipv6updater_cfg_ifname(void);

#endif /* CONF_H */

