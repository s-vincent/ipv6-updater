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
 * \file conf.c
 * \brief Config option.
 * \author Sebastien Vincent
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <confuse.h>

#include "conf.h"

/**
 * \var opts
 * \brief Options recognized.
 */
static cfg_opt_t opts[]=
{
	CFG_BOOL("daemon", cfg_false, CFGF_NONE),
	CFG_STR("server", "www.dns6.org", CFGF_NONE),
	CFG_INT("port", 80, CFGF_NONE),
	CFG_STR("login", "", CFGF_NONE),
	CFG_STR("password", "", CFGF_NONE),
	CFG_STR("key", "", CFGF_NONE),
	CFG_INT("update", 30, CFGF_NONE),
	CFG_STR("host", "all", CFGF_NONE), 
	CFG_STR("static_ipv6", "::", CFGF_NONE),
	CFG_INT("auth_method", IPV6UPDATER_AUTH_LOGIN, CFGF_NONE),
	CFG_INT("ip_method", IPV6UPDATER_IP_LOCAL, CFGF_NONE),
	CFG_STR("ifname", "eth0", CFGF_NONE),
	CFG_END()
};

/**
 * \var cfg
 * \brief Config pointer.
 */
static cfg_t *cfg=NULL;

int ipv6updater_cfg_parse(char* file)
{
	int ret=0;
	cfg=cfg_init(opts, CFGF_NONE);

	ret=cfg_parse(cfg, file);
	if(ret==CFG_FILE_ERROR)
	{
		fprintf(stderr, "Cannot find configuration file %s\n", file);
		return -1;
	}
	else if(ret==CFG_PARSE_ERROR)
	{
		fprintf(stderr, "Parse error in configuration file %s\n", file);
		return -2;
	}
	return 0;
}

void ipv6updater_cfg_print(void)
{
	cfg_print(cfg, stderr);
}

void ipv6updater_cfg_free(void)
{
	if(cfg)
	{
		cfg_free(cfg);
	}
	cfg=NULL;
}

int ipv6updater_cfg_daemon(void)
{
	return cfg_getbool(cfg, "daemon");
}

char* ipv6updater_cfg_server(void)
{
	return cfg_getstr(cfg, "server");
}

int ipv6updater_cfg_port(void)
{
	return cfg_getint(cfg, "port");
}

char* ipv6updater_cfg_login(void)
{
	return cfg_getstr(cfg, "login");
}

char* ipv6updater_cfg_password(void)
{
	return cfg_getstr(cfg, "password");
}

char* ipv6updater_cfg_key(void)
{
	return cfg_getstr(cfg, "key");
}

unsigned long ipv6updater_cfg_update(void)
{
	return cfg_getint(cfg, "update");
}

char* ipv6updater_cfg_host(void)
{
	return cfg_getstr(cfg, "host");
}

char* ipv6updater_cfg_ipv6(void)
{
	return cfg_getstr(cfg, "static_ipv6");
}

int ipv6updater_cfg_auth_method(void)
{
	return cfg_getint(cfg, "auth_method");
}

int ipv6updater_cfg_ip_method(void)
{
	return cfg_getint(cfg, "ip_method");
}

char* ipv6updater_cfg_ifname(void)
{
	return cfg_getstr(cfg, "ifname");
}

