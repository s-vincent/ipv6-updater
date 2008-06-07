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
 * \file main.c
 * \brief IPv6 Updater main file.
 * \author Sebastien Vincent
 * \todo Add MS Windows compatiblity.
 * \todo Add events logs (file or syslog).
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <error.h>
#include <errno.h>
#include <locale.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/resource.h>

#ifdef S_SPLINT_S
#include "/usr/share/splint/lib/posix.h"
#else
#include <arpa/inet.h>
#endif
#include <netdb.h>
#include <netinet/in.h>
#include <net/if.h>

#include "util.h"
#include "util_sys.h"
#include "dbg.h"
#include "conf.h"

/**
 * \def DEFAULT_HOSTNAME
 * \brief Default hostname.
 */
#define DEFAULT_HOSTNAME "www.dns6.org"

/**
 * \def DEFAULT_PORT
 * \brief Default port.
 */
#define DEFAULT_PORT 80

/**
 * \def DEFAULT_UPDATE
 * \brief Default 30 seconds between updates.
 */
#define	DEFAULT_UPDATE 30

/** 
 * \def DEFAULT_HOST
 * \brief Default is to update all host.
 */
#define DEFAULT_HOST "all"

#ifndef VERSION
/**
 * \def VERSION 
 * \brief The version of this software.
 */
#define VERSION "0.2.2"
#endif

/**
 * \def IPV6UPDATER_DEBUG
 * \brief Debug Level.
 */
#define IPV6UPDATER_DEBUG 2

#if IPV6UPDATER_DEBUG >=2
#define debug2 debug
#else
#define debug2 dbg_print_null
#endif
#if IPV6UPDATER_DEBUG>=3
#define debug3 debug
#else
#define debug3 dbg_print_null
#endif
#if IPV6UPDATER_DEBUG>=4
#define debug4 debug
#else 
#define debug4 dbg_print_null
#endif

/* 
	format :

  http://www.dns6.org/upd.php?user=login&pwd=mypassword&host=host1,host2 => update host1 and host2
  http://www.dns6.org/upd.php?user=login&pwd=mypassword&host=all => upgrade all host of the account
  http://wwww.dns6.org/upd.php?key=1234567890ABCDEF1234567890ABCDEF&host=all => upgrade all host with a key (which replaced login/pass)

	Your IP address is automaticaly detected. However, if you want to specify another IP, you can use :
  http://www.dns6.org/upd.php?user=login&pwd=mypassword&host=host1,host2&ip=2001::1
*/

/**
 * \struct ipv6updater_config
 * \brief Configuration parameters used.
 */
struct ipv6updater_config
{
	char* file; 	/**< Config file */
	char* login;	/**< Login 	*/
	char* password; /**< Password 	*/
	char* key;	/**< Key (replace login/pass) */
	char* server;	/**< Server 	*/
	uint16_t port;	/**< TCP port of server */
	char* ip;	/**< IPv6 address to update */
	char* host;	/**< Host to update */
	int daemon;	/**< Go daemon */
	unsigned long update;/**< Update every... */
	char* dev;	/**< Interface name (i.e eth0) */
	int auth_method;/**< Authentification method */
	int ip_method; 	/**< Method to retrieve IPv6 address */
}ipv6updater_config;

/**
 * \var connection_string
 * \brief Connection string for login / password.
 */
static const char* connection_string="GET /upd.php?user=%s&pwd=%s&host=%s";

/**
 * \var connection_string_key
 * \brief Connection string for key.
 */
static const char* connection_string_key="GET /upd.php?key=%s&host=%s"; 

/**
 * \var http_footer
 * \brief Footer for the HTTP request.
 */
static const char* http_footer=" HTTP/1.1\nHost: %s\nConnection: close\n\n";

/**
 * \var run
 * \brief Wheter or not the application is running.
 */
static volatile int run=1; /**< Wheter or not the application is running */

/**
 * \var cfg
 * \brief Parameters for the application.
 */
static struct ipv6updater_config cfg; 

/**
 * \brief Read and parse config file.
 * \param cfg config
 * \return 0 if success, -1 otherwise
 */
static int read_config(struct ipv6updater_config* cfg)
{
  if(cfg->file)
  {
    /* reset config parser */
    ipv6updater_cfg_free(); /* cfg is set to NULL in conf.c at the beginning and after all call to ipv6updater_cfg_free, so no problem */
    ipv6updater_cfg_parse(cfg->file);

    /* put option values in structure */
    cfg->server=ipv6updater_cfg_server();
    cfg->port=ipv6updater_cfg_port();
    cfg->daemon=ipv6updater_cfg_daemon();
    cfg->key=ipv6updater_cfg_key();
    cfg->login=ipv6updater_cfg_login();
    cfg->password=ipv6updater_cfg_password();
    cfg->ip=ipv6updater_cfg_ipv6();
    cfg->update=ipv6updater_cfg_update();
    cfg->auth_method=ipv6updater_cfg_auth_method();
    cfg->ip_method=ipv6updater_cfg_ip_method();
    cfg->host=ipv6updater_cfg_host();

    if(cfg->ip_method==IPV6UPDATER_IP_LOCAL)
    {
      cfg->ip=NULL;
      cfg->dev=ipv6updater_cfg_ifname();
    }
    if(cfg->auth_method==IPV6UPDATER_AUTH_LOGIN)
    {
      cfg->key=NULL;
    }

    /* ipv6updater_cfg_print(); */
    return 0;
  }
  return -1;
}

/**
 * \brief Check the parameters.
 * \param cfg config
 * \note exit program otherwise
 * \warning in case of errors, the program will exit!
 */
static void check_config(struct ipv6updater_config* cfg)
{
  /* check parameters */
  if(cfg->ip) /* if you use -d eth0 -i 2002::1 for example, it is static IP that will be used */
  {
    /* command line, IPV6UPDATER_IP_STATIC */
    cfg->ip_method=IPV6UPDATER_IP_STATIC;
    if(!is_valid_ip(AF_INET6, cfg->ip))
    {
      debug(DBG_ATTR, "Error IPv6 not valid!\n");
      exit(EXIT_FAILURE);
    }
  }
  else
  {
    cfg->ip_method=IPV6UPDATER_IP_LOCAL;
    if(!cfg->dev)
    {
      debug(DBG_ATTR, "Ifname required!\n");
      exit(EXIT_FAILURE);
    }
  }

  if(!(cfg->login && cfg->password) && !cfg->key)
  {
    debug(DBG_ATTR, "Error login/password or key not set!\n");
    exit(EXIT_FAILURE);
  }

  if(cfg->key)
  {
    cfg->auth_method=IPV6UPDATER_AUTH_KEY;
    /* if key is set, get rid of login/password */
    cfg->login=NULL;
    cfg->password=NULL;
  }
  else
  {
    cfg->auth_method=IPV6UPDATER_AUTH_LOGIN;
  }

  if(cfg->dev)
  {
    if(if_nametoindex(cfg->dev)==0)
    {
      debug(DBG_ATTR, "Interface does not exit!\n");
      exit(EXIT_FAILURE);
    }
  }

  return;
}

/**
 * \brief Function executed when we exit the application.
 */
static void exit_routine(void)
{
        debug(DBG_ATTR, "Exiting, cleanup!\n");
        ipv6updater_cfg_free(); /* in case we do not use a file, this call do nothing */
}

/**
 * \brief Function that process signal received.
 * \param code the signal code
 */
static void signal_handler(int code)
{
	switch(code)
	{
		case SIGTERM:
		case SIGINT:
		case SIGABRT:
			debug(DBG_ATTR, "---------------------\n");
			debug(DBG_ATTR, "Exit due to a signal.\n");
			run=0;
			exit_routine(); /* with _exit(), the atexit routine will not work! */

			/* we do this because exit() is not recommanded to be called
			 * in a signal handler (other than in a separate thread.
			 */
			_exit(EXIT_FAILURE); 
			break;
		case SIGPIPE:
			break;
		case SIGHUP:
			if(cfg.file)
			{
				if(read_config(&cfg)==-1)
				{
					debug(DBG_ATTR, "Config error\n");
				}
				check_config(&cfg);
			}
			break;
		default:
			break;
	}
}

/**
 * \brief Print the help.
 * \param name the program name 
 */
static void print_help(char* name)
{
	fprintf(stdout, "Usage : %s [OPTIONS | -f file]\n", name);
	fprintf(stdout, "-f file\t\t: config file (other options will be ignored)\n");
	fprintf(stdout, "-s server\t: specify the server\n");
	fprintf(stdout, "-P port\t\t: specify the port\n");
	fprintf(stdout, "-l login\t: set user\n");
	fprintf(stdout, "-p password\t: set password\n");
	fprintf(stdout, "-k key\t\t: the key (cannot be combined with login/pass)\n");
	fprintf(stdout, "-u n\t\t: update every 'n' seconds\n");
	fprintf(stdout, "-i ipv6\t\t: update to a specific IPv6\n");
	fprintf(stdout, "-H host\t\t: account host\n");
	fprintf(stdout, "-d \t\t: interface name (i.e. eth0)\n");
	fprintf(stdout, "-b \t\t: fork to the background\n");
	fprintf(stdout, "-h\t\t: print this help\n");
}


/**
 * \brief Parse the command line.
 * \param argc number of arguments
 * \param argv array of arguments
 * \param cfg config
 */
static void parse_cmdline(int argc, char** argv, struct ipv6updater_config* cfg)
{
	int arg=-1;
	const char* options="f:s:p:l:P:k:hu:i:d:H:b";
	
	/* default value */
	cfg->file=NULL;
	cfg->daemon=0;
	cfg->port=80;
  cfg->update=DEFAULT_UPDATE;
  cfg->server=DEFAULT_HOSTNAME;
	cfg->host=DEFAULT_HOST;

	while((arg=getopt(argc, argv, options))!=-1 && !cfg->file)
	{
		switch(arg)
		{
			case '?':
				exit(EXIT_FAILURE);
				break;
			case 'f': 
				if(optarg)
				{
					cfg->file=optarg;
				}
				break;
			case 'H':
				if(optarg)
				{
					cfg->host=optarg;
				}
				else
				{
					print_help(argv[0]);
					exit(EXIT_FAILURE);
				}
				break;
			case 'd':
				cfg->dev=optarg;
				break;
			case 'b': 
				cfg->daemon=1;
				break;
			case 'h':
				print_help(argv[0]);
				exit(EXIT_SUCCESS);
				break;
			case 'l':
				if(optarg)
				{
					cfg->login=optarg;
				}
				else
				{
					print_help(argv[0]);
					exit(EXIT_FAILURE);
				}
				break;
			case 'p': 
				if(optarg)
				{
					cfg->password=optarg;
				}
				else
				{
					print_help(argv[0]);
					exit(EXIT_FAILURE);
				}
				break;
			case 'k':
				if(optarg)
				{
					cfg->key=optarg;;
				}
				else
				{
					print_help(argv[0]);
					exit(EXIT_FAILURE);
				}
				break;
			case 'i':
				if(optarg)
				{
					cfg->ip=optarg;
				}
				else
				{
					print_help(argv[0]);
					exit(EXIT_FAILURE);
				}
				break;
			case 'u':
				if(optarg)
				{
					int tmp=atoi(optarg);
					if(tmp<0)
					{
						debug(DBG_ATTR, "Update must be > 0\n");
						exit(EXIT_FAILURE);
					}
					else
					{
						cfg->update=(uint32_t)tmp;
					}
				}
				break;
			case 's':
				if(!optarg)
				{
					print_help(argv[0]);
					exit(EXIT_FAILURE);
				}
				else
				{
					cfg->server=optarg;
				}
				break;
			case 'P':
				if(optarg)
				{
					int tmp=atoi(optarg);
					if(tmp<=0)
					{
						debug(DBG_ATTR, "Port must be >0 and <65536\n");
					}
					else
					{
						cfg->port=(uint16_t)tmp;
					}

				}
				else
				{
					print_help(argv[0]);
					exit(EXIT_FAILURE);
				}
				break;	
		}
	}

}

/**
 * \brief Update by sending a HTTP request to the server.
 * \param server the server
 * \param port the port
 * \param login the login to use (may be NULL if key is used!)
 * \param password the password to use (may be NULL if key is used!)
 * \param key the key to use (may be NULL if login/password is used!)
 * \param host the hostname or "all" to update all the hosts
 * \param ip the IPv6 the server will update (may be NULL)
 * \return 1 if success, 0 if not update or a negative value otherwise (errors)
 * \todo Add better detection of success.
 * \todo Add error handling (in HTTP response).
 */
static int update_ipv6(char* server, uint16_t port, char* login, char* password, char *key, char* host, char* ip)
{
	char* query=NULL;
	char buf[16384]; /* buffer to read the HTTP response */
	char* p=NULL;
	int sock=-1;
	size_t bytes_read=0;
	size_t len=0;
	size_t len_footer=strlen(http_footer)+strlen(server)+1 -2; /* 1 = \0, -2 ="%s" */
	int use_key=0;
	char* elogin=NULL; /* encoded login */
	char* epassword=NULL;  /* encoded password */

  sock=connect_socket_tcp(server, port);
  if(sock==-1)
  {
	  return -errno;
  }
	
	if(ip)
	{
		len+=strlen(ip)+4; /* 4 = "&ip=" */
	}

	host=encode_http_string(host); /* host are not allocated so... */

	len+=strlen(host);

	if(login && password)
	{
		elogin=encode_http_string(login);
		epassword=encode_http_string(password);

		if(!elogin || !epassword)
		{
			if(close(sock)==-1)
			{
				debug(DBG_ATTR, "Error close()\n");
			}
			free(host);
			free(elogin);
			free(epassword);
			return -ENOMEM;
		}

		use_key=0;
		len+=strlen(connection_string)+strlen(elogin)+strlen(epassword)-6; /* 6 = 3 * "%s" */
	}
	else if(key)
	{
		use_key=1;
		elogin=NULL;
		epassword=NULL;
		len+=strlen(connection_string_key)+strlen(key)-4; /* 4 = 2 * "%s" */
	}

	query=malloc(sizeof(char)*(len+len_footer));
	if(!query)
	{
		perror("malloc");
		if(close(sock)==-1)
		{
			debug(DBG_ATTR, "Error close()\n");
		}
		free(elogin); /* no problem : login / password equal a valid value or NULL */
		free(epassword);
		free(host);
		return -ENOMEM;
	}

	if(use_key)
	{
		sprintf(query, connection_string_key, key, host);
	}
	else
	{
		sprintf(query, connection_string, elogin, epassword, host);
		free(elogin);
		free(epassword);
	}
	free(host);
	
	if(ip)
	{
		/* specify IP to connection_string */
		strcat(query, "&ip=");
		strcat(query, ip);
	}
	
	/* add footer */
	p=query+len;
	sprintf(p, http_footer, server);

	debug2(DBG_ATTR, "HTTP query :\n %s", query);
	
	/* send the query */
	if(send(sock, query, strlen(query), 0)<=0)
	{
		free(query);
		return -errno;
	}
	
	memset(buf, 0x00, sizeof(buf));
	
	do
	{
		p=buf+bytes_read;
		len=recv(sock, p, 16383-bytes_read, 0);
		bytes_read+=len;
	}while(len>0 || bytes_read>16383);
	
	buf[bytes_read]=0x00;
#if IPV6UPDATER_DEBUG >=2
	debug2(DBG_ATTR, "HTTP response : \n");
	fprintf(stdout, "%s\n", buf);
#endif

	/* cleanup */
	free(query);
	if(close(sock)==-1)
	{
		debug(DBG_ATTR, "Error close()\n");
	}

	/* check return code of HTTP response */
	if(strstr(buf, "[<font color=\"#00FF00\">200</font>]")==NULL)
	{
		return 0;
	}
	else
	{
		return 1;
	}
}

/**
 * \brief Entry point of the program.
 * \param argc number of argument
 * \param argv array of the arguments
 * \return exit value
 */
int main(int argc, char** argv)
{
	char* use_file=NULL;
	char msg[1024]; /* buffer for error message */
	char* buf=NULL;
	struct sigaction sig;

  /* internationalisation */
  setlocale(LC_ALL, "");

	debug(DBG_ATTR, "IPv6 Updater %s\n", VERSION);
	debug(DBG_ATTR, "Written by Sebastien Vincent\n");
	
	memset(msg, 0x00, sizeof(msg));

	/* signals handler and exit routine */
	memset(&sig, 0x00, sizeof(struct sigaction));
	sig.sa_handler=signal_handler;
	sigemptyset(&sig.sa_mask);
	sig.sa_flags=0;

	if(sigaction(SIGTERM, &sig, 0)==-1)
	{
		debug(DBG_ATTR, "Signal SIGTERM will not be caught\n");
	}

  if(sigaction(SIGINT, &sig, 0)==-1)
  {
		debug(DBG_ATTR, "Signal SIGINT will not be caught\n");
  }
        
	if(sigaction(SIGABRT, &sig, 0)==-1)
  {
  	debug(DBG_ATTR, "Signal SIGABRT will not be caught\n");
  }

  if(sigaction(SIGPIPE, &sig, 0)==-1)
  {
  	debug(DBG_ATTR, "Signal SIGPIPE will not be caught\n");
  }

  if(sigaction(SIGHUP, &sig, 0)==-1)
  {
  	debug(DBG_ATTR, "Signal SIGHUP will not be caught\n");
  }

#if 0
        if(signal(SIGTERM, signal_handler)==SIG_ERR)
        {
                debug(DBG_ATTR, "Signal SIGTERM will not be caught\n");
        }

        if(signal(SIGINT, signal_handler)==SIG_ERR)
        {
                debug(DBG_ATTR, "Signal SIGINT will not be caught\n");
        }

        if(signal(SIGABRT, signal_handler)==SIG_ERR)
        {
                debug(DBG_ATTR, "Signal SIGABRT will not be caught\n");
        }
        if(signal(SIGPIPE, signal_handler)==SIG_ERR)
        {
                debug(DBG_ATTR, "Signal SIGPIPE will not be caught\n");
        }
	if(signal(SIGHUP, signal_handler)==SIG_ERR)
	{
		debug(DBG_ATTR, "Signal SIGHUP will not be caught\n");
	}
#endif
        
	if(atexit(exit_routine)==-1)
	{
		debug(DBG_ATTR, "Error exit routine will not be run at the end!!\n");
	}
	
	memset(&cfg, 0x00, sizeof(struct ipv6updater_config));
	parse_cmdline(argc, argv, &cfg);
	use_file=cfg.file;

	if(use_file)
	{
		if(read_config(&cfg)==-1)
		{
			debug(DBG_ATTR, "Config error\n");
		}
	}

	check_config(&cfg);

  if(cfg.daemon)
  {
	  debug(DBG_ATTR, "Fork to the background\n");
		/* the father will exit in any case and call exit_routine so ipv6updater_cfg_free() is done  */
    if(go_daemon("/tmp/", 0)==-1)
    {
  	  buf=get_error(errno, msg, sizeof(msg));
      debug(DBG_ATTR, "Error fork : %s\n", buf);
      exit(EXIT_FAILURE);
     }

#if 0
		/* Only the child can be here, we read the config again ! */
		if(cfg->file)
		{
			read_config(&cfg);
		}
		/* Not necessary to check_config(), we check before
		 * Note : there is a few risk that the configuration 
		 * change between the moment we checked and the fork
		 */
#endif
	}

	/* print parameters */
	debug(DBG_ATTR, "Server    : %s\n", cfg.server);
	debug(DBG_ATTR, "Port      : %d\n", cfg.port);
	debug(DBG_ATTR, "Host      : %s\n", cfg.host);
	debug(DBG_ATTR, "Interface : %s\n", cfg.dev);
	debug(DBG_ATTR, "Update    : %d s\n", cfg.update);
	debug(DBG_ATTR, "Daemon    : %d\n", cfg.daemon);

	if(cfg.login)
	{
		debug(DBG_ATTR, "Login     : %s\n", cfg.login);	
		debug(DBG_ATTR, "Password  : ****\n");
	}
	else
	{
		debug(DBG_ATTR, "Key       : ****\n");
	}

	if(cfg.ip)
	{
		debug(DBG_ATTR, "IPv6      : %s\n", cfg.ip);
	}
	
	while(run)
	{
		int ret=0;

		if(cfg.ip_method==IPV6UPDATER_IP_LOCAL)
		{
			/* get global IPv6 */
			char* ipv6=get_global_ipv6_addr(cfg.dev);
			if(ipv6)
			{
				debug(DBG_ATTR, "IPv6 address : %s\n", ipv6);
				cfg.ip=ipv6;
			}
			else
			{
				debug(DBG_ATTR, "Failed to get IPv6!\n");
				msleep(cfg.update*1000000);
				continue;
			}
			
		}

		ret=update_ipv6(cfg.server, cfg.port, cfg.login, cfg.password, cfg.key, cfg.host, cfg.ip);
		
		if(ret<0)
		{
			buf=get_error(-ret, msg, 1023);
			debug(DBG_ATTR, "Error when updating : %s!\n", buf);
		}
		else if(ret==0)
		{
			debug(DBG_ATTR, "Update failed! (i.e wrong authentifcation, bad host, ...)\n");
		}
		else
		{
			debug(DBG_ATTR, "Update successful!\n");
		}

		if(cfg.ip_method==IPV6UPDATER_IP_LOCAL)
		{
			free(cfg.ip);
			cfg.ip=NULL;
		}
		msleep(cfg.update*1000000);
	}

	return EXIT_SUCCESS;
}

