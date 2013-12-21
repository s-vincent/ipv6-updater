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
 * \file util_sys.c
 * \brief Some system function.
 * \author Sebastien Vincent
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <sys/select.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <time.h>
#include <pwd.h>
#endif

#include "util_sys.h"

/**
 * \def UNKNOWN_ERROR
 * \brief When no other error string can be used.
 */
#define UNKNOWN_ERROR "Unknown error!"

#ifdef __cplusplus
extern "C"
{
#endif

	int msleep(unsigned long usec)
	{
		unsigned long sec;
		struct timeval tv;

		sec=(unsigned long)usec/1000000;
		usec=(unsigned long)usec%1000000;

		tv.tv_sec=sec;
		tv.tv_usec=usec;

		select(0, NULL, NULL, NULL, &tv);

		return 0;
	}

	int get_dtablesize(void)
	{
#ifndef _WIN32
		struct rlimit limit;
		getrlimit(RLIMIT_NOFILE, &limit);
		return limit.rlim_cur;
#else
#ifndef FD_SETSIZE
#define FD_SETSIZE 256
#endif
		return FD_SETSIZE;
#endif
	}

	int is_big_endian(void)
	{
		long one=1;
		return !(*((char *)(&one)));
	}

	int is_little_endian(void)
	{
		return !is_big_endian();
	}

	char* get_error(int errnum, char* buf, size_t buflen)
	{
		char* error=NULL;
#ifdef HAVE_STRERROR_R
# if _POSIX_C_SOURCE==200112L && !defined(_GNU_SOURCE)
		/* POSIX version */
		int ret=0;
		ret=strerror_r(errnum, buf, buflen);
		if (ret==-1)
		{
			strncpy(buf, UNKNOWN_ERROR, buflen-1);
			buf[buflen-1]=0x00;
		}
		error=buf;
# else
		/* GNU libc */
		error=strerror_r(errnum, buf, buflen);
# endif
#else
		/* no strerror_r() function, assume that strerror is reentrant! */
		strncpy(buf, strerror(errnum), buflen);
		error=buf;
#endif
		return error;
	}

	pid_t go_daemon(char* dir, mode_t mask)
	{
		pid_t pid=-1;
		int i=0;
		int max=0;

#ifdef _WIN32
		return -1;
#else

		pid=fork();

		if (pid>0) /* father */
		{
			return pid;
		}
		else if (pid==-1) /* error */
		{
			return -1;
		}

		max=sysconf(_SC_OPEN_MAX);
		for (i=0;i<max;i++)
		{
			close(i);
		}

		/* change directory */
		if (!dir)
		{
			dir="/tmp";
		}

		if (chdir(dir)==-1)
		{
			return -1;
		}

		/* change mask */
		umask(mask);

		return 0;
#endif
	}

	char* encode_http_string(char* str)
	{
		size_t len=strlen(str);
		char* p=NULL;
		unsigned int i=0;
		unsigned int j=0;

		p=malloc(sizeof(char)*(3*len+1)); /* in the worst case, it take 3x (%20) the size */

		if (!p)
		{
			return NULL;
		}

		for (i=0,j=0;i<len;i++, j++)
		{
			unsigned int t=(unsigned int)str[i];

			if (t<42 || t==',' || (t>=58  && t<64) || (t>=91 && t<95) || t=='`' || t>122 || t=='+' || t=='&' || t==',' || t==';' || t=='/' || t=='?' || t=='@' || t=='$' || t=='=' || t==':' )
			{
				/* replace */
				sprintf(p+j, "%%%02X", t);
				j+=2;
			}
			else
			{
				p[j]=(char)t;
			}
		}

		p[j]=0x00;

		return p;
	}

#ifdef _WIN32

	ssize_t sock_readv(int fd, const struct iovec *iov, int iovcnt, struct sockaddr* addr)
	{
		/* it should be sufficient.
		 * the dynamically allocation is timecost.
		 * We could use a static WSABUF* winiov but the function would be
		 * non reentrant.
		 */
		WSABUF winiov[50];
		int winiov_len = 0;
		int i=0;
		DWORD ret=0;

		if (iovcnt>(int)sizeof(winiov))
		{
			return -1;
		}

		for (i=0;i<iovcnt;i++)
		{
			winiov[i].len=iov[i].iov_len;
			winiov[i].buf=iov[i].iov_base;
		}

		if (addr) /* UDP case */
		{
			int addr_size=sizeof(struct sockaddr_in);
			if (WSARecvFrom(fd, winiov, winiov_len, &ret, NULL, (struct sockaddr*)addr, &addr_size, NULL, NULL)!=0)
			{
				return -1;
			}
		}
		else /* TCP case */
		{
			if (WSARecv(fd, winiov, winiov_len, &ret, NULL, NULL, NULL)!=0)
			{
				return -1;
			}
		}

		return (ssize_t)ret;
	}

	ssize_t sock_writev(int fd, const struct iovec *iov, int iovcnt, struct sockaddr* addr)
	{
		/* it should be sufficient.
		 * the dynamically allocation is timecost.
		 * We could use a static WSABUF* winiov but the function would be
		 * non reentrant.
		 */
		WSABUF winiov[50];
		int winiov_len = 0;
		int i=0;
		DWORD ret; /* number of byte read or written */

		if (iovcnt>(int)sizeof(winiov))
		{
			return -1;
		}

		for (i=0;i<iovcnt;i++)
		{
			winiov[i].len=iov[i].iov_len;
			winiov[i].buf=iov[i].iov_base;
		}

		/* UDP case */
		if (addr)
		{
			if (WSASendTo(fd, winiov, winiov_len, &ret, 0, (struct sockaddr*)addr, sizeof(struct sockaddr_in), NULL, NULL)!=0)
			{
				/* error send */
				return -1;
			}
		}
		else  /* TCP case */
		{
			if (WSASend(fd, winiov, winiov_len, &ret, 0, NULL, NULL)!=0)
			{
				/* error send */
				return -1;
			}
		}
		return (ssize_t)ret;
	}

#endif

	void iovec_free_data(struct iovec* iov, uint32_t nb)
	{
		uint32_t i=0;

		for (i=0;i<nb;i++)
		{
			free(iov[i].iov_base);
			iov[i].iov_base=NULL;
		}
	}

	int uid_drop_privileges(uid_t uid_real, gid_t gid_real, char* user_name)
	{
#ifdef _WIN32
		return -1;
#endif
		if (uid_real==0 && gid_real==0) /* we are root or sudoers */
		{
			struct passwd user;
			struct passwd* tmpUser=&user;
			struct passwd* tmp=NULL;
			char buf[1024];

			if (!user_name)
			{
				user_name="nobody";
			}

			if (getpwnam_r(user_name, tmpUser, buf, sizeof(buf), &tmp)==0)
			{
				int ret=-1;
				setegid(user.pw_uid);
				ret=seteuid(user.pw_gid);
				return ret;
			}
			else
			{
				/* cannot lost our privileges */
				return -1;
			}
		}
		else
		{
#ifdef _POSIX_SAVED_IDS
			return seteuid(uid_real);
#else
			/* i.e for *BSD */
			return setreuid(-1, uid_real);
#endif
		}

	}

	int uid_gain_privileges(uid_t uid_eff, gid_t gid_eff)
	{
#ifdef _WIN32
		return -1;
#endif
#ifdef _POSIX_SAVED_IDS
		setegid(gid_eff);
		return seteuid(uid_eff);
#else
		/* i.e for *BSD */
		setregid(-1, gid_eff);
		return setreuid(-1, uid_eff);
#endif
	}

	uint32_t id_generate(void)
	{
#ifndef _WIN32
		struct timespec t;
		clock_gettime(CLOCK_REALTIME, &t);
		return t.tv_nsec & 0xFFFFFFFF;
#else
		return 0xDEADBEEF;
#endif
	}

#ifdef __cplusplus
}
#endif

