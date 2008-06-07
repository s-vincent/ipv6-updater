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
 * \file util_sys.h
 * \brief Some system function.
 * \author Sebastien Vincent
 */

#ifndef UTIL_SYS_H
#define UTIL_SYS_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>

#ifndef _WIN32
#include <sys/uio.h>
#else
#include <winsock2.h>
#include <windows.h>
#endif

#ifndef _MSC_VER
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#else
/* replace stdint.h type for MS Windows*/
typedef __int8 int8_t;
typedef unsigned __int8 uint8_t;
typedef __int16 int16_t;
typedef unsigned __int16 uint16_t;
typedef __int32 int32_t;
typedef unsigned __int32 uint32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;
typedef int pid_t;
typedef int mode_t;
#define ssize_t int
#define size_t unsigned int
#endif

/**
 * \def MAX
 * \brief Maximum number of the two arguments.
 */
#define	MAX(a, b) ((a)>(b)?(a):(b));

/**
 * \def MIN
 * \brief Minimum number of the two arguments.
 */
#define	MIN(a, b) ((a)<(b)?(a):(b))

#ifdef _WIN32
/**
 * \struct iovec
 * \brief iovector structure for win32
 */
typedef struct iovec
{
	void* iov_base; /**< Pointer on data */
	size_t iov_len; /**< Size of data */
}iovec;

/**
 * \brief The writev() function for win32 socket.
 * \param fd the socket descriptor to write the data
 * \param iov the iovector which contains the data
 * \param iovcnt number of element that should be written
 * \param addr source address to send with UDP, set to NULL if you want to send with TCP
 * \return number of bytes written or -1 if error
 * \warning this function work only with socket!
 * \warning this function supports only AF_INET protocol
 * \todo implements AF_INET6 support
 */
ssize_t sock_writev(int fd, const struct iovec *iov, int iovcnt, struct sockaddr* addr);

/**
 * \brief The readv() function for win32 socket.
 * \param fd the socket descriptor to read the data
 * \param iov the iovector to store the data
 * \param iovcnt number of element that should be filled
 * \param addr if not NULL it considers using a UDP socket,
 * otherwise it considers using a TCP one
 * \return number of bytes read or -1 if error
 * \warning this function work only with socket!
 * \warning this function supports only AF_INET protocol
 * \todo implements AF_INET6 support
 */
ssize_t sock_readv(int fd, const struct iovec *iov, int iovcnt, struct sockaddr* addr);
#endif

#ifdef __cplusplus
extern "C"
{
#endif

	/**
	 * \brief Sleep for usec microseconds.
	 * \param usec number of microseconds
	 * \return 0 if success, -1 otherwise
	 */
	int msleep(unsigned long usec);

	/**
	 * \brief The getdtablesize() function from glibc does not compile in ANSI.
	 * \return max open files for a process
	 */
	int get_dtablesize(void);

	/**
	 * \brief Return if host machine is big endian.
	 * \return 1 if big endian
	 */
	int is_big_endian(void);

	/**
	 * \brief Return if host machine is little endian.
	 * \return 1 if little endian, 0 otherwise
	 */
	int is_little_endian(void);

	/**
	 * \brief Return the error which correspond to errnum.
	 * \param errnum error number (i.e errno)
	 * \param buf a buffer
	 * \param buflen size of buffer
	 * \return pointer on buf
	 * \note This function use strerror_r if available, and assume strerror() is reentrant on systems which do not have strerror_r().
	 * \warning If you do a multithreaded program, be sure strerror_r() is available or strerror() is reentrant on your system.
	 */
	char* get_error(int errnum, char* buf, size_t buflen);

	/**
	 * \brief Go in daemon mode.
	 * \param dir change directory to this, default is /tmp.
	 * \param mask to fix permission : mask & 0777, default is 0.
	 * \return
	 *  Father : -1 if error, return pid if success\n
	 *  Daemon : -1 if cannot chdir into dir, 0 otherwise
	 */
	pid_t go_daemon(char* dir, mode_t mask);

	/**
	 * \brief Free elements of an iovec array.
	 * It does not freed the array (if allocated).
	 * \param iov the iovec array
	 * \param nb number of elements
	 */
	void iovec_free_data(struct iovec* iov, uint32_t nb);

	/**
	 * \brief Generate an unique id based on the current nanosecond.
	 *\return unique 32 bits id
	 */
	uint32_t id_generate(void);

	/**
	 * \brief Drop our privileges.
	 * If the program is executed by root or sudoers,
	 * We change our privileges to those of the user_name account.
	 * If the program is setuid root, we change the UID/GID to
	 * those of the function parameters.
	 * \param uid_real the real UID of the user
	 * \param gid_real the real GID of the user
	 * \param user_name user name of the account we want to switch.
	 * \return 0 if success, -1 otherwise
	 * \warning Should work on POSIX and *BSD systems.
	 */
	int uid_drop_privileges(uid_t uid_real, gid_t gid_real, char* user_name);

	/**
	 * \brief Gain our lost privileges.
	 * \param uid_eff the effective UID of the user
	 * \param gid_eff the effective GID of the user
	 * \return 0 if success, -1 otherwise
	 * \warning Should work on POSIX and *BSD systems.
	 */
	int uid_gain_privileges(uid_t uid_eff, gid_t gid_eff);

	/**
	 * \brief Encode string for HTTP request.
	 * \param str string to encode.
	 * \return encoding string or NULL if problem.
	 * \warning The caller must free the return value.
	 */
	char* encode_http_string(char* str);

#ifndef s_strncpy
	/**
	 * \def s_strncpy
	 * Secure version of strncpy.
	 *
	 * \param dest destination buffer
	 * \param src source buffer to copy
	 * \param n maximum size to copy
	 * \warning It does not return a value (like strncpy does).
	 */
#define s_strncpy(dest, src, n) \
	do{ strncpy((dest), (src), (n)-1); dest[n-1]=0x00; }while(0);
#endif

#if __STDC_VERSION__ >= 199901L /* C99 */
#ifndef s_snprintf
	/**
	 * \def s_snprintf
	 * \brief Secure version of snprintf.
	 * \param str buffer to copy
	 * \param size maximum size to copy
	 * \param format the format (see printf)
	 * \param ... a list of argument
	 * \warning It does not return a value (like snprintf does).
	 * \warning The call must have extra arguments (at least one),
	 * - s_snprintf(str, sizeof(str), "plop") is not good.
	 * - s_snprintf(str, sizeof(str), "plop %d", 32) is good.
	 * - s_snprintf(str, sizeof(str), "plop %s %d", str2, (int)nb) is good.
	 */
#define s_snprintf(str, size, format, ...) \
	do{ snprintf(str, size-1, format,  __VA_ARGS__); str[size-1]=0x00; }while(0);
#endif
#endif

#ifdef __STRICT_ANSI__
	/**
	 * \brief strdup-style.\n
	 * strdup non-C89 (ANSI) function.
	 * \param str string to duplicate
	 * \return pointer on duplicate string
	 * \warning Do not forget to freed the pointer
	 * \author Sebastien Vincent
	 */
	char* strdup(char* str);
#endif

#ifdef __cplusplus
}
#endif

#endif /* UTIL_SYS_H */

