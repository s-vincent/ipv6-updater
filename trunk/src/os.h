/*
	 Copyright (C) 2006-2008 Sebastien Vincent.

	 Permission to use, copy, modify, and distribute this software for any
	 purpose with or without fee is hereby granted, provided that the above
	 copyright notice and this permission notice appear in all copies.

	 THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
	 REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
	 AND FITNESS. IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
	 INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
	 LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
	 OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
	 PERFORMANCE OF THIS SOFTWARE.
*/

/**
 * \file os.h
 * \brief Macro to know the operating system.
 *
 * UNIX      => Unix-like operating system.\n
 * LINUX     => Linux operating system.\n
 * SUNOS     => Sun operating system.\n
 * MACINTOSH => Macintosh or MacOS operating system.\n
 * WINDOWS   => MS Windows operating system.\n
 * MSDOS     => MS DOS operating system.\n
 *
 * \author Sebastien Vincent
 * \todo Add more OS detection.
 */

#ifndef OS_H
#define OS_H

/**
 * \brief Extract the "MACINTOSH" flag from the compiler.
 */
#if defined(__APPLE__)
#define MACINTOSH
#endif

/**
 * \brief Extract the "SUNOS" flag from the compiler.
 */
#if defined(sun)
#define UNIX
#define SUNOS
#endif


/**
 * \brief Extract the "UNIX" flag from compiler.
 */
#ifdef __linux__
#define UNIX
#define LINUX
#endif

/**
 * \brief Extract the "BSD" flag from compiler.
 */
#if defined(BSD) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#ifndef BSD
#define BSD
#endif
#define UNIX
#endif

/**
 * \brief Extract the "MSDOS" flag from the compiler.
 */
#ifdef __MSDOS__
#define MSDOS
#undef UNIX
#endif

/**
 * \brief Extract the "WINDOWS" flag from the compiler.
 */
#if defined(_Windows) || defined(__WINDOWS__) || \
	defined(__WIN32__) || defined(WIN32) || \
defined(__WINNT__) || defined(__NT__) || \
defined(_WIN32) || defined(_WIN64)
#define WINDOWS
#undef UNIX
#undef MSDOS
#endif


/**
 * \brief Remove the WINDOWS flag when using MACINTOSH.
 */
#ifdef MACINTOSH
#undef WINDOWS
#endif

/**
 * \brief Assume UNIX if not Windows, Macintosh or MSDOS.
 */
#if !defined(WINDOWS) && !defined(MACINTOSH) && !defined(MSDOS)
#define UNIX
#endif

#endif /* OS_H */

