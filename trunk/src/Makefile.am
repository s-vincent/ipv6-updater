AM_CFLAGS = -std=c99 -Wall -W -pedantic -D_POSIX_C_SOURCE=200112L -Wstrict-prototypes -Wredundant-decls -Waggregate-return

INCLUDES = -I.
bin_PROGRAMS = ipv6-updater
noinst_HEADERS = dbg.h util.h conf.h util_sys.h os.h

ipv6_updater_SOURCES = main.c dbg.c util_sys.c util.c conf.c 
#ipv6_updater_LDADD = -lconfuse
