ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST =
CLEANFILES =

lib_LTLIBRARIES = libxdelta3.la

libxdelta3_la_SOURCES = \
    xdelta3.c \
    xdelta3-blkcache.h \
    xdelta3-decode.h \
    xdelta3-djw.h \
    xdelta3-hash.h \
    xdelta3-internal.h \
    xdelta3-list.h \
    xdelta3-second.h

# Note: for extra sanity checks, enable -Wconversion. Note there
# are a lot of false positives.
WFLAGS = -Wall -Wshadow -fno-builtin -Wextra -Wsign-compare -Wextra \
	 -Wno-unused-parameter -Wno-unused-function -Wno-implicit-fallthrough

libxdelta3_la_CFLAGS = $(WFLAGS) -pedantic -std=c99

libxdelta3_la_CFLAGS += "-DSECONDARY_DJW=1"

if HAVE_LZMA
    libxdelta3_la_CFLAGS += -DSECONDARY_LZMA=1
    libxdelta3_la_SOURCES += xdelta3-lzma.h
endif

if HAVE_FGK
    libxdelta3_la_CFLAGS += -DSECONDARY_FGK=1
    libxdelta3_la_SOURCES += xdelta3-fgk.h
endif

if NO_ENCODER
    libxdelta3_la_CFLAGS += -DXD3_ENCODER=0
endif

nobase_include_HEADERS = \
    xdelta3-config.h \
    xdelta3.h

libxdelta3_la_LDFLAGS = -no-undefined -version-info 3:12:0

