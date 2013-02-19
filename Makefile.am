SUBDIRS = tests
ACLOCAL_AMFLAGS = -I m4

ivartjincludedir = $(includedir)/ivartj
ivartjinclude_HEADERS = crypto.h

lib_LTLIBRARIES = libivartjcrypto.la
libivartjcrypto_la_SOURCES = crypto.h crypto.c

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = ivartjcrypto.pc
