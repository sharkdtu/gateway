include Make.vars

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = include lib

bin_PROGRAMS = gateway 

gateway_SOURCES = include/gateway.hh   \
                  core/gateway.cc      \
                  gateway_main.cc

gateway_CPPFLAGS = $(AM_CPPFLAGS)

gateway_LDFLAGS = $(AM_LDFLAGS)

gateway_LDADD = $(LDADD)                     \
                $(builddir)/lib/libgateway.a \
				$(BOOST_THREAD_LIB)          \
				$(BOOST_FILESYSTEM_LIB)      \
				$(BOOST_SYSTEM_LIB)          

