include ../../../Make.vars 

CONFIGURE_DEPENCIES = $(srcdir)/Makefile.am

EXTRA_DIST = \
	meta.json

pkglib_LTLIBRARIES =		\
	hwdbcontroller.la \
	monitorswitch.la	

hwdbcontroller_la_CPPFLAGS = $(AM_CPPFLAGS) \
-I $(top_srcdir)/src/nox -I $(top_srcdir)/src/nox/coreapps/

hwdbcontroller_la_SOURCES = control.hh control.cc

hwdbcontroller_la_LDFLAGS = -module -export-dynamic -lhwdb
monitorswitch_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/src/nox -I$(top_srcdir)/src/nox/netapps -I /usr/include/hwdb/
monitorswitch_la_SOURCES = monitorswitch.cc monitorswitch.hh
monitorswitch_la_LDFLAGS = -module -export-dynamic  -lnl -lhwdb

NOX_RUNTIMEFILES = meta.json

all-local: nox-all-local
clean-local: nox-clean-local 
install-exec-hook: nox-install-local
