AC_INIT([OCI Systemd Hook], 0.1)
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AC_PROG_CC

PKG_CHECK_MODULES([YAJL], [yajl >= 2.0.0])
PKG_CHECK_MODULES([SELINUX], [libselinux >= 2.0.0])

AC_CONFIG_FILES(Makefile)
AC_OUTPUT
