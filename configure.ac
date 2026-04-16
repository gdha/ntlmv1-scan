#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([ntlmv1scan], [1.0], [gratien.dhaese at gmail.com], [],
        [https://github.com/gdha/ntlmv1-scan])
AC_CONFIG_SRCDIR([ntlmv1scan.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])

AC_CHECK_PROGS([ASCIIDOC], [asciidoc], [])
AC_CHECK_PROGS([XMLTO], [xmlto], [])
AM_CONDITIONAL([USE_ASCIIDOC], [test -n "$ASCIIDOC" && test -n "$XMLTO"])

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h unistd.h errno.h])
AC_CHECK_HEADERS([arpa/inet.h linux/if_ether.h linux/if_packet.h])
AC_CHECK_HEADERS([net/if.h netinet/ip.h netinet/tcp.h])
AC_CHECK_HEADERS([sys/ioctl.h sys/socket.h sys/time.h time.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([gettimeofday localtime_r memset strftime strtoul strncpy])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

echo "
  ntlmv1scan..: version $PACKAGE_VERSION
  Prefix......: $prefix
  C compiler..: $CC $CFLAGS $CPPFLAGS

  Now type 'make' to build.
"
