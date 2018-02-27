#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([aws_c], [0.1.0], [BUG-REPORT-ADDRESS])
AM_INIT_AUTOMAKE([-Wall -Werror])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC_STDC

# Checks for libraries.
PKG_CHECK_MODULES(CURL, libcurl)
PKG_CHECK_MODULES(OPENSSL, openssl)
PKG_CHECK_MODULES(DISH, libdish)

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
