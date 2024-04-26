#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([IOTsec], [1.0], [dvijaymanohar@gmail.com])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AC_CONFIG_MACRO_DIRS([m4])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AM_PROG_AR

AC_CHECK_LIB([DOXYGEN], [doxygen], [gnutls], [gnutls_check_version], [], [AC_MSG_ERROR([libgnutls not found])])

# Check for Doxygen
if test -z "$DOXYGEN";
   then AC_MSG_WARN([Doxygen not found - continuing without Doxygen support])
fi

AM_CONDITIONAL([HAVE_DOXYGEN],
[test -n "$DOXYGEN"])AM_COND_IF([HAVE_DOXYGEN], [AC_CONFIG_FILES([doc/Doxyfile])])

LT_INIT
AC_CONFIG_HEADERS([config.h])


AC_CONFIG_FILES([Makefile 
                 lib/Makefile
                 Doxyfile])

AC_OUTPUT
