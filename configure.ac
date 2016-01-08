dnl                                             -*- Autoconf -*-
AC_COPYRIGHT([
Copyright (c) 2015, 2016 Genome Research Ltd.
Author: Andrew Whitwham <aw7+github@sanger.ac.uk>

This file is part of tears.

tears is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 3 of the License, or (at your option) any later
version.
This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
details.
You should have received a copy of the GNU General Public License along with
this program. If not, see <http://www.gnu.org/licenses>])

dnl Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([tears], [1.1], [aw7+github@sanger.ac.uk])

AM_INIT_AUTOMAKE([-Wall -Werror foreign])

AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_CC_C_O
AC_LANG([C])

# Checks for header files
AC_CHECK_HEADERS([stdio.h stdlib.h string.h unistd.h stdarg.h], [], [
echo "Missing required header file, giving up."
exit 1
])dnl

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_CHECK_FUNCS([memset strchr strdup strndup strstr], [], [
echo "Required function not found, giving up."
exit 1
])dnl

AC_CHECK_LIB([gssapi_krb5], [gss_acquire_cred])
AC_CHECK_LIB([pthread], [pthread_kill])

dnl Save the original values to restore between tests
CPPFLAGS_ORIG=${CPPFLAGS}
LDFLAGS_ORIG=${LDFLAGS}
LIBS_ORIG=${LIBS}

dnl Look for iRODS
IRODS_HOME=
AC_ARG_WITH([irods],
  [AS_HELP_STRING([--with-irods],
    [Specify the location of a run-in-place iRODS installation (default: /usr/local/lib/irods)])],
  [AS_IF(
    [test "x$with_irods" = "xno"],
      [AC_MSG_FAILURE([iRODS is required to build tears])],
    [test "x$with_irods" = "xyes"],
      [AC_MSG_NOTICE([using default iRODS location])
       IRODS_HOME="/usr/local/lib/irods"
       IS_PACKAGED_INSTALL="no"],
     [IRODS_HOME="$with_irods"
      IS_PACKAGED_INSTALL="no"])],
  [IS_PACKAGED_INSTALL="yes"])
  
AC_SUBST(IRODS_HOME)

dnl Begin iRODS 3.3.x

dnl iRODS 3.3.x supports only run-in-place (RIP) installation.  Its
dnl headers and shared libraries are in non-standard places, which may
dnl be determined relative to IRODS_HOME.
IRODS3_CPPFLAGS=\
"-I${IRODS_HOME}/lib/api/include \
-I${IRODS_HOME}/lib/core/include \
-I${IRODS_HOME}/lib/md5/include \
-I${IRODS_HOME}/lib/sha1/include \
-I${IRODS_HOME}/server/core/include \
-I${IRODS_HOME}/server/drivers/include \
-I${IRODS_HOME}/server/icat/include \
-I${IRODS_HOME}/server/re/include"
IRODS3_LDFLAGS="-L${IRODS_HOME}/lib/core/obj"

CPPFLAGS="$CPPFLAGS_ORIG ${IRODS3_CPPFLAGS}"
LDFLAGS="$LDFLAGS_ORIG ${IRODS3_LDFLAGS}"
LIBS="${LIBS_ORIG}"

HAVE_IRODS3=no

AC_RUN_IFELSE(
  [AC_LANG_PROGRAM([
#include <string.h>
#include <rodsVersion.h>
], [
#if defined (RODS_REL_VERSION)
  return strncmp("rods3.3", RODS_REL_VERSION, 7);
#else
  exit(-1);
#endif
])],
  [ AC_MSG_NOTICE([detected iRODS 3.3.x])
   [HAVE_IRODS3=yes]
   AC_CHECK_LIB([RodsAPIs], [getRodsEnvFileName], [],
     [AC_MSG_ERROR([unable to find the iRODS library libRodsAPIs])])],
    [AC_MSG_ERROR([test iRODS program failed with IRODS_HOME=${IRODS_HOME}])])

AC_CONFIG_SRCDIR([tears.c])
AC_CONFIG_HEADERS([tears_config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

