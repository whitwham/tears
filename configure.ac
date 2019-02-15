dnl                                             -*- Autoconf -*-
AC_COPYRIGHT([
Copyright (c) 2015-2016, 2018-2019 Genome Research Ltd.
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

AC_INIT([tears], [1.2.5], [aw7+github@sanger.ac.uk], [tears], [https://github.com/whitwham/tears])
AC_USE_SYSTEM_EXTENSIONS

AM_INIT_AUTOMAKE([-Wall foreign])

AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_CC_C_O
AC_PROG_CXX

AC_LANG([C])

AC_CONFIG_MACRO_DIR([m4])

AC_ARG_ENABLE(debug,
    AS_HELP_STRING([--enable-debug],[use compiler debug flags (default no)]),
    [debug=${enableval}],[debug=no])
AC_ARG_ENABLE(profile,
    AS_HELP_STRING([--enable-profile],[use compiler profiling flags (default no)]),
    [profile=${enableval}],[profile=no])
AC_ARG_ENABLE(optimise,
    AS_HELP_STRING([--enable-optimise],[use highest optimisation flag (default no)]),
    [optimise=${enableval}],[optimise=no])

if test "${debug}" = "yes" ; then
    CFLAGS="-g -O0"
    CPPFLAGS="-Wall"
elif test "${profile}" = "yes" ; then
    CFLAGS="-g -pg"
elif test "${optimise}" = "yes" ; then
    CFLAGS="-O3"
fi

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

AX_WITH_IRODS

AC_CONFIG_SRCDIR([tears.c])
AC_CONFIG_HEADERS([tears_config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

