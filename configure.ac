#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([gateway], [1.0], [txgbuaa@gmail.com])
AC_CONFIG_SRCDIR([src])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AC_PROG_RANLIB

AM_INIT_AUTOMAKE([foreign -Wall])

# Checks for programs.
${CXXFLAGS="-g -O0"}
AC_PROG_CXX
AC_PROG_CC
AC_PROG_CPP

AX_CXX_COMPILE_STDCXX_0X
if test "$ax_cv_cxx_compile_cxx0x_native" = "yes"; then
	true
elif test "$ax_cv_cxx_compile_cxx0x_gxx" = "yes"; then
	CXXFLAGS="$CXXFLAGS -std=gnu++0x"
elif test "$ax_cv_cxx_compile_cxx0x_cxx" = "yes"; then
	CXXFLAGS="$CXXFLAGS -std=c++0x"
else
    AC_MSG_ERROR([no support for C++0x])
fi

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h limits.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_SIZE_T

# Checks for library functions.
AC_CHECK_FUNCS([bzero gethostbyname gettimeofday inet_ntoa memset select socket strcasecmp strrchr])

#AX_TLS([], AC_MSG_ERROR([thread-local storage is not supported]))
CHECK_NDEBUG
CHECK_PROFILING
CHECK_COVERAGE

# Checks for Boost libraries
AX_BOOST_BASE([1.40])
AX_BOOST_FILESYSTEM
AX_BOOST_SYSTEM
AX_BOOST_THREAD

AC_CONFIG_FILES([ 
Makefile
src/Makefile
src/include/Makefile
src/lib/Makefile
])  
AC_OUTPUT
