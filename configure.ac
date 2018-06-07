AC_INIT([socksv5], [0.0.1], [jcodagno@itba.edu.ar])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

# se declara lo mas arriba posible para que los chequeos 
# lo usen. En particular --std es lo que importa
CFLAGS="-g --std=c11 -pedantic -pedantic-errors -Wall -Wextra -Werror -Wno-unused-parameter -Wno-implicit-fallthrough -D_POSIX_C_SOURCE=200112L $CFLAGS"

# Checks for programs.
AC_PROG_CC
AM_PROG_AR
#AC_PROG_LIBTOOL

# Checks for header files.
AC_HEADER_ASSERT
AC_HEADER_STDC

# Checks for typedefs, structures, and compiler characteristics.
#AC_C_CONST
#AC_TYPE_SIZE_T

# Checks for library functions.
#AC_FUNC_FORK
#AC_FUNC_MALLOC
#AC_FUNC_REALLOC
#AC_TYPE_SIGNAL
#AC_FUNC_STRTOD
#AC_FUNC_VPRINTF
AC_CHECK_FUNCS([gethostbyname memset socket connect inet_ntoa])
AC_SEARCH_LIBS([pthread_create], [pthread], [
  CFLAGS="-pthread ${CFLAGS}"
  LDFLAGS="-pthread ${LDFLAGS}"
 ], [AC_MSG_ERROR([unable to find pthread])])
PKG_CHECK_MODULES([CHECK], [check >= 0.9.4])

AC_CONFIG_HEADERS([config.h])

AC_CONFIG_FILES([
 Makefile
 src/Makefile
])
AC_OUTPUT
