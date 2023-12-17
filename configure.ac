# virtio-loopback adapter

AC_PREREQ([2.69])

AC_INIT([virtio-loopback-adapter], [1.0])

AM_INIT_AUTOMAKE([foreign subdir-objects])

AC_CONFIG_SRCDIR([src/vhost_loopback.c])

AC_CONFIG_HEADERS([include/config.h])

AC_CONFIG_MACRO_DIR([m4])

AC_ARG_ENABLE([vhost-rng],
  [AS_HELP_STRING([--enable-vhost-rng], [Enable vhost rng (default is no)])],
  [:],
  [enable_vhost_rng=no])
AM_CONDITIONAL([ENABLE_VHOST_RNG], [test "$enable_vhost_rng" = "yes"])

AC_ARG_ENABLE([vhost-user-rng],
  [AS_HELP_STRING([--enable-vhost-user-rng], [Enable vhost user rng (default is no)])],
  [:],
  [enable_vhost_user_rng=no])
AM_CONDITIONAL([ENABLE_VHOST_USER_RNG], [test "$enable_vhost_user_rng" = "yes"])

AC_ARG_ENABLE([vhost-user-blk],
  [AS_HELP_STRING([--enable-vhost-user-blk], [Enable vhost user blk (default is no)])],
  [:],
  [enable_vhost_user_blk=no])
AM_CONDITIONAL([ENABLE_VHOST_USER_BLK], [test "$enable_vhost_user_blk" = "yes"])

AC_ARG_ENABLE([vhost-user-input],
  [AS_HELP_STRING([--enable-vhost-user-input], [Enable vhost user input (default is no)])],
  [:],
  [enable_vhost_user_input=no])
AM_CONDITIONAL([ENABLE_VHOST_USER_INPUT], [test "$enable_vhost_user_input" = "yes"])

AC_ARG_ENABLE([vhost-user-gpio],
  [AS_HELP_STRING([--enable-vhost-user-gpio], [Enable vhost user gpio (default is no)])],
  [:],
  [enable_vhost_user_gpio=no])
AM_CONDITIONAL([ENABLE_VHOST_USER_GPIO], [test "$enable_vhost_user_gpio" = "yes"])

AC_ARG_ENABLE([vhost-user-sound],
  [AS_HELP_STRING([--enable-vhost-user-sound], [Enable vhost user sound (default is yes)])],
  [:],
  [enable_vhost_user_sound=yes])
AM_CONDITIONAL([ENABLE_VHOST_USER_SOUND], [test "$enable_vhost_user_sound" = "yes"])

AC_ARG_ENABLE([address-sanitizer],
  [AS_HELP_STRING([--enable-address-sanitizer], [Enable address sanitizer in build time (for debug, default is no)])],
  [:],
  [enable_address_sanitizer=no])
AM_CONDITIONAL([ENABLE_ADDRESS_SANITIZER], [test "$enable_address_sanitizer" = "yes"])

AC_ARG_ENABLE([gcov],
  [AS_HELP_STRING([--enable-gcov], [Enable gcov in build time (for debug, default is no)])],
  [:],
  [enable_gcov=no])
AM_CONDITIONAL([ENABLE_GCOV], [test "$enable_gcov" = "yes"])

AC_ARG_ENABLE([debug],
  [AS_HELP_STRING([--enable-debug], [Enable debug (default is no)])],
  [:],
  [enable_printfdebug=no])
AM_CONDITIONAL([ENABLE_DEBUG], [test "$enable_debug" = "yes"])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL

AC_DISABLE_STATIC

# Checks for libraries.
LT_INIT
AM_PROG_LIBTOOL 


# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_CONFIG_FILES([Makefile
				src/Makefile ])
AC_OUTPUT

