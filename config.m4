dnl $Id$
dnl config.m4 for extension rsa

PHP_ARG_WITH(rsa, for rsa support,
[  --with-rsa             Include rsa support])

if test "$PHP_RSA" != "no"; then
  test -z "$PHP_OPENSSL" && PHP_OPENSSL=no
  if test "$PHP_OPENSSL" != "no" || test "$PHP_OPENSSL_DIR" != "no"; then
    dnl Try to find pkg-config
    if test -z "$PKG_CONFIG"; then
      AC_PATH_PROG(PKG_CONFIG, pkg-config, no)
    fi
    dnl If pkg-config is found try using it
    if test -x "$PKG_CONFIG" && $PKG_CONFIG --exists openssl; then
      OPENSSL_INCDIR=`$PKG_CONFIG --variable=includedir openssl`
      PHP_ADD_INCLUDE($OPENSSL_INCDIR)
      RSA_LIBS=`$PKG_CONFIG --libs openssl`
      PHP_EVAL_LIBLINE($RSA_LIBS, RSA_SHARED_LIBADD)
    fi

    AC_DEFINE(HAVE_RSALIB,1,[Enable objective OpenSSL RSA wrapper])
    PHP_SUBST(RSA_SHARED_LIBADD)
    PHP_NEW_EXTENSION(rsa, rsa.c, $ext_shared)
  fi
fi
