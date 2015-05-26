/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 2015 Jakub Zelenka                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Jakub Zelenka <bukka@php.net>                                |
  +----------------------------------------------------------------------+
*/

#ifndef PHP_RSA_H
#define PHP_RSA_H

extern zend_module_entry rsa_module_entry;
#define phpext_rsa_ptr &rsa_module_entry

#ifdef PHP_WIN32
#	define PHP_RSA_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#	define PHP_RSA_API __attribute__ ((visibility("default")))
#else
#	define PHP_RSA_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

/* Crypto version */
#define PHP_RSA_VERSION "0.1.0"

/* PHP Compatibility layer */
#include "phpc/phpc.h"

/* RSA param encoding */
typedef enum {
	PHP_RSA_ENC_AUTO,
	PHP_RSA_ENC_HEX,
	PHP_RSA_ENC_DEC
} php_rsa_encoding;

/* GLOBALS */
ZEND_BEGIN_MODULE_GLOBALS(rsa)
	php_rsa_encoding encoding;
ZEND_END_MODULE_GLOBALS(rsa)

#ifdef ZTS
# define PHP_RSA_G(v) TSRMG(rsa_globals_id, zend_rsa_globals *, v)
#else
# define PHP_RSA_G(v) (rsa_globals.v)
#endif


/* MODULE FUNCTIONS */

PHP_MINIT_FUNCTION(rsa);
PHP_GINIT_FUNCTION(rsa);
PHP_MSHUTDOWN_FUNCTION(rsa);
PHP_MINFO_FUNCTION(rsa);

/* methods */
PHP_METHOD(RSA, __construct);
PHP_METHOD(RSA, setEncoding);
PHP_METHOD(RSA, getEncoding);
PHP_METHOD(RSA, setN);
PHP_METHOD(RSA, setE);
PHP_METHOD(RSA, setD);
PHP_METHOD(RSA, setP);
PHP_METHOD(RSA, setQ);
PHP_METHOD(RSA, setDMP1);
PHP_METHOD(RSA, setDMQ1);
PHP_METHOD(RSA, setIQMP);
PHP_METHOD(RSA, getN);
PHP_METHOD(RSA, getE);
PHP_METHOD(RSA, getD);
PHP_METHOD(RSA, getP);
PHP_METHOD(RSA, getQ);
PHP_METHOD(RSA, getDMP1);
PHP_METHOD(RSA, getDMQ1);
PHP_METHOD(RSA, getIQMP);
PHP_METHOD(RSA, generateKey);
PHP_METHOD(RSA, getSize);
PHP_METHOD(RSA, publicEncrypt);
PHP_METHOD(RSA, privateDecrypt);

#endif	/* PHP_RSA_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
