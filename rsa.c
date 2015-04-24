/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2015 Jakub Zelenka                                |
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "zend_exceptions.h"
#include "ext/standard/info.h"
#include "php_rsa.h"

#include <openssl/evp.h>

ZEND_DECLARE_MODULE_GLOBALS(rsa)

/* {{{ rsa_functions[] */
static const zend_function_entry rsa_functions[] = {
	PHP_FE_END
};
/* }}} */

/* {{{ rsa_module_entry
 */
zend_module_entry rsa_module_entry = {
	STANDARD_MODULE_HEADER,
	"rsa",
	rsa_functions,
	PHP_MINIT(rsa),
	PHP_MSHUTDOWN(rsa),
	NULL,
	NULL,
	PHP_MINFO(rsa),
	PHP_RSA_VERSION,
	PHP_MODULE_GLOBALS(rsa),
	PHP_GINIT(rsa),
	NULL,
	NULL,
	STANDARD_MODULE_PROPERTIES_EX
};
/* }}} */

#ifdef COMPILE_DL_CRYPTO
ZEND_GET_MODULE(rsa)
#endif

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(rsa)
{
	zend_class_entry ce;
	
	/* Init OpenSSL algorithms */
	OpenSSL_add_all_algorithms();

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_GINIT_FUNCTION
*/
PHP_GINIT_FUNCTION(rsa)
{
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(rsa)
{
	EVP_cleanup();
	
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(rsa)
{
	php_info_print_table_start();
	php_info_print_table_row(2, "RSA Support", "enabled");
	php_info_print_table_row(2, "RSA Version", PHP_RSA_VERSION);
	php_info_print_table_row(2, "OpenSSL Library Version", SSLeay_version(SSLEAY_VERSION));
	php_info_print_table_row(2, "OpenSSL Header Version", OPENSSL_VERSION_TEXT);
	php_info_print_table_end();
}
/* }}} */


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
