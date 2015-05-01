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
#include <openssl/rsa.h>

ZEND_DECLARE_MODULE_GLOBALS(rsa)

/* {{{ rsa_module_entry
 */
zend_module_entry rsa_module_entry = {
	STANDARD_MODULE_HEADER,
	"rsa",
	NULL,
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

#ifdef COMPILE_DL_RSA
ZEND_GET_MODULE(rsa)
#endif

PHPC_OBJ_STRUCT_BEGIN(rsa)
	RSA *ctx;
PHPC_OBJ_STRUCT_END()

ZEND_BEGIN_ARG_INFO(arginfo_rsa_set_encoding, 0)
ZEND_ARG_INFO(0, encoding)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_rsa_set_value, 0, 0, 1)
ZEND_ARG_INFO(0, value)
ZEND_ARG_INFO(0, encoding)
ZEND_END_ARG_INFO()


static const zend_function_entry php_rsa_object_methods[] = {
	PHP_ME(RSA, __construct,    NULL,                       ZEND_ACC_CTOR|ZEND_ACC_PUBLIC)
	PHP_ME(RSA, setEncoding,    arginfo_rsa_set_encoding,   ZEND_ACC_PUBLIC)
	PHP_ME(RSA, getEncoding,    NULL,                       ZEND_ACC_PUBLIC)
	PHP_ME(RSA, setN,           arginfo_rsa_set_value,      ZEND_ACC_PUBLIC)
	PHP_ME(RSA, setE,           arginfo_rsa_set_value,      ZEND_ACC_PUBLIC)
	PHP_ME(RSA, setD,           arginfo_rsa_set_value,      ZEND_ACC_PUBLIC)
	PHP_ME(RSA, setP,           arginfo_rsa_set_value,      ZEND_ACC_PUBLIC)
	PHP_ME(RSA, setQ,           arginfo_rsa_set_value,      ZEND_ACC_PUBLIC)
	PHPC_FE_END
};

typedef enum {
	PHP_RSA_ERROR_INVALID_HEX_ENC,
	PHP_RSA_ERROR_INVALID_DEC_ENC
} php_rsa_error_code;

/* class entries */
static zend_class_entry *php_rsa_ce;
static zend_class_entry *php_rsa_exception_ce;

/* object handler */
PHPC_OBJ_DEFINE_HANDLER_VAR(rsa);

/* {{{ rsa free object handler */
PHPC_OBJ_HANDLER_FREE(rsa)
{
	PHPC_OBJ_STRUCT_DECLARE_AND_FETCH_FROM_ZOBJ(rsa, intern);
	RSA_free(intern->ctx);
	PHPC_OBJ_HANDLER_FREE_DTOR(intern);
}
/* }}} */

/* {{{ rsa create_ex object helper */
PHPC_OBJ_HANDLER_CREATE_EX(rsa)
{
	PHPC_OBJ_HANDLER_CREATE_EX_INIT();
	PHPC_OBJ_STRUCT_DECLARE(rsa, intern);

	intern = PHPC_OBJ_HANDLER_CREATE_EX_ALLOC(rsa);
	PHPC_OBJ_HANDLER_INIT_CREATE_EX_PROPS(intern);

	/* allocate encode context */
	intern->ctx = RSA_new();

	PHPC_OBJ_HANDLER_CREATE_EX_RETURN(rsa, intern);
}
/* }}} */

/* {{{ rsa create object handler */
PHPC_OBJ_HANDLER_CREATE(rsa)
{
	PHPC_OBJ_HANDLER_CREATE_RETURN(rsa);
}
/* }}} */

/* {{{ rsa clone object handler */
PHPC_OBJ_HANDLER_CLONE(rsa)
{
	PHPC_OBJ_HANDLER_CLONE_INIT();
	PHPC_OBJ_STRUCT_DECLARE(rsa, old_obj);
	PHPC_OBJ_STRUCT_DECLARE(rsa, new_obj);

	old_obj = PHPC_OBJ_FROM_SELF(rsa);
	PHPC_OBJ_HANDLER_CLONE_MEMBERS(rsa, new_obj, old_obj);

	memcpy(new_obj->ctx, old_obj->ctx, sizeof (RSA));

	PHPC_OBJ_HANDLER_CLONE_RETURN(new_obj);
}
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(rsa)
{
	zend_class_entry ce;

	/* Init OpenSSL algorithms */
	OpenSSL_add_all_algorithms();

	/* Register encoding constants */
	REGISTER_LONG_CONSTANT("RSA_ENC_HEX", PHP_RSA_ENC_HEX, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("RSA_ENC_DEC", PHP_RSA_ENC_DEC, CONST_CS | CONST_PERSISTENT);

	/* RSA class */
	INIT_CLASS_ENTRY(ce, "RSA", php_rsa_object_methods);
	PHPC_CLASS_SET_HANDLER_CREATE(ce, rsa);
	php_rsa_ce = PHPC_CLASS_REGISTER(ce);
	PHPC_OBJ_INIT_HANDLERS(rsa);
	PHPC_OBJ_SET_HANDLER_OFFSET(rsa);
	PHPC_OBJ_SET_HANDLER_FREE(rsa);
	PHPC_OBJ_SET_HANDLER_CLONE(rsa);

	/* RSAException class */
	INIT_CLASS_ENTRY(ce, "RSAException", NULL);
	php_rsa_exception_ce = PHPC_CLASS_REGISTER_EX(ce,
			zend_exception_get_default(TSRMLS_C), NULL);

	/* Register RSAException error constant */
	zend_declare_class_constant_long(php_rsa_exception_ce,
			"INVALID_HEX_ENCODING", sizeof("INVALID_HEX_ENCODING") - 1,
			PHP_RSA_ERROR_INVALID_HEX_ENC TSRMLS_CC);
	zend_declare_class_constant_long(php_rsa_exception_ce,
			"INVALID_DEC_ENCODING", sizeof("INVALID_DEC_ENCODING") - 1,
			PHP_RSA_ERROR_INVALID_DEC_ENC TSRMLS_CC);

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_GINIT_FUNCTION
*/
PHP_GINIT_FUNCTION(rsa)
{
	rsa_globals->encoding = PHP_RSA_ENC_HEX;
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

/* {{{ */
static int php_rsa_check_encoding(const char *sval, phpc_str_size_t sval_len,
		php_rsa_encoding encoding TSRMLS_DC)
{
	phpc_str_size_t pos;
	char c;

	for (pos = 0; pos < sval_len; pos++) {
		c = sval[pos];
		if ((c >= '0') && (c <= '9')) {
			continue;
		}
		if (encoding == PHP_RSA_ENC_DEC) {
			zend_throw_exception(php_rsa_exception_ce,
					"The string contains a non-decimal character",
					PHP_RSA_ERROR_INVALID_DEC_ENC TSRMLS_CC);
			return FAILURE;
		}

		if (!((c >= 'a') && (c <= 'f')) && !((c >= 'A') && (c <= 'F'))) {
			zend_throw_exception(php_rsa_exception_ce,
					"The string contains a non-hexadecimal character",
					PHP_RSA_ERROR_INVALID_HEX_ENC TSRMLS_CC);
			return FAILURE;
		}
	}

	return SUCCESS;
}
/* }}} */

/* {{{ */
static int php_rsa_set_value(BIGNUM **bnval, const char *sval, phpc_str_size_t sval_len,
		php_rsa_encoding encoding TSRMLS_DC)
{
	int rc;

	if (php_rsa_check_encoding(sval, sval_len, encoding TSRMLS_CC) == FAILURE) {
		return FAILURE;
	}

	switch (encoding) {
		case PHP_RSA_ENC_DEC:
			rc = BN_dec2bn(bnval, sval);
			break;

		default:
			rc = BN_hex2bn(bnval, sval);
	}

	return rc != 0 ? SUCCESS : FAILURE;
}
/* }}} */

/* {{{ */
static php_rsa_encoding php_rsa_long_to_encoding(phpc_long_t encoding_value)
{
	if (encoding_value == PHP_RSA_ENC_DEC) {
		return PHP_RSA_ENC_DEC;
	} else {
		return PHP_RSA_ENC_HEX;
	}
}
/* }}} */

/* {{{ */
static void php_rsa_set_value_method(INTERNAL_FUNCTION_PARAMETERS, BIGNUM **bnval)
{
	char *sval;
	phpc_str_size_t sval_len;
	phpc_long_t encoding_value = PHP_RSA_ENC_HEX;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|l",
			&sval, &sval_len, &encoding_value) == FAILURE) {
		return;
	}

	php_rsa_set_value(bnval, sval, sval_len,
			php_rsa_long_to_encoding(encoding_value) TSRMLS_CC);

	RETURN_NULL();
}
/* }}} */

/* {{{ proto void RSA::__Construct() */
PHP_METHOD(RSA, __construct)
{
}
/* }}} */

/* {{{ proto void RSA::setEncoding() */
PHP_METHOD(RSA, setEncoding)
{
	phpc_long_t encoding_value;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l",
			&encoding_value) == FAILURE) {
		return;
	}

	PHP_RSA_G(encoding) = php_rsa_long_to_encoding(encoding_value);
}
/* }}} */

/* {{{ proto int RSA::getEncoding() */
PHP_METHOD(RSA, getEncoding)
{
	if (zend_parse_parameters_none()  == FAILURE) {
		return;
	}

	RETURN_LONG((phpc_long_t) PHP_RSA_G(encoding));
}
/* }}} */

#define PHP_RSA_METHOD_VALUE_SETTER(name) \
	PHPC_THIS_DECLARE_AND_FETCH(rsa); \
	php_rsa_set_value_method(INTERNAL_FUNCTION_PARAM_PASSTHRU, &PHPC_THIS->ctx->name);

/* {{{ proto void RSA::setN($value, $format = RSA_ENC_HEX) */
PHP_METHOD(RSA, setN)
{
	PHP_RSA_METHOD_VALUE_SETTER(n);
}
/* }}} */

/* {{{ proto void RSA::setE($value, $format = RSA_ENC_HEX) */
PHP_METHOD(RSA, setE)
{
	PHP_RSA_METHOD_VALUE_SETTER(e);
}
/* }}} */

/* {{{ proto void RSA::setD($value, $format = RSA_ENC_HEX) */
PHP_METHOD(RSA, setD)
{
	PHP_RSA_METHOD_VALUE_SETTER(d);
}
/* }}} */

/* {{{ proto void RSA::setP($value, $format = RSA_ENC_HEX) */
PHP_METHOD(RSA, setP)
{
	PHP_RSA_METHOD_VALUE_SETTER(p);
}
/* }}} */

/* {{{ proto void RSA::setQ($value, $format = RSA_ENC_HEX) */
PHP_METHOD(RSA, setQ)
{
	PHP_RSA_METHOD_VALUE_SETTER(q);
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
