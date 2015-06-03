--TEST--
RSA::publicEncrypt basic usage.
--SKIPIF--
<?php
if (!extension_loaded('rsa'))
    die("Skip: RSA extension not loaded");
?>
--FILE--
<?php
require_once dirname(__FILE__) . "/keys.inc";

list($rsa1, $ctext1) = rsa_test_key1();

// test exceptions
try {
    $rsa1->publicEncrypt(str_repeat('x', 1024));
} catch (RSAException $e) {
    echo $e->getCode() === RSAException::PUB_ENCRYPT_INPUT_LONG ? "INPUT LONG\n" : "BAD CODE\n";
}
?>
--EXPECT--
INPUT LONG