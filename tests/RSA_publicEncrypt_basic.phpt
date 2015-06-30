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

list($rsa1, $ctext1_ex) = rsa_test_key1();
list($rsa2, $ctext2_ex) = rsa_test_key2();
list($rsa3, $ctext3_ex) = rsa_test_key3();

// test input exceptions
try {
	$rsa1->publicEncrypt(str_repeat('x', 1024));
} catch (RSAException $e) {
	echo $e->getCode() === RSAException::PUB_ENCRYPT_INPUT_LONG ? "INPUT LONG\n" : "BAD CODE\n";
}

$ptext_ex = pack("H*" , "54859b342c49ea2a");

// test padding exception
try {
	$rsa1->publicEncrypt($ptext_ex, RSA::PADDING_X931);
} catch (RSAException $e) {
	echo $e->getCode() === RSAException::INVALID_PADDING ? "INVALID PADDING\n" : "BAD CODE\n";
}

// key 1 test
function rsa_test_public_encrypt($i, $rsa, $ptext_ex, $ctext_ex) {
	$ctext1_pkcs1_1_5 = $rsa->publicEncrypt($ptext_ex, RSA::PADDING_PKCS1);

	if (strlen($ctext1_pkcs1_1_5) === strlen($ctext_ex)) {
		echo "KEY $i: PKCS#1 v1.5 encryption ok\n";
	} else {
		echo "KEY $i: PKCS#1 v1.5 encryption failed\n";
	}

	$ctext1_pkcs1_oaep = $rsa->publicEncrypt($ptext_ex, RSA::PADDING_OAEP);

	if (strlen($ctext1_pkcs1_oaep) === strlen($ctext_ex)) {
		echo "KEY $i: OAEP encryption ok\n";
	} else {
		echo "KEY $i: OAEP encryption failed\n";
	}
}

rsa_test_public_encrypt(1, $rsa1, $ptext_ex, $ctext1_ex);
rsa_test_public_encrypt(2, $rsa2, $ptext_ex, $ctext2_ex);
rsa_test_public_encrypt(3, $rsa3, $ptext_ex, $ctext3_ex);

?>
--EXPECT--
INPUT LONG
INVALID PADDING
KEY 1: PKCS#1 v1.5 encryption ok
KEY 1: OAEP encryption ok
KEY 2: PKCS#1 v1.5 encryption ok
KEY 2: OAEP encryption ok
KEY 3: PKCS#1 v1.5 encryption ok
KEY 3: OAEP encryption ok
