--TEST--
RSA::verify basic usage.
--SKIPIF--
<?php
if (!extension_loaded('rsa'))
	die("Skip: RSA extension not loaded");
?>
--FILE--
<?php
require_once dirname(__FILE__) . "/keys.inc";

$message = "test message";


echo "RSA 1\n";
$sig1 = '98d436d95d1a9167ba647c35151b6c29fda30aa35966adbe45' .
		'383dd6cec52a7917d5df90edcc3bf40c3287776d65b020bc64' .
		'2d80cb0235a6d528aaa5e3947865';
list($rsa1, $ctext1_ex) = rsa_test_key1();
var_dump($rsa1->verify($message, pack("H*", $sig1)));

echo "RSA 2\n";
$sig2 = '84f3fd4f701f8616632b0cd7c19a8cc12fa5450a839868517f' .
		'8b89cca7c2e67a54ec5f7ec780b7d227decd2d528ac34d8e2c';
list($rsa2, $ctext1_ex) = rsa_test_key2();
var_dump($rsa2->verify($message, pack("H*", $sig2), RSA::NID_SHA256));

echo "RSA 3\n";
$sig3 = '5fc5445a7040ffea154c4a6ba77d05c50366ee79770789e084' .
		'c5fb5b51d46c6b9e8e143b0140bf87ef96c7d1c13bb71fb90a' .
		'2f86a173fe770be0d7d8e1ff13bae57870b4b2de8d67514d97' .
		'31a5b1ee4c37c06d587bd6d6fd180339602af4a0da58626cb9' .
		'f3c8212de23e06982765f7986708d82c7d43b74302efabaa6c' .
		'8a0595';
list($rsa3, $ctext1_ex) = rsa_test_key3();
var_dump($rsa3->verify($message, pack("H*", $sig3), RSA::NID_SHA512));

?>
--EXPECT--
RSA 1
bool(true)
RSA 2
bool(true)
RSA 3
bool(true)
