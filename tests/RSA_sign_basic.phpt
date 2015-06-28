--TEST--
RSA::sign basic usage.
--SKIPIF--
<?php
if (!extension_loaded('rsa'))
	die("Skip: RSA extension not loaded");
?>
--FILE--
<?php
require_once dirname(__FILE__) . "/keys.inc";

$message = "test message";

function rsa_test_sign($i, $sig) {
	echo "RSA $i\n" . chunk_split(bin2hex($sig), 100, "\n") . "\n";
}

list($rsa1, $ctext1_ex) = rsa_test_key1();
rsa_test_sign(1, $rsa1->sign($message));

list($rsa2, $ctext1_ex) = rsa_test_key2();
rsa_test_sign(2, $rsa2->sign($message, RSA::NID_SHA256));

list($rsa3, $ctext1_ex) = rsa_test_key3();
rsa_test_sign(3, $rsa3->sign($message, RSA::NID_SHA512));

?>
--EXPECT--
RSA 1
98d436d95d1a9167ba647c35151b6c29fda30aa35966adbe45383dd6cec52a7917d5df90edcc3bf40c3287776d65b020bc64
2d80cb0235a6d528aaa5e3947865

RSA 2
84f3fd4f701f8616632b0cd7c19a8cc12fa5450a839868517f8b89cca7c2e67a54ec5f7ec780b7d227decd2d528ac34d8e2c

RSA 3
5fc5445a7040ffea154c4a6ba77d05c50366ee79770789e084c5fb5b51d46c6b9e8e143b0140bf87ef96c7d1c13bb71fb90a
2f86a173fe770be0d7d8e1ff13bae57870b4b2de8d67514d9731a5b1ee4c37c06d587bd6d6fd180339602af4a0da58626cb9
f3c8212de23e06982765f7986708d82c7d43b74302efabaa6c8a0595
