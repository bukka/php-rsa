--TEST--
RSA::setE basic usage.
--SKIPIF--
<?php
if (!extension_loaded('rsa'))
	die("Skip: RSA extension not loaded");
?>
--FILE--
<?php
$rsa = new RSA();
$rsa->setE("0x10001");
var_dump($rsa->getE(RSA::ENCODING_HEX));
var_dump($rsa->getE(RSA::ENCODING_DEC));
?>
--EXPECT--
string(6) "010001"
string(5) "65537"