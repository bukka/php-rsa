--TEST--
RSA::getEncoding basic usage.
--SKIPIF--
<?php
if (!extension_loaded('rsa'))
	die("Skip: RSA extension not loaded");
?>
--FILE--
<?php
$rsa = new RSA();
var_dump($rsa->getEncoding() === RSA::ENCODING_AUTO);
?>
--EXPECT--
bool(true)