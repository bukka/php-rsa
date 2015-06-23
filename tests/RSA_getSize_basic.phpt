--TEST--
RSA::getSize basic usage.
--SKIPIF--
<?php
if (!extension_loaded('rsa'))
	die("Skip: RSA extension not loaded");
?>
--FILE--
<?php
$rsa = new RSA();
$rsa->generateKey(1024, 65537);

var_dump($rsa->getSize());

?>
--EXPECTF--
int(128)
