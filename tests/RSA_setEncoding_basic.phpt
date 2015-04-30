--TEST--
RSA::setEncoding basic usage.
--SKIPIF--
<?php
if (!extension_loaded('rsa'))
    die("Skip: RSA extension not loaded");
?>
--FILE--
<?php
$rsa = new RSA();
$rsa->setEncoding(RSA_ENC_DEC);
var_dump($rsa->getEncoding() === RSA_ENC_DEC);
?>
--EXPECT--
bool(true)