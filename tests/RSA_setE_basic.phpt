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
try {
    $rsa->setE("1000i");
} catch (RSAException $e) {
    echo $e->getCode() === RSAException::INVALID_HEX_ENCODING ? "INVALID HEX\n" : "BAD CODE\n";
}

try {
    $rsa->setE("1000d", RSA::ENCODING_DEC);
} catch (RSAException $e) {
    echo $e->getCode() === RSAException::INVALID_DEC_ENCODING ? "INVALID DEC\n" : "BAD CODE\n";
}

$rsa->setE("10001");
$rsa->setE(65537);
echo "SUCCESS\n";
?>
--EXPECT--
INVALID HEX
INVALID DEC
SUCCESS