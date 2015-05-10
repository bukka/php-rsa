--TEST--
RSA::generateKey basic usage.
--SKIPIF--
<?php
if (!extension_loaded('rsa'))
    die("Skip: RSA extension not loaded");
?>
--FILE--
<?php
$rsa = new RSA();
try {
    $rsa->generateKey(RSA::MAX_MODULE_SIZE + 1, 65537);
} catch (RSAException $e) {
    echo $e->getCode() === RSAException::KEY_GENERATION_BITS_HIGH ? "BITS HIGH\n" : "BAD CODE\n";
}

$rsa->generateKey(1024, 65537);

$rsa->setEncoding(RSA::ENCODING_HEX);
var_dump($rsa->getE());
var_dump($rsa->getN());

?>
--EXPECTF--
BITS HIGH
string(6) "010001"
%s