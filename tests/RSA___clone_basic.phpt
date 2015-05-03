--TEST--
RSA::__clone basic usage.
--FILE--
<?php
$rsa = new RSA();
$rsa->setE('10001');
$rsa->setN('ab00cd00cd000cd00c00d0dd0d0d0d0d0');
$rsa_copy = clone $rsa;
$rsa_copy->setE('13');

var_dump($rsa->getE());
var_dump($rsa_copy->getE());
var_dump($rsa->getN());
var_dump($rsa_copy->getN());
?>
--EXPECT--
string(6) "010001"
string(2) "13"
string(34) "0AB00CD00CD000CD00C00D0DD0D0D0D0D0"
string(34) "0AB00CD00CD000CD00C00D0DD0D0D0D0D0"