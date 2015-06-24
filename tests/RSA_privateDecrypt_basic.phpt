--TEST--
RSA::privateDecrypt basic usage.
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

// test exceptions
try {
    $rsa1->privateDecrypt(str_repeat('x', 1024));
} catch (RSAException $e) {
    echo $e->getCode() === RSAException::PRIV_DECRYPT_INPUT_LONG ? "INPUT LONG\n" : "BAD CODE\n";
}

$ptext_ex = pack("H*" , "54859b342c49ea2a");

// key 1 test
function rsa_test_public_crypt($i, $rsa, $ptext_ex, $ctext_ex) {
    $ctext1_pkcs1_1_5 = $rsa->publicEncrypt($ptext_ex, RSA::PADDING_PKCS1);

    if (strlen($ctext1_pkcs1_1_5) !== strlen($ctext_ex)) {
        echo "KEY $i: PKCS#1 v1.5 encryption failed\n";
    }

    $ptext1_pkcs1_1_5 = $rsa->privateDecrypt($ctext1_pkcs1_1_5, RSA::PADDING_PKCS1);
    if ($ptext1_pkcs1_1_5 === $ptext_ex) {
        echo "KEY $i: PKCS#1 v1.5 decryption ok\n";
    } else {
        echo "KEY $i: PKCS#1 v1.5 decryption failed\n";
    }

    $ctext1_pkcs1_oaep = $rsa->publicEncrypt($ptext_ex, RSA::PADDING_OAEP);

    if (strlen($ctext1_pkcs1_oaep) !== strlen($ctext_ex)) {
        echo "KEY $i: OAEP encryption failed\n";
    }

    $ptext1_pkcs1_oaep = $rsa->privateDecrypt($ctext1_pkcs1_oaep, RSA::PADDING_OAEP);
    if ($ptext1_pkcs1_oaep === $ptext_ex) {
        echo "KEY $i: OAEP decryption ok\n";
    } else {
        echo "KEY $i: OAEP decryption failed\n";
    }
}

rsa_test_public_crypt(1, $rsa1, $ptext_ex, $ctext1_ex);
rsa_test_public_crypt(2, $rsa2, $ptext_ex, $ctext2_ex);
rsa_test_public_crypt(3, $rsa3, $ptext_ex, $ctext3_ex);

?>
--EXPECT--
INPUT LONG
KEY 1: PKCS#1 v1.5 decryption ok
KEY 1: OAEP decryption ok
KEY 2: PKCS#1 v1.5 decryption ok
KEY 2: OAEP decryption ok
KEY 3: PKCS#1 v1.5 decryption ok
KEY 3: OAEP decryption ok