<?php

function rsa_test_key1() {
    $params = array(
        'n' => "0x" .
            "00AA36ABCE88ACFDFF55523C7FC4523F" .
            "90EFA00DF3774A259F2E62B4C5D99CB5" .
            "ADB300A0285E5301930E0C70FB687693" .
            "9CE616CE624A11E0086D341EBCACA0A1" .
            "F5",

        'e' => "0x11",

        'd' => "0x" .
            "0A033748626487695F5F30BC38B98B44" .
            "C2CD2DFF434098CD20D8A138D090BF64" .
            "797C3FA7A2CDCB3CD1E0BDBA2654B4F9" .
            "DF8E8AE59D733D9F33B301624AFD1D51",

        'p' => "0x" .
            "00D840B41666B42E92EA0DA3B43204B5" .
            "CFCE3352524D0416A5A441E700AF4612" .
            "0D",

        'q' => "0x" .
            "00C97FB1F027F453F6341233EAAAD1D9" .
            "353F6C42D08866B1D05A0F2035028B9D" .
            "89",

        'dmp1' => "0x" .
            "590B9572A2C2A9C406059DC2AB2F1DAF" .
            "EB7E8B4F10A7549E8EEDF5B4FCE09E05",

        'dmq1' => "0x" .
            "008E3C0521FE15E0EA06A36FF0F10C99" .
            "52C35B7A7514FD3238B80AAD5298628D" .
            "51",

        'iqmp' => "0x" .
            "363FF7189DA8E90B1D341F71D09B76A8" .
            "A943E11D10B24D249F2DEAFEF80C1826",
    );

    $rsa = new RSA();
    foreach ($params as $param_name => $param_value) {
        $method = 'set' . strtoupper($param_name);
        $rsa->$method($param_value);
    }

    $ctext_ex = "0x" .
        "1b8f05f9ca1a79526e53f3cc514fdb89" .
        "2bfb9193231e78b992e68d50a480cb52" .
        "33895c74958d5d02ab8c0fd040eb5844" .
        "b005c39ed8274a9dbfa80671409439d2";

    return array($rsa, $ctext_ex);

}
