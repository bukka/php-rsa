--TEST--
RSA::export basic usage
--SKIPIF--
<?php
if (!extension_loaded('rsa'))
	die("Skip: RSA extension not loaded");
?>
--FILE--
<?php
require_once dirname(__FILE__) . "/keys.inc";

$rsa_empty = new RSA();
echo "EMPTY KEY\n";
echo $rsa_empty->export();

list($rsa1, $ctext1_ex) = rsa_test_key1();
list($rsa2, $ctext2_ex) = rsa_test_key2();
list($rsa3, $ctext3_ex) = rsa_test_key3();

echo "\nRSA 1\n";
echo $rsa1->export();
echo "\nRSA 2\n";
echo $rsa2->export();
echo "\nRSA 3\n";
echo $rsa3->export();
?>
--EXPECT--
EMPTY KEY
Public-Key: (0 bit)

RSA 1
Private-Key: (512 bit)
modulus:
	00:aa:36:ab:ce:88:ac:fd:ff:55:52:3c:7f:c4:52:
	3f:90:ef:a0:0d:f3:77:4a:25:9f:2e:62:b4:c5:d9:
	9c:b5:ad:b3:00:a0:28:5e:53:01:93:0e:0c:70:fb:
	68:76:93:9c:e6:16:ce:62:4a:11:e0:08:6d:34:1e:
	bc:ac:a0:a1:f5
publicExponent: 17 (0x11)
privateExponent:
	0a:03:37:48:62:64:87:69:5f:5f:30:bc:38:b9:8b:
	44:c2:cd:2d:ff:43:40:98:cd:20:d8:a1:38:d0:90:
	bf:64:79:7c:3f:a7:a2:cd:cb:3c:d1:e0:bd:ba:26:
	54:b4:f9:df:8e:8a:e5:9d:73:3d:9f:33:b3:01:62:
	4a:fd:1d:51
prime1:
	00:d8:40:b4:16:66:b4:2e:92:ea:0d:a3:b4:32:04:
	b5:cf:ce:33:52:52:4d:04:16:a5:a4:41:e7:00:af:
	46:12:0d
prime2:
	00:c9:7f:b1:f0:27:f4:53:f6:34:12:33:ea:aa:d1:
	d9:35:3f:6c:42:d0:88:66:b1:d0:5a:0f:20:35:02:
	8b:9d:89
exponent1:
	59:0b:95:72:a2:c2:a9:c4:06:05:9d:c2:ab:2f:1d:
	af:eb:7e:8b:4f:10:a7:54:9e:8e:ed:f5:b4:fc:e0:
	9e:05
exponent2:
	00:8e:3c:05:21:fe:15:e0:ea:06:a3:6f:f0:f1:0c:
	99:52:c3:5b:7a:75:14:fd:32:38:b8:0a:ad:52:98:
	62:8d:51
coefficient:
	36:3f:f7:18:9d:a8:e9:0b:1d:34:1f:71:d0:9b:76:
	a8:a9:43:e1:1d:10:b2:4d:24:9f:2d:ea:fe:f8:0c:
	18:26

RSA 2
Private-Key: (400 bit)
modulus:
	00:a3:07:9a:90:df:0d:fd:72:ac:09:0c:cc:2a:78:
	b8:74:13:13:3e:40:75:9c:98:fa:f8:20:4f:35:8a:
	0b:26:3c:67:70:e7:83:a9:3b:69:71:b7:37:79:d2:
	71:7b:e8:34:77:cf
publicExponent: 3 (0x3)
privateExponent:
	6c:af:bc:60:94:b3:fe:4c:72:b0:b3:32:c6:fb:25:
	a2:b7:62:29:80:4e:68:65:fc:a4:5a:74:df:0f:8f:
	b8:41:3b:52:c0:d0:e5:3d:9b:59:0f:f1:9b:e7:9f:
	49:dd:21:e5:eb
prime1:
	00:cf:20:35:02:8b:9d:86:98:40:b4:16:66:b4:2e:
	92:ea:0d:a3:b4:32:04:b5:cf:ce:91
prime2:
	00:c9:7f:b1:f0:27:f4:53:f6:34:12:33:ea:aa:d1:
	d9:35:3f:6c:42:d0:88:66:b1:d0:5f
exponent1:
	00:8a:15:78:ac:5d:13:af:10:2b:22:b9:99:cd:74:
	61:f1:5e:6d:22:cc:03:23:df:df:0b
exponent2:
	00:86:55:21:4a:c5:4d:8d:4e:cd:61:77:f1:c7:36:
	90:ce:2a:48:2c:8b:05:99:cb:e0:3f
coefficient:
	00:83:ef:ef:b8:a9:a4:0d:1d:b6:ed:98:ad:84:ed:
	13:35:dc:c1:08:f3:22:d0:57:cf:8d

RSA 3
Private-Key: (1024 bit)
modulus:
	00:bb:f8:2f:09:06:82:ce:9c:23:38:ac:2b:9d:a8:
	71:f7:36:8d:07:ee:d4:10:43:a4:40:d6:b6:f0:74:
	54:f5:1f:b8:df:ba:af:03:5c:02:ab:61:ea:48:ce:
	eb:6f:cd:48:76:ed:52:0d:60:e1:ec:46:19:71:9d:
	8a:5b:8b:80:7f:af:b8:e0:a3:df:c7:37:72:3e:e6:
	b4:b7:d9:3a:25:84:ee:6a:64:9d:06:09:53:74:88:
	34:b2:45:45:98:39:4e:e0:aa:b1:2d:7b:61:a5:1f:
	52:7a:9a:41:f6:c1:68:7f:e2:53:72:98:ca:2a:8f:
	59:46:f8:e5:fd:09:1d:bd:cb
publicExponent: 17 (0x11)
privateExponent:
	00:a5:da:fc:53:41:fa:f2:89:c4:b9:88:db:30:c1:
	cd:f8:3f:31:25:1e:06:68:b4:27:84:81:38:01:57:
	96:41:b2:94:10:b3:c7:99:8d:6b:c4:65:74:5e:5c:
	39:26:69:d6:87:0d:a2:c0:82:a9:39:e3:7f:dc:b8:
	2e:c9:3e:da:c9:7f:f3:ad:59:50:ac:cf:bc:11:1c:
	76:f1:a9:52:94:44:e5:6a:af:68:c5:6c:09:2c:d3:
	8d:c3:be:f5:d2:0a:93:99:26:ed:4f:74:a1:3e:dd:
	fb:e1:a1:ce:cc:48:94:af:94:28:c2:b7:b8:88:3f:
	e4:46:3a:4b:c8:5b:1c:b3:c1
prime1:
	00:ee:cf:ae:81:b1:b9:b3:c9:08:81:0b:10:a1:b5:
	60:01:99:eb:9f:44:ae:f4:fd:a4:93:b8:1a:9e:3d:
	84:f6:32:12:4e:f0:23:6e:5d:1e:3b:7e:28:fa:e7:
	aa:04:0a:2d:5b:25:21:76:45:9d:1f:39:75:41:ba:
	2a:58:fb:65:99
prime2:
	00:c9:7f:b1:f0:27:f4:53:f6:34:12:33:ea:aa:d1:
	d9:35:3f:6c:42:d0:88:66:b1:d0:5a:0f:20:35:02:
	8b:9d:86:98:40:b4:16:66:b4:2e:92:ea:0d:a3:b4:
	32:04:b5:cf:ce:33:52:52:4d:04:16:a5:a4:41:e7:
	00:af:46:15:03
exponent1:
	54:49:4c:a6:3e:ba:03:37:e4:e2:40:23:fc:d6:9a:
	5a:eb:07:dd:dc:01:83:a4:d0:ac:9b:54:b0:51:f2:
	b1:3e:d9:49:09:75:ea:b7:74:14:ff:59:c1:f7:69:
	2e:9a:2e:20:2b:38:fc:91:0a:47:41:74:ad:c9:3c:
	1f:67:c9:81
exponent2:
	47:1e:02:90:ff:0a:f0:75:03:51:b7:f8:78:86:4c:
	a9:61:ad:bd:3a:8a:7e:99:1c:5c:05:56:a9:4c:31:
	46:a7:f9:80:3f:8f:6f:8a:e3:42:e9:31:fd:8a:e4:
	7a:22:0d:1b:99:a4:95:84:98:07:fe:39:f9:24:5a:
	98:36:da:3d
coefficient:
	00:b0:6c:4f:da:bb:63:01:19:8d:26:5b:db:ae:94:
	23:b3:80:f2:71:f7:34:53:88:50:93:07:7f:cd:39:
	e2:11:9f:c9:86:32:15:4f:58:83:b1:67:a9:67:bf:
	40:2b:4e:9e:2e:0f:96:56:e6:98:ea:36:66:ed:fb:
	25:79:80:39:f7
