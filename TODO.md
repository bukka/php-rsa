# TODO list

- Add public key cryptography
  - padding constants
  - RSA::publicEncrypt($from, $padding)
  - RSA::privateDecrypt($from, $padding)
- Add signing and verifying functions
  - RSA::sing($message, $type)
  - RSA::verify($message, $type)
  - RSA::privateEncrypt($from, $padding)
  - RSA::publicDecrypt($from, $padding)
- Add printing function
  - RSA::print()
- Test
  - Use data from `crypto/rsa/rsa_test.c` in OpenSSL