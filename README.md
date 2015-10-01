# PHP RSA OpenSSL wrapper

The php-rsa is a wrapper for RSA part of OpenSSL Crypto library.


## Installation

### Linux

Before starting with installation this extensions, the `OpenSSL` library has to be installed. It is defaultly installed on the most Linux distribution.

Currently PHP needs to be compiled with OpenSSL extension (`--with-openssl`). This dependency will be removed in the future.

#### Manual Installation

First clone the repository
```
git clone --recursive https://github.com/bukka/php-rsa.git
```

Then go to the created directory and compile the extension. The PHP development package has to be installed (command `phpize` must be available).
```
cd php-rsa
phpize
./configure
make
sudo make install
```

Finally the following line needs to be added to `php.ini`
```
extension=rsa.so
```

## API

The API is not documented. There are just tests that can be found in [test directory](tests/).


## Future development

This extension is finished and there are no plans for improvements except quick fixes.

Please see [lcrypto](https://github.com/bukka/php-lcrypto) that contains RSA and more features.

