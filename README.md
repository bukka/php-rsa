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

## Examples

The examples can be found in [the example directory](examples).


## TODO list

The TODO list can be found [here](TODO.md).

