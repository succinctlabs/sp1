# Installing OpenSSL

Currently, SP1 requires OpenSSL 1.1 and OpenSSL 3 as a dependencies. Your existing Linux/MacOs installation
should already be shipped with either OpenSSL 1.1 or OpenSSL3. 

## MacOS:

OpenSSL 1.1:

`brew install openssl@1.1`

OpenSSL 3:

`brew install openssl@3`

## Linux

Debian 12 / Ubuntu 22.04 or higher are shipped with OpenSSL 3.

OpenSSL 1.1:

```
sudo apt update
sudo apt install libssl-dev libz-dev build-essential
```

```
wget https://ftp.openssl.org/source/old/1.1.1/openssl-1.1.1w.tar.gz
tar -xzvf openssl-1.1.1w.tar.gz
cd openssl-1.1.1w
./config --prefix=/usr/local/ssl1.1 --openssldir=/usr/local/ssl1.1 --libdir=lib zlib-dynamic
make
make test
sudo make install
sudo ln -s /usr/local/ssl1.1/lib/libssl.so.1.1 /usr/local/lib/libssl.so.1.1
sudo ln -s /usr/local/ssl1.1/lib/libcrypto.so.1.1 /usr/local/lib/libcrypto.so.1.1
sudo ldconfig
```

These commands are borrowed from this [StackOverflow post](https://askubuntu.com/questions/1102803/how-to-upgrade-openssl-1-1-0-to-1-1-1-in-ubuntu-18-04).