# OpenSSL libraries installation

Unfortunately, sp1 requires library files from both OpenSSL 1.1 and OpenSSL 3 for now.

Your Linux distributions / macOS installation should be shipped with either OpenSSL 1.1 or OpenSSL 3.
In order to minimize the pain, use a distribution that is shipped with OpenSSL 3 
and manually compile the OpenSSL 1.1.1 library.

Warning: a lot of system packages rely on the OpenSSL library with version that is originally shipped with.
Our goal is just to obtain the missing library files (`libssl.so.1.1` and `libcrypto.so.1.1`)
instead of replacing OpenSSL on your system. 
So, do not install OpenSSL via your package manager,
since your distribution **will not** officially provide two versions of OpenSSL.
Also, do not manually install the OpenSSL package (e.g., `*.deb`, `*.rpm`) obtained from a different release of your distribution 
unless you want to break the whole package management.

## macOS
`brew install openssl@1.1.1`

## Debian / Ubuntu: 
Debian 12 / Ubuntu 22.04 or higher are shipped with OpenSSL 3. Package `libssl3` should be already installed by default.

First, install additional develop packages.
```bash
sudo apt update
sudo apt install libssl-dev libz-dev build-essential
```

Then, compile and install OpenSSL 1.1.1 library.
```bash
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
