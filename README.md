dionaea - catches bugs
======================

[![Build Status](https://ci.dinotools.org/job/dionaea-master/badge/icon)](https://ci.dinotools.org/job/dionaea-master/)

Dionaea is meant to be a nepenthes successor, embedding python as scripting language, using libemu to detect shellcodes, supporting ipv6 and tls.

Protocols
---------

* blackhole
* epmap
* ftp
* http
* memcache
* mirror
* mqtt
* mssql
* mysql
* pptp
* sip
* smb
* tftp
* upnp

Logging
-------

* fail2ban
* hpfeeds
* log_json
* log_sqlit

Documentation
-------------

* [Documentation](https://dionaea.readthedocs.io/)
* [Source](https://github.com/DinoTools/dionaea)
* [Issues](https://github.com/DinoTools/dionaea/issues)

Installation (Ubuntu 16.04)
---------------------------
```
sudo apt install \
    build-essential \
    cmake \
    check \
    cython3 \
    libcurl4-openssl-dev \
    libemu-dev \
    libev-dev \
    libglib2.0-dev \
    libloudmouth1-dev \
    libnetfilter-queue-dev \
    libnl-3-dev \
    libpcap-dev \
    libssl-dev \
    libtool \
    libudns-dev \
    python3 \
    python3-dev \
    python3-bson \
    python3-yaml \
    fonts-liberation
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX:PATH=/opt/dionaea ..
make
sudo make install
```

Licenses
--------

* dionaea: GPLv2+
* pyev(modules/python/pyev): GPLv3+
* tftp service(modules/python/tftp.py): CNRI Python License (incompatible with GPL)
* parts of ftp service(modules/python/ftp.py): MIT (compatible with GPL)
