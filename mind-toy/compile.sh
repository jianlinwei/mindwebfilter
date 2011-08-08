#!/bin/bash

if [ $# -ne 2 ]
then
  echo "Usage: $0 proxyuser proxygroup"
  echo "Example: $0 proxy proxy"
  exit 2
fi

./bootstrap&&./configure --mandir=/usr/share/man/ --enable-clamd=yes --with-proxyuser=$1 \
--with-proxygroup=$2 --prefix=/ --mandir=/usr/share/man \
--infodir=/usr/share/info --sysconfdir=/etc --localstatedir=/var \
--enable-icap=yes --enable-commandline=yes --enable-trickledm=yes --enable-email=yes \
--enable-ntlm=yes CXX="g++" CXXFLAGS="-O0 -g" LDFLAGS="-Wl,-Bsymbolic-functions" \
CPPFLAGS="" CC="cc" CFLAGS="-O0 -g"&&make

