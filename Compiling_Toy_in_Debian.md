# Compiling MinD Toy in Debian GNU/Linux #

## Download ##

We already provide packages for the stable Debian distribution [here](http://code.google.com/p/mindwebfilter/downloads/list). If you need to compile MinD, get the stable source code snapshot from [here](http://code.google.com/p/mindwebfilter/downloads/list).

You can also grab the latest testing code from the Google Code repository (must have the package subversion installed):

```
svn checkout http://mindwebfilter.googlecode.com/svn/trunk/ mindwebfilter-read-only
```


## Dependencies ##

For compiling Toy under Debian based distributions, you will need the following packages installed before executing the _configure_ command:
  * automake
  * pkg-config
  * build-essential
  * libz-dev
  * libpcre3-dev
  * libclamav-dev
  * libxml2-dev
  * libtool


## Configuring ##

For using MinD without Clam Antivirus protection support just execute:
```
./bootstrap && ./configure --mandir=/usr/share/man/ --enable-clamd=no --with-proxyuser=proxy \
--with-proxygroup=proxy --prefix=/ --mandir=/usr/share/man \
--infodir=/usr/share/info --sysconfdir=/etc --localstatedir=/var \
--enable-ntlm=yes CXX="g++" CXXFLAGS="-O3" LDFLAGS="-Wl,-Bsymbolic-functions" \
CPPFLAGS="" CC="cc" CFLAGS="-O3"
```

For using MinD with Clam Antivirus protection support just execute:
```
./bootstrap && ./configure --mandir=/usr/share/man/ --enable-clamd=yes --with-proxyuser=proxy \
--with-proxygroup=proxy --prefix=/ --mandir=/usr/share/man \
--infodir=/usr/share/info --sysconfdir=/etc --localstatedir=/var \
--enable-ntlm=yes CXX="g++" CXXFLAGS="-O3" LDFLAGS="-Wl,-Bsymbolic-functions" \
CPPFLAGS="" CC="cc" CFLAGS="-O3"
```


## Compiling ##
Once configuration has finished just type:
```
make
```
and wait patiently...


## Installing ##
After compiling just type:
```
sudo make install
```