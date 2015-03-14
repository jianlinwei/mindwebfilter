# Compiling MinD Toy in FreeBSD #


## Dependencies ##

For compiling Toy under FreeBSD, you will need the following packages installed before executing the _configure_ command:
  * pkg-config
  * autogen
  * pcre
  * clamav
  * libiconv
  * iconv
  * subversion (for svn checkout)


## Download ##

Get the source code from Google Code repository:
```
svn checkout http://mindwebfilter.googlecode.com/svn/trunk/ mindwebfilter-read-only
```


## Configuring ##

For using MinD without Clam Antivirus protection support just execute:
```
./bootstrap && ./configure --prefix=/usr/local/ --enable-clamd=no --enable-ntlm=yes \
--with-proxyuser=nobody --with-proxygroup=nogroup \
CXX="g++" CXXFLAGS="-I/usr/local/include,-O3" CPPFLAGS="" CC="cc" CFLAGS="-O3" \
LDFLAGS="-L/usr/local/lib,-Wl,-Bsymbolic-functions"
```

For using MinD with Clam Antivirus protection support just execute:
```
./bootstrap && ./configure --prefix=/usr/local/ --enable-clamd=yes --enable-ntlm=yes \
--with-proxyuser=nobody --with-proxygroup=nogroup \
CXX="g++" CXXFLAGS="-I/usr/local/include,-O3" CPPFLAGS="" CC="cc" CFLAGS="-O3" \
LDFLAGS="-L/usr/local/lib,-Wl,-Bsymbolic-functions"
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