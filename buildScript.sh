#!/bin/sh

#########################################################################################################################################
# Script:       buildScript.sh                                                                                                          #
# Goal:         Build the Engine part of the Vulture project based on Apache                                                            #
# Description:  Compile, configure and build all the components of the Engine part of Vulture:                                          #
#                - Apache            2.4.46    The core of the Engine part (must be the latest for performance and security reasons)    #
#                - mod_vulture       0.1.0     The Vulture custom module which handles and manages authentication                       #
#                - hiredis           0.13.3    C client for Redis (used in mod_vulture to communicate with Redis Server)                #
#                - mod_proxy_msrpc   0.6.0     For MS activesync support                                                                #
#                - mod_wsgi          3.5.0     To manage python sources especially the Django framework                                 #
#                - mod_security      2.9.0     Important components used to manage Vulture security and web servers protection          #
# Usage:        sudo ./buildScript.sh                                                                                                   #
# Warning:      Some tools are built upon shared objects (.so) which can vary based on the OS updates and softwares versions,           #
#               to be fully compatible with the Vulture installation, be carefull to have exactly the same updates and                  #
#               OS version between the factory and a Vulture installation                                                               #
# Authors:      Anthony DECHY  Jeremie Jourdin Kevin Guillemot                                                                          #
# License:      GPLv3                                                                                                                   #
# Version:      1.0                                                                                                                     #
# Modification: 05/06/2019                                                                                                              #
#########################################################################################################################################


# pkg install -y cmake gmake

#####################
# Pre install setup #
#####################

set -ex

if [ "$(/usr/bin/id -u)" != "0" ]; then
   /bin/echo "This script must be run as root" 1>&2
   exit 1
fi

SRCPATH="/home/vlt-sys/buildSRV"
DSTPATH="/home/vlt-sys"
DSTPATHSED="\/home\/vlt-sys"

SHASUM_FILE="SHASUMS"
MODSEC_VERSION="2.9.2"
APACHE_VERSION="2.4.46"
MODPYTHON_VERSION="3.5.0"
PYTHON_VERSION="2.7"
HIREDIS_VERSION="0.13.3"
REV="66"


/bin/echo "You are about to build a new version of vulture-BINARY"
/bin/echo "Press CTRL+C to exit"

/bin/echo "Verifying SHASUMs of sources"
for line in $(/usr/local/bin/shasum -c $SHASUM_FILE | /usr/bin/awk '{print $2}')
do
    if [ "$(/bin/echo $line |/usr/bin/grep 'OK')" == "" ]
    then
        /bin/echo "BAD SHASUM : $line"
        exit
    fi
done

#/bin/echo "Copy of /home/vlt-sys/Engine/conf is in /root"
#if [ -d "/home/vlt-sys/Engine/conf" ] ; then /bin/cp -rp /home/vlt-sys/Engine/conf /root ;  fi


/bin/echo ""
/bin/echo "Cleaning directories..."
/bin/rm -rf $SRCPATH/src
/bin/rm -rf $DSTPATH/Engine

/bin/echo "Creating directories..."
/bin/mkdir -p $SRCPATH/src
/bin/mkdir -p $DSTPATH/Engine/tmp
/bin/mkdir -p $DSTPATH/Engine/null
/bin/mkdir -p $DSTPATH/Engine/modsec

cd $SRCPATH/src
cp -r $DSTPATH/vulture-engine/src/* $SRCPATH/src

/bin/echo "Decompressing Apache sources..."
tar xf httpd-$APACHE_VERSION.tar.gz
/bin/echo "Decompressing mod_wsgi sources..."
unzip mod_wsgi.zip
/bin/echo "Decompressing hiredis sources..."
unzip hiredis-${HIREDIS_VERSION}.zip
/bin/echo "Decompressiong mod_maxminddb sources..."
unzip mod_maxminddb.zip
/bin/echo "Decompressiong mod_proxy_msrpc sources..."
unzip mod_proxy_msrpc.zip
/bin/echo "Decompressiong mod_security sources..."
tar xf modsecurity-$MODSEC_VERSION.tar.gz
/bin/echo "Decompressiong scikit-learn-master sources..."
unzip scikit-learn-master.zip
/bin/echo "Decompressing yajl sources..."
tar xf yajl-2.1.0.tar.gz


###########
# yaj     #
###########

/bin/echo ""
/bin/echo "Configuring YAJL sources..."
cd $DSTPATH/buildSRV/src/lloyd-yajl-66cb08c
./configure -p $DSTPATH/Engine
make install


###########
# hiredis #
###########

/bin/echo ""
/bin/echo "Configuring Hiredis sources..."
cd $DSTPATH/buildSRV/src/hiredis-${HIREDIS_VERSION}/
gmake -j4
sed -i "" "s/^PREFIX?=\/usr\/local/PREFIX\?=$DSTPATHSED\/Engine/g" Makefile
gmake install


##########
# Apache #
##########

/bin/echo ""
/bin/echo "Configuring Apache sources..."
cd $DSTPATH/buildSRV/src/httpd-$APACHE_VERSION
./configure --prefix=$DSTPATH/Engine --with-mpm=worker --enable-status --enable-info --enable-authn-anon --enable-heartbeat --enable-watchdog --enable-heartmonitor --disable-autoindex --disable-cgid --disable-fcgi --enable-ssl-staticlib-deps --enable-ssl --with-ssl=/usr/local --enable-proxy --enable-proxy-connect --enable-proxy-http --enable-proxy-ftp --enable-proxy-wstunnel --enable-proxy-ajp --enable-proxy-balancer --enable-proxy-html --enable-xml2enc --with-nghttp2=/usr/local --enable-http2 
/bin/echo "Building Apache sources..."
make -j4 CFLAGS=-DOPENSSL_NO_SSL2
/bin/echo "Installing Apache sources..."
make install


#################
# mod_security2 #
#################

/bin/echo ""
/bin/echo "Configuring mod_security sources..."
cd $DSTPATH/buildSRV/src/modsecurity-$MODSEC_VERSION
cp $DSTPATH/buildSRV/src/modSecurity-Patches/* $DSTPATH/buildSRV/src/modsecurity-$MODSEC_VERSION/apache2/
./autogen.sh
./configure --with-apxs=$DSTPATH/Engine/bin/apxs CC=clang --enable-lua-cache --with-lua=/usr/local/lib
/bin/echo "Building mod_security sources..."
make -j4 CFLAGS=-I$DSTPATH/Engine/include/hiredis
/bin/echo "Installing mod_security sources..."
make CFLAGS=-I$DSTPATH/Engine/include/hiredis install
mkdir $DSTPATH/Engine/include/modsecurity
cp $DSTPATH/buildSRV/src/modsecurity-$MODSEC_VERSION/apache2/*.h $DSTPATH/Engine/include/modsecurity/


###############
# mod_vulture #
###############

/bin/echo ""
/bin/echo "Building mod_vulture..."
cd $DSTPATH/buildSRV/src/mod_vulture
DSTPATH=$DSTPATH /bin/sh ./make.sh
#./bin/apxs -I$DSTPATH/Engine/include/hiredis -L$DSTPATH/Engine/lib/ -lhiredis -lssl -lgssapi -lgssapi_krb5 -i -a -c $DSTPATH/buildSRV/src/mod_vulture.c
/bin/echo "Activating mod_vulture..."

################
# mod_defender #
################

/bin/echo ""
/bin/echo "Building mod_defender..."
wget https://github.com/VultureProject/mod_defender/archive/master.zip -O ./defender.zip
unzip ./defender.zip
cd mod_defender-master
cmake .
make -j4
cp mod_defender.so $DSTPATH/Engine/modules/


#######################
# scikit-learn-master #
#######################

/bin/echo ""
/bin/echo "Configuring Scikit-learn sources..."
cd $DSTPATH/buildSRV/src/scikit-learn-master
# Build liblibsvm-skl.a
/usr/bin/c++ -fno-strict-aliasing -O2 -pipe -fstack-protector -fno-strict-aliasing -DNDEBUG -fPIC -I/home/vlt-gui/env/lib/python2.7/site-packages/numpy/core/include -c ./sklearn/svm/src/libsvm/libsvm_template.cpp
/usr/bin/ar rc liblibsvm-skl.a libsvm_template.o
/bin/rm libsvm_template.o
/bin/cp ./liblibsvm-skl.a $DSTPATH/Engine/lib/

# Build libsvm_helper.so
cd ./sklearn/svm/src/libsvm
# Add "#include <stdio.h>" && "#include <string.h>"
/usr/bin/sed -i '' 's/#include <stdlib.h>/#include <stdlib.h> \
	#include <stdio.h> \
	#include <string.h>/' ./libsvm_helper.c
# Comment "#include <numpy\/arrayobject.h>"
/usr/bin/sed -i '' 's/#include <numpy\/arrayobject.h>/\/\/#include <numpy\/arrayobject.h>/' ./libsvm_helper.c
/usr/bin/head ./libsvm_helper.c
# Define npy_intp type
/usr/bin/sed -i '' 's/#define _LIBSVM_H/#define _LIBSVM_H\
	#define npy_intp long int/' ./svm.h
/usr/bin/head ./svm.h
gcc -shared -fPIC -I. libsvm_helper.c -o libsvm_helper.so
/bin/cp ./libsvm_helper.so $DSTPATH/Engine/lib
/bin/cp ./svm.h $DSTPATH/Engine/include

cd $DSTPATH/Engine
/bin/echo "Building mod_svm2..."
cd $DSTPATH/Engine
./bin/apxs -Wall -Wextra -Wc -L$DSTPATH/Engine/lib/ -I$SRCPATH/Engine/include/ -l:libsvm_helper.so -llibsvm-skl -lm -lstdc++ -i -a -c $DSTPATH/buildSRV/src/mod_svm/mod_svm2.c $DSTPATH/buildSRV/src/mod_svm/svm_util.c
/bin/echo "Activating mod_svm2..."
/bin/echo ""
/bin/echo "Building mod_svm3..."
cd $DSTPATH/Engine
./bin/apxs -Wall -Wextra -Wc -L$DSTPATH/Engine/lib/ -I$SRCPATH/Engine/include/ -l:libsvm_helper.so -llibsvm-skl -lm -lstdc++ -i -a -c $DSTPATH/buildSRV/src/mod_svm/mod_svm3.c $DSTPATH/buildSRV/src/mod_svm/svm_util.c
/bin/echo "Activating mod_svm3..."
/bin/echo "Building mod_svm4..."
cd $DSTPATH/Engine
./bin/apxs -Wall -Wextra -Wc -L$DSTPATH/Engine/lib/ -I$SRCPATH/Engine/include/ -l:libsvm_helper.so -llibsvm-skl -lm -lstdc++ -i -a -c $DSTPATH/buildSRV/src/mod_svm/mod_svm4.c $DSTPATH/buildSRV/src/mod_svm/svm_util.c
/bin/echo "Activating mod_svm4..."
/bin/echo "Building mod_svm5..."
cd $DSTPATH/Engine
./bin/apxs -Wall -Wextra -Wc -L$DSTPATH/Engine/lib/ -I$SRCPATH/Engine/include/ -l:libsvm_helper.so -llibsvm-skl -lm -lstdc++ -i -a -c $DSTPATH/buildSRV/src/mod_svm/mod_svm5.c $DSTPATH/buildSRV/src/mod_svm/svm_util.c
/bin/echo "Activating mod_svm5..."


###################
# mod_maxminddb #
###################

#Requires pkg install automake

/bin/echo ""
/bin/echo "Configuring mod_maxminddb..."
cd $DSTPATH/buildSRV/src/mod_maxminddb-master
./bootstrap
LDFLAGS=-L/usr/local/lib/ ./configure --prefix=$DSTPATH/Engine --with-apxs=$DSTPATH/Engine/bin/apxs 
/bin/echo "Building mod_maxminddb sources..."
make -j4
/bin/echo "Installing mod_maxminddb sources..."
make install


###################
# mod_proxy_msrpc #
###################

/bin/echo ""
/bin/echo "Patching mod_proxy_msrpc..."
cd $DSTPATH/buildSRV/src/mod_proxy_msrpc-master/src
sed -i "" "s/ENODATA/ENOATTR/g" msrpc_sync.c

/bin/echo "Building mod_proxy_msrpc..."
cp /usr/local/lib/libuuid* $DSTPATH/Engine/lib
cp /usr/local/lib/libinotify* $DSTPATH/Engine/lib
$DSTPATH/Engine/bin/apxs -L$DSTPATH/Engine/lib -linotify -luuid -i -a -c mod_proxy_msrpc.c msrpc_pdu_parser.c msrpc_sync.c 


############
# mod_wsgi #
############

/bin/echo ""
/bin/echo "Configuring mod_wsgi sources..."
cd $DSTPATH/buildSRV/src/mod_wsgi-develop/
./configure --prefix=$DSTPATH/Engine --with-apxs=$DSTPATH/Engine/bin/apxs --with-python=/usr/local/bin/python$PYTHON_VERSION 

/bin/echo "Building mod_wsgi sources..."
make -j4

/bin/echo "Installing mod_wsgi sources..."
make install


######################
# Post install setup #
######################

/bin/echo ""
/bin/echo "Cleaning useless files..."
/bin/rm -rf $DSTPATH/Engine/build $DSTPATH/Engine/icons $DSTPATH/Engine/man $DSTPATH/Engine/manual $DSTPATH/Engine/cgi-bin $DSTPATH/Engine/error $DSTPATH/Engine/htdocs $DSTPATH/Engine/share $DSTPATH/Engine/tmp

/bin/echo "Add version file for update..."
/bin/echo "Engine-$APACHE_VERSION-$REV" > $DSTPATH/Engine/version

/bin/echo "Building archives..."
cd $DSTPATH
tar -c -z -f $SRCPATH/Vulture-Engine-$APACHE_VERSION-$REV.tar.gz ./Engine
chgrp builder $SRCPATH/Vulture-Engine-$APACHE_VERSION-$REV.tar.gz
chmod 460 $SRCPATH/Vulture-Engine-$APACHE_VERSION-$REV.tar.gz

/bin/echo "Computing checksum"
sha256 $SRCPATH/Vulture-Engine-$APACHE_VERSION-$REV.tar.gz > $SRCPATH/Vulture-Engine-SHA256.txt
chown vlt-sys $SRCPATH/Vulture-Engine-$APACHE_VERSION-$REV.tar.gz
chgrp builder $SRCPATH/Vulture-Engine-$APACHE_VERSION-$REV.tar.gz
chmod 440 $SRCPATH/Vulture-Engine-$APACHE_VERSION-$REV.tar.gz
