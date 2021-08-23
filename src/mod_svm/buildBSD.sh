#!/bin/sh

ENGINE=/home/vlt-sys/Engine
APXS=$ENGINE/bin/apxs
MODULES=$ENGINE/modules
CONF=$ENGINE/conf/10.59.10.100-80.conf

for i in $(seq 2 5)
do
	echo "Building mod_svm"$i" ..."
	$APXS -L$ENGINE/lib -I$ENGINE/include/ -l:libsvm_helper.so -llibsvm-skl -lm -lstdc++ -c mod_svm$i.c svm_util.c libsvm/libsvm_helper.c
	mv .libs/mod_svm$i.so mod_svm$i.so
done

echo "Building mod_svm6 ..."
$APXS -L$ENGINE/lib -I$ENGINE/include/ -l:libsvm_helper.so -llibsvm-skl -lm -lstdc++ -lhiredis -c mod_svm6.c svm_util.c libsvm/libsvm_helper.c
mv .libs/mod_svm6.so mod_svm6.so

for i in $(seq 2 6)
do
	echo "Copying mod_svm"$i" ..."
	cp mod_svm$i.so $MODULES/mod_svm$i.so
done

for i in $(seq 6 2)
do
	if [ $(grep -c 'LoadModule svm'$i'_module modules/mod_svm'$i'.so' $CONF) -eq 0 ]; then
		sed -iE	's,LoadModule proxy_http_module modules/mod_proxy_http.so,LoadModule proxy_http_module modules/mod_proxy_http.so\
LoadModule svm'$i'_module modules/mod_svm'$i'.so,' $CONF
	fi
done