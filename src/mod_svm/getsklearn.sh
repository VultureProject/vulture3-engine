#!/bin/sh

if [ ! -f master.zip ]; then
    echo "Downloading scikit-learn tarball from repository"
    wget https://github.com/scikit-learn/scikit-learn/archive/master.zip
fi

rm -rf scikit-learn-master
unzip -q master.zip

cd scikit-learn-master

# Build liblibsvm-skl.a
c++ -fno-strict-aliasing -O2 -DNDEBUG -fPIC -c sklearn/svm/src/libsvm/libsvm_template.cpp
ar rc liblibsvm-skl.a libsvm_template.o
echo "Built liblibsvm-skl.a"

mv liblibsvm-skl.a ..
echo "liblibsvm-skl.a moved to $(dirname $PWD)"

cd sklearn/svm/src/libsvm

# Add #include <stdio.h> 
#     #include <string.h>
sed -iE	'1s/^/#include <stdio.h>\
#include <string.h>\
/' libsvm_helper.c

# Remove #include <numpy/arrayobject.h>
sed -iEr '/#include <numpy\/arrayobject.h>/d' libsvm_helper.c

# Define npy_intp type by replacing #define _LIBSVM_H by #define npy_intp long int
sed -iE 's/#define _LIBSVM_H/#define _LIBSVM_H\
	#define npy_intp long int/' svm.h

cc -shared -g -fPIC -I. libsvm_helper.c -o libsvm_helper.so
echo "Built libsvm_helper.so"

sudo cp libsvm_helper.so /usr/lib
echo "libsvm_helper.so copied to /usr/lib"

cd -
cd ..
rm -R scikit-learn-master