#!/bin/bash

# Script build the blockstack virtualenv distributed with
# the macOS app


## make working directory the same as location of script
#cd "$(dirname "$0")"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/"

echo "Script is running in $SCRIPT_DIR"

cd /tmp

echo "Removing any existing virtualenv dir..."

rm -Rfv blockstack-venv

echo "Creating a new virtualenv..."

virtualenv -p /usr/bin/python2.7 blockstack-venv

echo "Downloading gmp..."

curl -O https://gmplib.org/download/gmp/gmp-6.1.2.tar.bz2

bunzip2 gmp-6.1.2.tar.bz2

tar -xf gmp-6.1.2.tar

echo "Building gmp..."

cd gmp-6.1.2

./configure --prefix=/tmp/blockstack-venv

make

make install

cd ..

echo "Activating virtualenv..."

source blockstack-venv/bin/activate

echo "Installing fastecdsa..."

CFLAGS="-I/tmp/blockstack-venv/include" LDFLAGS="-L/tmp/blockstack-venv/lib" pip install -v --force --no-cache-dir --no-binary :all: fastecdsa

echo "Installing latest virtualchain..."

pip install git+https://github.com/blockstack/virtualchain.git@43956be4c653038d4069eaac4497463bad176429

echo "Installing latest blockstack-profiles..."

pip install git+https://github.com/blockstack/blockstack-profiles-py.git@103783798df78cf0f007801e79ec6298f00b2817

echo "Installing latest blockstack-zones..."

pip install git+https://github.com/blockstack/zone-file-py.git@73739618b51d4c8b85966887fae4ca22cba87e10

echo "Installing latest blockstack..."

pip install git+https://github.com/blockstack/blockstack-core.git@master-sprint-2017-04-13

echo "Blockstack virtual environment created."

echo "Making Blockstack virtual environment relocatable..."

virtualenv --relocatable blockstack-venv

echo "Build Blockstack virtualenv archive..."

tar -czvf $SCRIPT_DIR/Blockstack/Blockstack/blockstack-venv.tar.gz blockstack-venv
