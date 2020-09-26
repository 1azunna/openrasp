#!/bin/bash
# Chinese PHP extension compilation instructions
# https://rasp.baidu.com/doc/hacking/compile/php.html

set -ex
script_base="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$script_base"

# PHP version and architecture
php_version=$(php -r 'echo PHP_MAJOR_VERSION, ".", PHP_MINOR_VERSION;')
php_arch=$(uname -m)
php_zts=$(php -r 'echo ZEND_THREAD_SAFE ? "-ts" : "";')
php_os=

case "$(uname -s)" in
    Linux)     
		php_os=linux
		;;
    Darwin)
		php_os=macos
        ;;
    *)
		echo Unsupported OS: $(uname -s)
		exit 1
		;;
esac

# Compile openrasp-v8
git submodule update --init
rm -rf openrasp-v8/build
mkdir -p openrasp-v8/build
cd openrasp-v8/build
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo -DENABLE_LANGUAGES=php ..
make

cd "$script_base"

#Determine the compilation directory
output_base="$script_base/rasp-php-$(date +%Y-%m-%d)"
output_ext="$output_base/php${php_zts}/${php_os}-php${php_version}-${php_arch}"

#Compile
cd agent/php7
phpize --clean
phpize

if [[ $php_os == "macos" ]]; then
	./configure --with-openrasp-v8=${script_base}/openrasp-v8/ --with-gettext=/usr/local/homebrew/opt/gettext -q ${extra_config_opt}
	make
else
	./configure --with-openrasp-v8=${script_base}/openrasp-v8/ --with-gettext --enable-openrasp-remote-manager -q ${extra_config_opt}
	make -j$(nproc)
fi

make

# Copy extension
mkdir -p "$output_ext"
cp modules/openrasp.so "$output_ext"/
make distclean
phpize --clean

# Copy other files
mkdir -p "$output_base"/{conf,assets,logs,locale,plugins}
cp ../../plugins/official/plugin.js "$output_base"/plugins/official.js
cp ../../rasp-install/php/*.php "$output_base"
cp ../../rasp-install/php/openrasp.yml "$output_base"/conf/openrasp.yml
cp ../../rasp-install/php/iast.yml "$output_base"/conf/iast.yml

# Generate and copy the mo file
./scripts/locale.sh
mv ./po/locale.tar "$output_base"/locale
cd "$output_base"/locale
tar xvf locale.tar && rm -f locale.tar

# Bale
cd "$script_base"
if [[ -z "$NO_TAR" ]]; then
	tar --numeric-owner --group=0 --owner=0 -cjvf "$script_base/rasp-php.tar.bz2" "$(basename "$output_base")"
fi



