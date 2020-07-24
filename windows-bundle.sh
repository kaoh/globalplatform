#!/bin/sh
dirName="gpshell-bundle"
rm -rf $dirName
unzip gpshell-binary*.zip -d $dirName
unzip zlib-1.2.8/zlib-1.2.8.zip -d $dirName

# get gpshell directory 
dirNamegpshell=""
for gpshell in $dirName/gpshell-binary*
do
    dirNamegpshell=$gpshell;
    break;
done

cp $dirNamegpshell/lib/globalplatform.dll $dirNamegpshell/bin
cp $dirNamegpshell/lib/gppcscconnectionplugin.dll $dirNamegpshell/bin

cp /c/Program\ Files\ \(x86\)/OpenSSL-Win32/libcrypto*.dll $dirNamegpshell/bin
cp /c/Program\ Files\ \(x86\)/OpenSSL-Win32/libssl*.dll $dirNamegpshell/bin
cp /c/Program\ Files\ \(x86\)/OpenSSL-Win32/libeay*.dll $dirNamegpshell/bin
cp $dirName/zlib-1.2.8/zlibwapi.dll $dirNamegpshell/bin

rm -f $dirNamegpshell/doc/CMakeLists.txt
rm -f $dirNamegpshell/doc/README.md
rm -rf $dirNamegpshell/include
rm -rf $dirNamegpshell/lib
rm -rf $dirName/zlib-1.2.8


