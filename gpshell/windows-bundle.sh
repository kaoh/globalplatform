#!/bin/sh
dirName="gpshell-bundle"
rm -rf $dirName
unzip ../globalplatform/globalplatform-binary*.zip -d $dirName
unzip ../gppcscconnectionplugin/gppcscconnectionplugin-binary*.zip -d $dirName
unzip gpshell-binary*.zip -d $dirName

# get gpshell directory 
dirNamegpshell=""
for gpshell in $dirName/gpshell-binary*
do
    dirNamegpshell=$gpshell;
    break;
done

for globalplatform in $dirName/globalplatform-binary*
do
  cp $globalplatform/lib/globalplatform.dll $dirNamegpshell/bin;
done
for gppcscconnectionplugin in $dirName/gppcscconnectionplugin-binary*
do
  cp $gppcscconnectionplugin/lib/gppcscconnectionplugin.dll $dirNamegpshell/bin;
done
cp C:/Windows/System32/libeay32.dll $dirNamegpshell/bin
cp C:/Windows/System32/libssl32.dll $dirNamegpshell/bin
cp C:/Windows/System32/zlibwapi.dll $dirNamegpshell/bin
