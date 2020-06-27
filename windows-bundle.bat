set dirName=gpshell-bundle
del /F /S /Q %dirName% > NUL
rmdir /S /Q %dirName%
mkdir %dirName%

for /f %%f in ('dir /a /b gpshell-binary-*.zip') do set gpshellZip=%%f

tar -xf %gpshellZip% -C %dirName%
tar -xf zlib-1.2.8/zlib-1.2.8.zip -C %dirName%

rem get gpshell directory 
set dirNamegpshell=""
for /f %%d in ('dir /ad /b %dirName%\gpshell-binary*') do set dirNamegpshell=%dirName%\%%d

copy "%dirNamegpshell%\lib\globalplatform.dll" "%dirNamegpshell%\bin"
copy "%dirNamegpshell%\lib\gppcscconnectionplugin.dll" "%dirNamegpshell%\bin"

copy "C:\Program Files (x86)\OpenSSL-Win32\libcrypto*.dll" "%dirNamegpshell%\bin"
copy "C:\Program Files (x86)\OpenSSL-Win32\libssl*.dll" "%dirNamegpshell%\bin"
copy %dirName%\zlib-1.2.8\zlibwapi.dll "%dirNamegpshell%\bin"

del /F %dirNamegpshell%\doc\CMakeLists.txt > NUL
del /F %dirNamegpshell%\doc\README.md > NUL
del /F /S /Q %dirNamegpshell%\doc\html > NUL
rmdir /s /Q %dirNamegpshell%\doc\html
del /F /S /Q %dirNamegpshell%\include > NUL
rmdir /s /Q %dirNamegpshell%\include
del /F /S /Q %dirNamegpshell%\lib > NUL
rmdir /s /Q %dirNamegpshell%\lib
del /F /S /Q %dirName%\zlib-1.2.8 > NUL
rmdir /s /Q %dirName%\zlib-1.2.8

rem tar -czf %dirName%\%gpshellZip% %dirNamegpshell% > NUL