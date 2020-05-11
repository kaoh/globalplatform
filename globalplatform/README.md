# Summary

- Title    : GlobalPlatform
- Authors  : Karsten Ohme <k_o_@users.sourceforge.net>
- License  : See file COPYING.LESSER
- Requires :
 * PC/SC Lite http://www.musclecard.com/ (for UNIXes)
 * OpenSSL http://www.openssl.org/
 * zlib http://www.zlib.net/

This is a library for providing access to OpenPlatform 2.0.1' and
GlobalPlatform 2.1.1 conforming smart cards.

You need also the libraries `zlib 1.2.3` (zlib1.dll in Windows) and OpenSSL >= v1.0.1c
(`libeay32.dll` and `ssleay32.dll` in Windows) or compatible.

For more information contact the author through the mailing list at:

http://sourceforge.net/projects/globalplatform/

# Debug Output

If you experience problems a DEBUG output is always helpful.
Set the variable GLOBALPLATFORM_DEBUG=1 in the environment. You can set
the logfile with GLOBALPLATFORM_LOGFILE=<file>. Under Windows by
default `C:\Temp\GlobalPlatform.log` is chosen. The log file must be
writable for the user.
Under Unix systems if syslog is available it will be used by default.
 The default log file under Unix systems is
`/tmp/GlobalPlatform.log` if syslog is not available or cannot be written by the user. 
If you don't have access to the syslog or don't want to use it you can still set the 
`GLOBALPLATFORM_LOGFILE` manually.
Keep in mind that the debugging output may contain sensitive information,
e.g. keys!

# Compilation

If you compile this on your own:

## Unix

You must have CMake installed. http://www.cmake.org/
This can be obtained in standard Unix distributions over the integrated package system.

On a command line type:

```bash
cd \path\to\globalplatform
cmake .
make
make install
```

It might be necessary to create a symlink to the correct library search directory, e.g. under Ubuntu 18.04 execute:

    sudo ln -s /usr/local/lib/libglobalplatform.so.6 /usr/lib/x86_64-linux-gnu/libglobalplatform.so.6
    
Or include the `/usr/local/lib ` under `/etc/ld.so.conf.d/` and run `sudo ldconfig`

## FreeBSD

Under FreeBSD the `pcsc-lite` libraries are not detected automatically. So you have to specify the locations:

    cmake -DPCSC_INCLUDE_DIRS=/usr/local/include -DPCSC_LIBRARIES=/usr/local/lib/libpcsclite.so

You also have to patch the PCSC sources under `/usr/local/include/PCSC`.
You have to replace the <> with "" for the includes.
See the compilation errors and fix the mentioned locations.

## Windows

__Note:__ After changing CMake parameters you must rebuild the files and delete the CMakeCache.txt file.

Tested with:

* Visual Studio 2013 Community Edition
* VISUAL C++ 2010 EXPRESS
* Visual Studio 2017

### Prerequisites

#### SDK

* Windows 7: Microsoft Windows SDK for Windows 7 and .NET Framework 4
http://msdn.microsoft.com/en-us/windows/bb980924
* Windows 10:
https://dev.windows.com/en-us/downloads/windows-10-sdk

##### VS 2010 Specific
If the setup fails look at http://blogs.msdn.com/b/windowssdk/archive/2009/09/16/windows-7-sdk-setup-common-installation-issues-and-fixes.aspx
and http://support.microsoft.com/kb/2717426. You have to install VC 2010 first to have the document explorer.
It might be necessary to remove the newer Microsoft Visual C++ 2010 x86 Redistributable and Microsoft Visual C++ 2010 x64 Redistributable  of VC 2010 because they are conflicting with the SDK.

#### Windows Driver Kit (WDK)

__Note:__ Only needed for platform independent builds

The WDK is needed to build a Windows platform independent version without getting into conflict with different
Windows `msvcrt` DLL versions.
http://www.microsoft.com/downloads/details.aspx?displaylang=en&FamilyID=36a2630f-5d56-43b5-b996-7633f2ec14ff

See http://kobyk.wordpress.com/2007/07/20/dynamically-linking-with-msvcrtdll-using-visual-c-2005/

#### OpenSSL
http://www.slproweb.com/products/Win32OpenSSL.html
* Win32 OpenSSL v1.0.1c or higher , not a "light" version
* Visual C++ 2008 Redistributables might be necessary
* Let it install the DLLs to the Windows system directory

#### zLib

The standard zLib from http://www.zlib.net/ is using the CDECL calling convention, but STDCALL is
needed for the compilation under Windows. So it does not work. See for details http://www.tannerhelland.com/5076/compile-zlib-winapi-wapi-stdcall/
This project contains a bundled pre-build version of zLib 1.2.8 in the upper module zlib-1.2.8/zlib-1.2.8.zip

If not using this version you will get errors like:

```
    unzip.c.obj : error LNK2019: unresolved external symbol "_inflate@8" in function "_unzReadCurrentFile@12".
```

  * Copy the zlibwapi.dll to `C:\Windows\System32` (dll32 version)

##### VISUAL C++ 2010 EXPRESS
  * Copy `zlib.h` and `zconf.h` from the sources of zlib to
    `C:\Program Files (x86)\Microsoft SDKs\Windows\v7.0A\Include`
  * Copy the file `zlibwapi.lib` from the lib directory to
    `C:\Program Files (x86)\Microsoft SDKs\Windows\v7.0A\Lib`

##### Visual Studio 2013 Community Edition

  * Copy `zlib.h` and `zconf.h` from the sources of zlib to
	`C:\Program Files (x86)\Windows Kits\8.1\Include\um`
  * Copy the file `zlibwapi.lib` from the lib directory to
    `C:\Program Files (x86)\Windows Kits\8.1\Lib\winv6.3\um\x86`

##### Visual Studio 2017

* Copy `zlib.h` and `zconf.h` from the sources of zlib to
`C:\Program Files (x86)\Windows Kits\10\Include\10.0.17134.0\um`
* Copy the file `zlibwapi.lib` from the lib directory to
	`C:\Program Files (x86)\Windows Kits\10\Lib\10.0.17134.0\um\x86`
* __Note:__ There can be several directories under `Lib` and `Include`. Use the version matching your compiler.

__Note:__ The paths given here are working only with the above toolchains respectively.
This path must be adjusted. When the command prompt of visual studio is open execute "set" and look for an
environment variable `WindowsSdkDir`. This value should be taken instead as search path for the right
sub directories.

#### Doxygen

You need Doxygen for generating the documentation.
www.doxygen.org/

#### CMake
http://www.cmake.org/
--> CMake 3.5.0 or higher

### Compile

* Launch Visual Studio Command Prompt / Developer Command Prompt

```
cd \path\to\globalplatform
cmake -G "NMake Makefiles" -DDEBUG=1 - for a debug version
cmake -G "NMake Makefiles" - for a release version  
```

* CMake will look for PC/SC, OpenSSL and zlib  
  If you get and error "Error 'LINK : fatal error LNK1123: failure during conversion to COFF"
  copy `C:\Windows\Microsoft.NET\Framework\v4.0.30319\cvtres.exe` to `C:\Program Files (x86)\Microsoft Visual Studio 10.0\VC\BIN\cvtres.exe`
  See http://stackoverflow.com/questions/10888391/error-link-fatal-error-lnk1123-failure-during-conversion-to-coff-file-inval    

* Make:

```
nmake  
```

* To build it downwards compatible you have to use a different set of common
    runtime libraries contained in the Windows Driver Development Kit. You have
    to specify with -DWINDDK_DIR the path to the DDK.  
* Complete example:

```
cmake -G "NMake Makefiles" -DWINDDK_DIR=C:\WinDDK\7600.16385.1 -DCMAKE_BUILD_TYPE=Release
nmake     
```  
* Done!   
* If you want to have Visual Studio project files run
  `cmake -G "Visual Studio 15 2017"` - Replace with your VS version
  You must have to remove the `CMakeCache.txt` before when using a different generator.    

#### Troubleshooting

* Problem:

```
    unzip.c.obj : error LNK2019: unresolved symbol "_inflate@8" in function "_unzReadCurrentFile@12".
```

* Solution:
If the zlib library is not in place or the zlib library was added only after executing
`cmake -G "NMake Makefiles"`` the make file does not contain the correct path.

* Problem:
  No verbose output for error detection is shown.

* Solution:
```
    nmake VERBOSE=1
```

* Problem:
```
CMake Error: Error: generator : NMake Makefiles
Does not match the generator used previously: Visual Studio 10 2010
Either remove the CMakeCache.txt file and CMakeFiles directory or choose a diffe
rent binary directory.
```

* Solution:
  Delete like mentioned `CMakeCache.txt` and the `CMakeFiles` directory in the top and `src`folder.

* Problem:
```
NMAKE : fatal error U1077: return code '0xc0000135'
```

* Solution: If you are updating from a previous Visual Studio Version the old compilation settings and
paths might be still stored in old files. Remove the CMakeFiles directory and all `*.cmake` files,
the `Makefile` and `CMakeCache.txt`.

## Source Packages

Execute:

    make/nmake package_source

## Binary Packages

Execute:

    make/nmake package

## Documentation

For documentation you also must have Doxygen installed.

Execute:

```
cmake .
make/nmake doc
```

## Ubuntu/Debian packages

You must also have `dput`, `pbuilder` and `debhelper` installed.

Execute:
```
cmake .
make package_ubuntu
```

The script ubuntu-package.sh iterates over all Ubuntu series and creates dsc files for Debian package creation or Launchpad uploads.

You can also upload the automatically created `sources.changes` to Launchpad. You must be registered there and you must have a `.dput.cf` in place. Follow the instructions on https://help.launchpad.net/Packaging/PPA/Uploading

Execute:

    make dput

If you have used the ubuntu-package.sh script you must manually upload the source.changes files.

Execute:

    dput gpsnapshots-ppa libglobalplatform6_6.1.0-0ubuntu1SNAPSHOT20120520195953+0200~precise.changes

You can create a Ubuntu/Debian package from a `dsc` file.

Execute:

```
dpkg-source -x libglobalplatform6_6.1.0-0ubuntu1SNAPSHOT20120520195953+0200~precise.dsc
cd libglobalplatform6-6.1.0
fakeroot debian/rules binary
```

## Debug Builds

To be able to debug the library enable the debug symbols:

```
cmake -DDEBUG=ON

```

## Testing

Testing is only supported under Linux for now. 

2 dependencies are required:

 * [cmocka](https://cmocka.org/)
 * [check](https://libcheck.github.io/check/)
 
 Under Ubuntu this can be installed with:
 
    sudo apt-get install libcmocka-dev
    sudo apt-get install check

To generate the tests execute:

```
cmake -DTESTING=ON -DDEBUG=ON
make
cd src
GLOBALPLATFORM_DEBUG=1
ctest -V
```

For the unit tests a JCOP v2.2 41 card is used.

## CMake Issues

You must rebuild the build system if your build tools have changed. Otherwise
CMake uses out dated values and compilation might fail. You have to delete manually
the `CMakeCache.txt` file and also the CMake specific directories like `CMakeFiles` and
`cmake_install.cmake` in the top folder and the `src` directory.

If your are using Cygwin and you have installed the GNU compiler tools and the
bin directory is on the PATH environment variable CMake will favor these tools
and the linking step will fail. Remove the Cygwin bin directory from the path.  
