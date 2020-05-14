# Summary

- Title    : Global Platform Shell (GPShell)
- Authors  :  
 * Karsten Ohme <k_o_@users.sourceforge.net>
 * snitmo@gmail.com
- License  : See file COPYING.LESSER
- Requires :
 * GlobalPlatform http://sourceforge.net/projects/globalplatform/
 * PC/SC Lite http://www.musclecard.com/ (for UNIXes)
 * OpenSSL http://www.openssl.org/
 * zlib http://www.zlib.net/

 GPShell is a script interpreter which talks to a smart card.  It is written on top of the GlobalPlatform library, which was developed by Karsten Ohme.
 It uses smart card communication protocols ISO-7816-4 and OpenPlatform 2.0.1 and GlobalPlatform 2.1.1.
 It can establish a secure channel with a smart card, load, instantiate, delete, list applets on a smart card.

 You need also the libraries GlobalPlatform 6.0.0, zlib 1.2.3 (zlib1.dll) and OpenSSL >= v1.0.1c (`libeay32.dll` and `ssleay32.dll`) or
 compatible and must place them in the directory where GPShell is called or better the system directory (`C:\Windows\System32` or `/usr/(local/)lib` usually).
 You also need at least one connection plugin, e.g. the shipped `gppcscconnectionplugin` to use PC/SC.

 For MacOSX you might set:

      export DYLD_LIBRARY_PATH=/opt/local/lib

 so that all needed libraries are found.

For more information contact the author through the mailing list at:

http://sourceforge.net/projects/globalplatform/

# Debug Output

If you experience problems a DEBUG output is always helpful.
Set the variable GLOBALPLATFORM_DEBUG=1 in the environment. You can set
the logfile with GLOBALPLATFORM_LOGFILE=<file>. Under Windows by
default `C:\Temp\GlobalPlatform.log` is chosen. The log file must be
writable for the user. The default log file under Unix systems is
`/tmp/GlobalPlatform.log`. But usually syslog is available and this will
be used by default, so you may have to specify the log file manually,
if you don't have access to the syslog or don't want to use it.
Keep in mind that the debugging output may contain sensitive information,
e.g. keys!

__!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!__

__PLEASE OBEY THAT EVERY CARD GETS LOCKED AFTER A FEW (USUALLY 10) UNSUCCESSFUL MUTUAL AUTHENTICATIONS.
THE CONTENTS OF A LOCKED CARD CANNOT BE MANAGED ANYMORE (DELETED, INSTALLED)!!!
IF YOU EXPERIENCE SOME UNSUCCESSFUL MUTUAL AUTHENTICATION ATTEMPS FIRST EXECUTE A SUCCESSFUL MUTUAL AUTHENTICATION WITH A KNOWN WORKING PROGRAM
TO RESET THE RETRY COUNTER BEFORE YOU PROCEED WITH GPSHELL. CHECK THE PARAMETERS FOR MUTUAL AUTHENTICATION (KEYS, SECURITY PROTOCOL) AND ASK IF ANYBODY KNOWS IF THE CARD IS SUPPORTED.__

__!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!__

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

See the instructions in the `globalplatform` module in the upper directory for this.

#### CMake
http://www.cmake.org/
--> CMake 3.5.0 or higher

### Compile

* Launch Visual Studio Command Prompt / Developer Command Prompt

```
cmake -G "NMake Makefiles" for a release version
cmake -G "NMake Makefiles" -DDEBUG=1 for a debug version  
```

* CMake will look for PC/SC, OpenSSL and zlib  
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

    dput gpsnapshots-ppa gpshell_1.4.4+5SNAPSHOT20120524080448+0200-0ubuntu1~precise.changes

You can create a Ubuntu/Debian package from a `dsc` file.

Execute:

```
dpkg-source -x gpshell_1.4.4+5SNAPSHOT20120524080448+0200-0ubuntu1~precise.dsc
cd gpshell-1.4.4+5
fakeroot debian/rules binary
```

## Debug Builds

To be able to debug the library enable the debug symbols:

```
cmake -DDEBUG=ON

```

## Man Page

The man page uses the groff syntax. To render a preview of the result use:

    groff -man -T ascii src/gpshell.1
    
## CMake Issues

 
You must rebuild the build system if your build tools have changed. Otherwise
CMake uses out dated values and compilation might fail. You have to delete manually
the `CMakeCache.txt` file and also the CMake specific directories like `CMakeFiles` and
`cmake_install.cmake` in the top folder and the `src` directory.

If your are using Cygwin and you have installed the GNU compiler tools and the
bin directory is on the PATH environment variable CMake will favor these tools
and the linking step will fail. Remove the Cygwin bin directory from the path.  

## Troubleshooting

See README in `globalplatform` module.
