# Summary

This is a C library providing an API to access OpenPlatform 2.0.1' and
GlobalPlatform 2.1.1 conforming smart cards and later.

# Compilation

## Prerequisites

Use a suitable packet manager for your OS or install the programs and libraries manually if applicable.

* Compiler Suite:
  * Linux: Termed `build-essential` in Debian based distributions (gcc, make)
  * MacOS: Xcode
  * Windows: Visual Studio and SDK
* [CMake 3.5.0](http://www.cmake.org/) or higher is needed
* [PC/SC Lite](https://pcsclite.apdu.fr) (only for UNIXes, Windows and MacOS is already including this)
* [Doxygen](www.doxygen.org/) for generating the documentation
* [OpenSSL](http://www.openssl.org/) (MacOS should already bundle this as LibreSSL, but the original version might be still needed)
* [zlib](http://www.zlib.net/) (MacOS should already bundle this, for Windows a pre-built version is included)

## Unix

You must have CMake installed. http://www.cmake.org/
This can be obtained in standard Unix distributions over the integrated package system.

On a command line type:

```
cd \path\to\globalplatform
cmake .
make
make doc
make install
```

## MacOS

The compilation was executed on a system with [Homebrew](https://brew.sh) as package manager.

It can be necessary to set the `OPENSSL_ROOT_DIR`. In case of the usage of Homebrew this works:

```
cd \path\to\globalplatform
cmake . -DOPENSSL_ROOT_DIR=$(brew --prefix openssl)
make
make install
```

In case the system is using a different package manager further settings might be necessary.

### Linux

It might be necessary to create a symlink to the correct library search directory, e.g. under Ubuntu 18.04 execute:

    sudo ln -s /usr/local/lib/libglobalplatform.so.<version> /usr/lib/x86_64-linux-gnu/libglobalplatform.so.<version>

Replace `<version>` with the library version.

Or include the `/usr/local/lib ` under `/etc/ld.so.conf.d/` and run `sudo ldconfig`

## Windows

Launch Visual Studio Command Prompt / Developer Command Prompt:

```
cd \path\to\globalplatform
cmake -G "NMake Makefiles"  
nmake
nmake doc
```

## FreeBSD

__NOTE:__ This section was not updated for a while and thus might work in the meanwhile without any patches.

Under FreeBSD the `pcsc-lite` libraries are not detected automatically. So you have to specify the locations:

    cmake -DPCSC_INCLUDE_DIRS=/usr/local/include -DPCSC_LIBRARIES=/usr/local/lib/libpcsclite.so

You also have to patch the PCSC sources under `/usr/local/include/PCSC`.
You have to replace the <> with "" for the includes.
See the compilation errors and fix the mentioned locations.

## Documentation

For documentation Doxygen must be installed.

Execute:

    make/nmake doc

After being installed with `make install` the HTML documentation can be found in `/usr/share/doc/libglobalplatform<version>` or `/usr/local/share/doc/libglobalplatform<version>` or `~/.linuxbrew/share/doc/libglobalplatform<version>`


## Binary Packages

Execute:

    make/nmake package

## Source Packages

Execute:

    make/nmake package_source

## Debug Builds

To be able to debug the library enable the debug symbols:

    cmake . -DDEBUG=ON

## Testing

 * [cmocka](https://cmocka.org/) is required

Under Ubuntu this can be installed with:

    sudo apt-get install libcmocka-dev

To generate the tests execute:

```
cmake . -DTESTING=ON -DDEBUG=ON
make
make test
```

## Debug Output

If you experience problems a DEBUG output is helpful.
The variable `GLOBALPLATFORM_DEBUG=1` in the environment must be set. The logfile can be set with `GLOBALPLATFORM_LOGFILE=<file>`. Under Windows by default `C:\Temp\GlobalPlatform.log` is chosen. The log file must be writable for the user.
Under Unix systems if syslog is available it will be used by default.
 The default log file under Unix systems is `/tmp/GlobalPlatform.log` if syslog is not available or cannot be written by the user. If you don't have access to the syslog or don't want to use it you can still set the
`GLOBALPLATFORM_LOGFILE` manually. Keep in mind that the debugging output may contain sensitive information, e.g. keys!

## Special Notes for Windows

Tested with:

* Visual Studio 2013 Community Edition
* VISUAL C++ 2010 EXPRESS
* Visual Studio 2017

### Prerequisites

#### SDK

* [Windows 7 (Microsoft Windows SDK for Windows 7 and .NET Framework 4)](http://msdn.microsoft.com/en-us/windows/bb980924)
* [Windows 10](https://dev.windows.com/en-us/downloads/windows-10-sdk)

##### VS 2010 Specific

If the setup fails look at http://blogs.msdn.com/b/windowssdk/archive/2009/09/16/windows-7-sdk-setup-common-installation-issues-and-fixes.aspx
and http://support.microsoft.com/kb/2717426. You have to install VC 2010 first to have the document explorer.
It might be necessary to remove the newer Microsoft Visual C++ 2010 x86 Redistributable and Microsoft Visual C++ 2010 x64 Redistributable  of VC 2010 because they are conflicting with the SDK.

#### Windows Driver Kit (WDK)

__NOTE:__ Only needed for platform independent builds

The WDK is needed to build a Windows platform independent version without getting into conflict with different
Windows `msvcrt` DLL versions.
http://www.microsoft.com/downloads/details.aspx?displaylang=en&FamilyID=36a2630f-5d56-43b5-b996-7633f2ec14ff

See http://kobyk.wordpress.com/2007/07/20/dynamically-linking-with-msvcrtdll-using-visual-c-2005/

#### OpenSSL

[Win32 OpenSSL](http://www.slproweb.com/products/Win32OpenSSL.html)

* Win32 OpenSSL v1.0.1c or higher, not a "light" version
* Visual C++ 2008 Redistributables might be necessary
* Let it install the DLLs to the Windows system directory

#### zLib

The standard zLib from http://www.zlib.net/ is using the CDECL calling convention, but STDCALL is
needed for the compilation under Windows. So it does not work. See for details http://www.tannerhelland.com/5076/compile-zlib-winapi-wapi-stdcall/

__NOTE:__ This project contains a bundled pre-build version of zLib 1.2.8 in the upper module `zlib-1.2.8/zlib-1.2.8.zip`

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
* __NOTE:__ There can be several directories under `Lib` and `Include`. Use the version matching your compiler.

__NOTE:__ The paths given here are working only with the above toolchains respectively.
This path must be adjusted. When the command prompt of visual studio is open execute "set" and look for an
environment variable `WindowsSdkDir`. This value should be taken instead as search path for the right
sub directories.

#### Windows Backward Compatible Build

* To build it backwards compatible for lower Windows versions you have to use a different set of common runtime libraries contained in the Windows Driver Development Kit. It is necessary to specify with `-DWINDDK_DIR` the path to the DDK.  
* Complete example:

```
cmake -G "NMake Makefiles" -DWINDDK_DIR=C:\WinDDK\7600.16385.1 -DCMAKE_BUILD_TYPE=Release
nmake     
```

* If you want to have Visual Studio project files run
  `cmake -G "Visual Studio 15 2017"` - Replace with your VS version
  You must have to remove the `CMakeCache.txt` before when using a different generator.    

#### Compile Errors

Problem:

> "Error 'LINK : fatal error LNK1123: failure during conversion to COFF"
  copy `C:\Windows\Microsoft.NET\Framework\v4.0.30319\cvtres.exe` to `C:\Program Files (x86)\Microsoft Visual Studio 10.0\VC\BIN\cvtres.exe`

Solution: See http://stackoverflow.com/questions/10888391/error-link-fatal-error-lnk1123-failure-during-conversion-to-coff-file-inval    

Problem:

> unzip.c.obj : error LNK2019: unresolved symbol "\_inflate@8" in function "\_unzReadCurrentFile@12".

Solution: If the zlib library is not in place or the zlib library was added only after executing
`cmake -G "NMake Makefiles"` the make file does not contain the correct path.

Problem: No verbose output for error detection is shown.

Solution: `nmake VERBOSE=1`

Problem:

> CMake Error: Error: generator : NMake Makefiles
Does not match the generator used previously: Visual Studio 10 2010
Either remove the CMakeCache.txt file and CMakeFiles directory or choose a diffe
rent binary directory.

Solution: See section "Clean CMake Files"

Problem:

> NMAKE : fatal error U1077: return code '0xc0000135'

Solution: If you are updating from a previous Visual Studio Version the old compilation settings and
paths might be still stored in old files. See section "Clean CMake Files"

Problem: Cygwin GNU compiler on PATH variable.

Solution: If your are using Cygwin and you have installed the GNU compiler tools and the
bin directory is on the PATH environment variable CMake will favor these tools
and the linking step will fail. Remove the Cygwin bin directory from the path.

## Clean CMake Files

You must rebuild the build system if your build tools have changed. Otherwise
CMake uses out dated values and compilation might fail. You have to delete manually
the `CMakeCache.txt` file and also the CMake specific directories like `CMakeFiles` and
`cmake_install.cmake` in the top folder and the `src` directory.

E.g. under Linux:

```
rm -f CMakeCache.txt && rm -f cmake_install.cmake && rm -rf CMakeFiles && rm -rf _CPack_Packages && rm -f CPack* && rm -rf src/CMakeFiles && cmake -DTESTING=ON -DDEBUG=ON .
```

The file `cleanCMake.sh` in the parent folder can be used which is cleaning all projects.
