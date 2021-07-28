# Summary

This is a C library providing an API to access OpenPlatform 2.0.1' and
GlobalPlatform 2.1.1 conforming smart cards and later.

# Compilation

Clone the project from GitHub or download the zip file (also available under the Clone tab).

## Prerequisites

Use a suitable packet manager for your OS or install the programs and libraries manually if applicable.

* Compiler Suite:
  * Linux: Termed `build-essential` in Debian based distributions (gcc, make)
  * MacOS: Xcode
  * Windows: Visual Studio and SDK
* [CMake 3.5.0](http://www.cmake.org/) or higher is needed
* [PC/SC Lite](https://pcsclite.apdu.fr) (only for UNIXes, Windows and MacOS is already including this)
* [Doxygen](www.doxygen.org/) for generating the documentation
* [Graphviz](https://graphviz.org) for generating graphics in the documentation
* [OpenSSL](http://www.openssl.org/) (MacOS is already providing this as LibreSSL)
* [zlib](http://www.zlib.net/) (MacOS should already bundle this, for Windows a pre-built version is included)
* [cmocka](https://cmocka.org/) for running the tests

## Unix

Install the dependencies with `brew` or your distribution's package system:

~~~
brew install openssl doxygen cmake cmocka zlib graphviz pcsc-lite
~~~

### Compile

__NOTE:__ If using Homebrew in parallel and having not used Homebrew for installing the dependencies but the distribution's package manager then several tools and libraries can be hidden by Homebrew or are not installed in Homebrew (`pkgconfig`, `PC/SC Lite`, `cmocka`, ...). One option is to install these tools and libraries with `brew` or remove the Homebrew path from the `PATH` variable temporarily
(which should be `./home/linuxbrew/.linuxbrew/bin:/home/linuxbrew/.linuxbrew/sbin`).

```
cd \path\to\globalplatform
cmake .
make
make doc
make install
```

__NOTE:__ The Homebrew version of pcsc-lite is not a fully functional version. It is missing the USB drivers and is also not started as a system service. The distribution's version of pcscd should be installed. Under Linux the Homebrew version of pcsc-lite must be unlinked:

~~~
brew remove --ignore-dependencies pcsc-lite
~~~

###  Set Library Search Directory

It might be necessary to create a symlink to the correct library search directory, e.g. under Ubuntu 18.04 execute:

    sudo ln -s /usr/local/lib/libglobalplatform.so.<version> /usr/lib/x86_64-linux-gnu/libglobalplatform.so.<version>

Replace `<version>` with the library version.

Or include the `/usr/local/lib ` under `/etc/ld.so.conf.d/` and run `sudo ldconfig`

## MacOS

The compilation was executed on a system with [Homebrew](https://brew.sh) as package manager.

Install the dependencies with `brew`:

~~~
brew install openssl doxygen cmocka pandoc cmake graphviz
~~~

### Compile

It can be necessary to set the `OPENSSL_ROOT_DIR`. In case of the usage of Homebrew this works:

```
cd \path\to\globalplatform
cmake . -DOPENSSL_ROOT_DIR=$(brew --prefix openssl)
make
make install
```

In case the system is using a different package manager other settings will be necessary.

## Windows

Install the dependencies with [Chocolatey](https://chocolatey.org) in an administrator's PowerShell or install the dependencies manually:

~~~
choco install cmake doxygen.install openssl graphviz
~~~

__NOTE:__ `zlib` must be installed manually. Copy the zlibwapi.dll to `C:\Windows\System32` from the upper module's `zlib-1.2.8/zlib-1.2.8.zip`.

__NOTE:__ OpenSSL must be installed manually. Chocolatey is using the systems architecture, which is nowadays 64 bit, but the compilation needs the 32 bit version. Download [OpenSSL](https://slproweb.com/products/Win32OpenSSL.html) and choose the Win32 bit version and no light version.

### Compile

Launch Visual Studio Command Prompt / Developer Command Prompt:
It will be necessary to set the `ZLIB_ROOT`. Use the pre-built `zlib` version of the project for convenience.

```
cd \path\to\globalplatform
cmake -G "NMake Makefiles" -DZLIB_ROOT="C:\Users\john\Desktop\globalplatform\zlib-1.2.8\win32-build"
nmake
```

__NOTE:__ CMake might fail if different compilers are on the path, e.g. MingW. CMake will pick the wrong linker.
A way to set the linker explicitly is (replace the linker path with the correct one for your version):

~~~
cmake -G "NMake Makefiles" -DCMAKE_LINKER="C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\bin\link.exe" -DCMAKE_C_LINK_EXECUTABLE=link.exe -DTESTING=ON -DDEBUG=ON
~~~

## FreeBSD

__NOTE:__ This section was not updated for a while and thus might work in the meanwhile without any patches.

Under FreeBSD the `pcsc-lite` libraries are not detected automatically. So you have to specify the locations:

    cmake -DPCSC_INCLUDE_DIRS=/usr/local/include -DPCSC_LIBRARIES=/usr/local/lib/libpcsclite.so

You also have to patch the PCSC sources under `/usr/local/include/PCSC`.
You have to replace the <> with "" for the includes.
See the compilation errors and fix the mentioned locations.

## Documentation

For documentation Doxygen must be installed and also the `dot` package for getting graphics.

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

To generate the tests execute:

```
cmake . -DTESTING=ON -DDEBUG=ON
make
make test
```

__NOTE:__ This is not supported under Windows.

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
* Visual Studio 2015
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

__NOTE:__ This project contains a bundled pre-build version of zLib 1.2.8 in the upper module's `zlib-1.2.8/zlib-1.2.8.zip`

If not using this version you will get errors like:

```
    unzip.c.obj : error LNK2019: unresolved external symbol "_inflate@8" in function "_unzReadCurrentFile@12".
```

  * Copy the zlibwapi.dll to `C:\Windows\System32` (dll32 version)

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

## Checking Memory Leaks / Stack Corruption

[Valgrind](https://valgrind.org) can be used to check for memory leaks during the execution:

~~~
valgrind --leak-check=full gpshell listSCP03.txt
~~~

When passing `-DDEBUG=ON` to `cmake` the ` fsanitize=address` is passed as `CFLAG` to identify stack corruptions.

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
