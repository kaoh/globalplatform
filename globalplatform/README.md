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
* [CMake 3.5.1](http://www.cmake.org/) or higher is needed
* [PC/SC Lite](https://pcsclite.apdu.fr) (only for UNIXes, Windows and MacOS are already including this)
* [Doxygen](www.doxygen.org/) for generating the documentation
* [Graphviz](https://graphviz.org) for generating graphics in the documentation
* [OpenSSL](http://www.openssl.org/) (On MacOS use OpenSSL 3)
* [zlib](http://www.zlib.net/) (MacOS should already bundle this, for Windows a pre-built version is included)
* [cmocka](https://cmocka.org/) for running the tests

## Unix

Install the dependencies with [`brew`](https://docs.brew.sh/Homebrew-on-Linux) or your distribution's package system.

brew:

~~~shell
brew install openssl doxygen cmake cmocka zlib graphviz pcsc-lite pkg-config
~~~

Ubuntu:

~~~shell
apt-get install libssl-dev doxygen cmake libcmocka0 zlib1g-dev graphviz pcscd libpcsclite-dev pkg-config
~~~

### Compile

__NOTE:__ If using Homebrew in parallel and having not used Homebrew for installing the dependencies but the distribution's package manager then several tools and libraries can be hidden by Homebrew or are not installed in Homebrew (`pkgconfig`, `PC/SC Lite`, `cmocka`, ...). One option is to install these tools and libraries with `brew` or remove the Homebrew path from the `PATH` variable temporarily
(which should be `./home/linuxbrew/.linuxbrew/bin:/home/linuxbrew/.linuxbrew/sbin`).

```shell
cd \path\to\globalplatform
cmake .
make
make doc
make install
```

__NOTE:__ The Homebrew version of pcsc-lite is not a fully functional version. It is missing the USB drivers and is also not started as a system service. The distribution's version of pcscd should be installed. Under Linux the Homebrew version of pcsc-lite must be unlinked:

~~~shell
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

~~~shell
brew install openssl@3 doxygen cmocka pandoc cmake graphviz
~~~

### Compile

It is necessary to set the `OPENSSL_ROOT_DIR`. In case of the usage of Homebrew this works:

```shell
cd \path\to\globalplatform
cmake . -DCMAKE_C_COMPILER=/usr/bin/gcc -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)
make
make install
```

__NOTE:__ `CMAKE_C_COMPILER` is required if Xcode is installed. CMake would favor the Xcode compiler leading to potential runtime errors.

__NOTE:__ The included LibreSSL is causing this [issue]https://stackoverflow.com/questions/58446253/xcode-11-ld-error-your-binary-is-not-an-allowed-client-of-usr-lib-libcrypto-dy).

In case the system is using a different package manager other settings will be necessary.

## Windows

Install the dependencies with [Chocolatey](https://chocolatey.org) in an administrator's PowerShell or install the dependencies manually:

~~~shell
choco install cmake doxygen.install graphviz
~~~

* For CMocka a pre-built version is used from the `cmock-cmocka-1.1.5` directory.
* For `zlib` a pre-built version is used the `zlib-1.2.8` directory.
* OpenSSL must be installed manually. Chocolatey is using the systems architecture, which is nowadays 64 bit, but the compilation needs the 32 bit version. Download [OpenSSL](https://slproweb.com/products/Win32OpenSSL.html) and choose the Win32 bit version and no light version.

### Compile

Launch Visual Studio Command Prompt / Developer Command Prompt / Developer PowerShell:

It will be necessary to set the `ZLIB_ROOT` and `CMOCKA_ROOT` and `OPENSSL_ROOT_DIR`. Use the pre-built versions of the project for convenience.

```shell
cd \path\to\globalplatform
cmake -G "NMake Makefiles" -DOPENSSL_ROOT_DIR="C:\Program Files (x86)\OpenSSL-Win32" -DZLIB_ROOT="C:\Users\john\Desktop\globalplatform\zlib-1.2.8\win32-build" -DCMOCKA_ROOT="C:\Users\john\Desktop\globalplatform\cmocka-cmocka-1.1.5\build-w32"
nmake
```

__NOTE:__ CMake might fail if different compilers are on the path, e.g. MingW. CMake will pick the wrong linker.
A way to set the linker explicitly is (replace the linker path with the correct one for your version):

~~~shell
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

```shell
cmake . -DTESTING=ON -DDEBUG=ON
make
make test
```

__NOTE:__ On Windows: When using the Visual Studio command line the neccessary mock functions are not supported by the linker and tests cannot be executed. See also the detailed instructions for running the tests under Windows in section "Special Notes for Windows".

## Debug Output

If you experience problems a DEBUG output is helpful.
The variable `GLOBALPLATFORM_DEBUG=1` in the environment must be set. The logfile can be set with `GLOBALPLATFORM_LOGFILE=<file>`. Under Windows by default `C:\Temp\GlobalPlatform.log` is chosen. The log file must be writable for the user.
Under Unix systems if syslog is available it will be used by default.
 The default log file under Unix systems is `/tmp/GlobalPlatform.log` if syslog is not available or cannot be written by the user. If you don't have access to the syslog or don't want to use it you can still set the
`GLOBALPLATFORM_LOGFILE` manually. Keep in mind that the debugging output may contain sensitive information, e.g. keys!

## Special Notes for Windows

### Prerequisites

#### OpenSSL

[Win32 OpenSSL](http://www.slproweb.com/products/Win32OpenSSL.html)

* Win32 OpenSSL v1.0.1c or higher, not a "light" version
* Let it install the DLLs to the Windows directory

#### zLib

The standard zLib from http://www.zlib.net/ is using the CDECL calling convention, but STDCALL is
needed for the compilation under Windows. So it does not work. See for details http://www.tannerhelland.com/5076/compile-zlib-winapi-wapi-stdcall/

__NOTE:__ This project contains a bundled pre-build version of zLib 1.2.8 in the upper module's `zlib-1.2.8/zlib-1.2.8.zip`

Copy the `zlibwapi.dll` to the Windows directory `C:\Windows` to be able to find the dll during the test execution.

If not using this version you will get errors like:

> unzip.c.obj : error LNK2019: unresolved external symbol "_inflate@8" in function "_unzReadCurrentFile@12".

#### CMocka

The available binary version of CMocka is linked against an older debug version of `msvcr120d.dll` which is not available as download.
Do not use this version and install it, CMake will detect it first and the tests would not run.
A pre-built version for VS 2022 is available in the top level directory `cmock-cmocka-1.1.5/build-w32`.

Copy the `cmocka.dll` to the Windows directory `C:\Windows` to be able to find the dll during the test execution.

If CMocka has to be rebuilt for a different VS version the steps should be:

~~~shell
mkdir build_w32
cmake .. -G "NMake Makefiles"
nmake
~~~

The compiled dll and lib have to be placed in the `build-w32` directory matching the directory structure existing.

### Visual Studio

The build was tested against Visual Studio 2022, but should also work for earlier versions.

#### SDK

Visual Studio 2022 already bundles the SDK.

When using lower VS versions it might be necessary to download the SDK in addition:

* [Windows 10/11](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/)
* [Windows 7 (Microsoft Windows SDK for Windows 7 and .NET Framework 4)](http://msdn.microsoft.com/en-us/windows/bb980924)


#### Visual Studio Project Files

  `cmake -G "Visual Studio 15 2017"` - Replace with your VS version

__NOTE:__ You must have to remove the `CMakeCache.txt` and related file before when using a different generator. See section "Clean CMake Files".

__NOTE:__ VS 2022 is supporting CMake and is using Ninja for the build files. The CMake files have to be cleaned and the CMake variables configured in the IDE.

#### Windows Backward Compatible Visual Studio Build

The WDK is needed to build a Windows platform independent version without getting into conflict with different
Windows `msvcrt` DLL versions.
http://www.microsoft.com/downloads/details.aspx?displaylang=en&FamilyID=36a2630f-5d56-43b5-b996-7633f2ec14ff

See http://kobyk.wordpress.com/2007/07/20/dynamically-linking-with-msvcrtdll-using-visual-c-2005/

* To build it backwards compatible for lower Windows versions you have to use a different set of common runtime libraries contained in the Windows Driver Development Kit. It is necessary to specify with `-DWINDDK_DIR` the path to the DDK.  
* Complete example:

```shell
cmake -G "NMake Makefiles" -DWINDDK_DIR=C:\WinDDK\7600.16385.1 -DCMAKE_BUILD_TYPE=Release
nmake     
```

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
rm -f CMakeCache.txt && rm -f cmake_install.cmake && rm -rf CMakeFiles && rm -rf _CPack_Packages && rm -f CPack* && rm -rf src/CMakeFiles
```

The file `cleanCMake.sh` in the parent folder can be used which is cleaning all projects.
