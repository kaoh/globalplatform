# Summary

This is the top level project for the GlobalPlatform library for providing access to OpenPlatform 2.0.1' and GlobalPlatform 2.1.1 conforming smart cards and later, the command line shell GPShell using the GlobalPlatform library and the PC/SC connection plugin for the GlobalPlatform Library.

# Compilation

Consult the individual sub projects for further instructions and prerequisites. It is also possible to compile the sub projects individually.

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

## Windows

Launch Visual Studio Command Prompt / Developer Command Prompt:

```
cd \path\to\globalplatform
cmake -G "NMake Makefiles"  
nmake
```

## Documentation

For documentation Doxygen must be installed.

Execute:

    make/nmake doc

## Binary Packages

    Execute:

        make/nmake package

## Source Packages

Execute:

    make/nmake package_source

## Debug Builds

To be able to debug the library enable the debug symbols:

```
cmake . -DDEBUG=ON

```

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

The variable `GLOBALPLATFORM_DEBUG=1` in the environment must be set. The logfile can be set with `GLOBALPLATFORM_LOGFILE=<file>`. Under Windows by default `C:\Temp\GlobalPlatform.log` is chosen, under Unix systems if syslog is available it will be used by default. The default log file under Unix systems is `/tmp/GlobalPlatform.log` if syslog is not available.

## Issues and Contact

For more information contact the author through the mailing list at:

http://sourceforge.net/projects/globalplatform/
