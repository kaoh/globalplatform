# Summary

This is the top level project for the GlobalPlatform library for providing access to OpenPlatform 2.0.1' and GlobalPlatform 2.1.1 conforming smart cards and later, the command line shell GPShell using the GlobalPlatform library and the PC/SC connection plugin for the GlobalPlatform Library.

# Pre-build Packages

There are Homebrew package for [Linux and MacOS](https://github.com/kaoh/homebrew-globalplatform)

For Windows binaries can be downloaded from [SourceForge](https://sourceforge.net/projects/globalplatform/files/GPShell/).

__NOTE:__ The [Microsoft Visual C++ 2015 Redistributable](https://www.microsoft.com/en-us/download/confirmation.aspx?id=52685) must be also installed.

# Compilation

Clone the project from GitHub or download the zip file (also available under the Clone tab).

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
* [Graphviz](https://graphviz.org) for generating graphics in the documentation
* [OpenSSL](http://www.openssl.org/) (MacOS is already providing this as LibreSSL)
* [zlib](http://www.zlib.net/) (MacOS should already bundle this, for Windows a pre-built version is included)
* [cmocka](https://cmocka.org/) for running the tests

## Unix

Install the dependencies with `brew` or your distribution's package system:

~~~
brew install openssl doxygen pandoc cmake cmocka zlib graphviz
~~~

### Compile

```
cd \path\to\globalplatform
cmake .
make
make doc
make install
```

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

## Windows

Install the dependencies with [Chocolatey](https://chocolatey.org) in an administrator's PowerShell or install the dependencies manually:

~~~
choco install cmake doxygen.install graphviz
~~~

__NOTE:__ `zlib` must be installed manually. Copy the zlibwapi.dll to `C:\Windows\System32` from the upper module's `zlib-1.2.8/zlib-1.2.8.zip`.

__NOTE:__ OpenSSL must be installed manually. Chocolatey is using the systems architecture, which is nowadays 64 bit, but the compilation needs the 32 bit version. Download [OpenSSL](https://slproweb.com/products/Win32OpenSSL.html) and choose the Win32 bit version and no light version.

### Compile

Launch Visual Studio Command Prompt / Developer Command Prompt.
It will be necessary to set the `ZLIB_ROOT`. Use the pre-built `zlib` version of the project for convenience.

```
cd \path\to\globalplatform
cmake -G "NMake Makefiles" -DZLIB_ROOT="C:\Users\john\Desktop\globalplatform\zlib-1.2.8\win32-build"
nmake
```

## Documentation

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

To generate the tests execute:

```
cmake . -DTESTING=ON -DDEBUG=ON
make
make test
```

## Debug Output

The variable `GLOBALPLATFORM_DEBUG=1` in the environment must be set. The logfile can be set with `GLOBALPLATFORM_LOGFILE=<file>`. Under Windows by default `C:\Temp\GlobalPlatform.log` is chosen, under Unix systems if syslog is available it will be used by default. The default log file under Unix systems is `/tmp/GlobalPlatform.log` if syslog is not available.

# GitHub Documentation

The GitHub documentation is located under the `docs` folder and is using [Jekyll](https://jekyllrb.com).

Useful commands inside the `docs` folder:

* Cleaning local generated site: `bundle exec jekyll clean`
* Serving site in a local browser updating automatically on content changes: `bundle exec jekyll serve`
* Update configuration in the Gemfile: `bundle update`

# Issues

For issues please use the [GitHub issue tracker](https://github.com/kaoh/globalplatform/issues).

You can also use the [Mailing List](https://sourceforge.net/p/globalplatform/mailman/) or ask a question on Stack Overflow assigning the tags `gpshell` or `globalplatform`.
