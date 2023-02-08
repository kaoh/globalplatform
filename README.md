# Summary

This is the top level project for the GlobalPlatform library for providing access to OpenPlatform 2.0.1' and GlobalPlatform 2.1.1 conforming smart cards and later, the command line shell GPShell using the GlobalPlatform library and the PC/SC connection plugin for the GlobalPlatform Library.

# Pre-build Packages

There are Homebrew package for [Linux and MacOS](https://github.com/kaoh/homebrew-globalplatform)

Windows binaries can be downloaded from the [GitHub release page](https://github.com/kaoh/globalplatform/releases) or from [SourceForge](https://sourceforge.net/projects/globalplatform/files/GPShell/).

Please read also the [manual of GPShell]( https://github.com/kaoh/globalplatform/blob/master/gpshell/src/gpshell.1.md) if you are interested in the command line
or use the installed man page with `man gpshell` under Unix like systems.
There are several script examples available. See the [.txt files](https://github.com/kaoh/globalplatform/tree/master/gpshell) or look into the local file systems
under `(/usr/ | /home/linuxbrew/.linuxbrew/) share/doc/gpshell1/`.

# Compilation

Cor lone the project from GitHub or download the zip file (also available under the Clone tab).

Consult the individual sub projects for further instructions and prerequisites. It is also possible to compile the sub projects individually.

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
* [Pandoc](https://pandoc.org/installing.html) for generating the man page the tests

## Unix

Install the dependencies with `brew` or your distribution's package manager:

~~~shell
brew install openssl doxygen pandoc cmake cmocka zlib graphviz pcsc-lite
~~~

Ubuntu:

~~~shell
apt-get install libssl-dev doxygen cmake libcmocka0 zlib1g-dev graphviz pcscd libpcsclite-dev pkg-config
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

## MacOS

The compilation was executed on a system with [Homebrew](https://brew.sh) as package manager.

Install the dependencies with `brew`:

~~~
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

## Windows

Install the dependencies with [Chocolatey](https://chocolatey.org) in an administrator's PowerShell or install the dependencies manually:

~~~shell
choco install cmake doxygen.install graphviz
~~~

* For CMocka a pre-built version is used from the `cmock-cmocka-1.1.5` directory.
* For `zlib` a pre-built version is used the `zlib-1.2.8` directory.
* OpenSSL must be installed manually. Chocolatey is using the systems architecture, which is nowadays 64 bit, but the compilation needs the 32 bit version. Download [OpenSSL](https://slproweb.com/products/Win32OpenSSL.html) and choose the Win32 bit version and no light version.

### Compile

Launch Visual Studio Command Prompt / Developer Command Prompt / Developer PowerShell.

It will be necessary to set the `ZLIB_ROOT` and `CMOCKA_ROOT` and `OPENSSL_ROOT_DIR`. Use the pre-built versions of the project for convenience.

```shell
cd \path\to\globalplatform
cmake -G "NMake Makefiles" -DOPENSSL_ROOT_DIR="C:\Program Files (x86)\OpenSSL-Win32" -DZLIB_ROOT="C:\Users\john\Desktop\globalplatform\zlib-1.2.8\win32-build" -DCMOCKA_ROOT="C:\Users\john\Desktop\globalplatform\cmocka-cmocka-1.1.5\build-w32"
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

```shell
cmake . -DTESTING=ON -DDEBUG=ON
make
make test
```

__NOTE:__ On Windows: When using the Visual Studio command line the neccessary mock functions are not supported by the linker and tests cannot be executed.

## Debug Output

The variable `GLOBALPLATFORM_DEBUG=1` in the environment must be set. The logfile can be set with `GLOBALPLATFORM_LOGFILE=<file>`. Under Windows by default `C:\Temp\GlobalPlatform.log` is chosen, under Unix systems if syslog is available it will be used by default. The default log file under Unix systems is `/tmp/GlobalPlatform.log` if syslog is not available.

# GitHub Documentation

The GitHub documentation is located under the `docs` folder and is using [Jekyll](https://jekyllrb.com).

Installation:

~~~shell
cd docs
gem uninstall jekyll
# select all
gem install jekyll -v 3.9.0
gem uninstall bundler
gem install bundler
bundle
bundle update github-pages
~~~


Useful commands inside the `docs` folder:

* Cleaning local generated site: `bundle exec jekyll clean`
* Serving site in a local browser updating automatically on content changes: `bundle exec jekyll serve`
* Update configuration in the Gemfile: `bundle update`

# Issues

For issues please use the [GitHub issue tracker](https://github.com/kaoh/globalplatform/issues).

You can also use the [Mailing List](https://sourceforge.net/p/globalplatform/mailman/) or ask a question on Stack Overflow assigning the tags `gpshell` or `globalplatform`.
