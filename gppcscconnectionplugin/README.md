# Summary

- Title    : GlobalPlatform PC/SC Connection Plugin
- Authors  : Karsten Ohme <k_o_@users.sourceforge.net>
- License  : See file COPYING.LESSER
- Requires :
 * PC/SC Lite http://www.musclecard.com/ (for UNIXes)
 * GlobalPlatformn http://globalplatform.sourceforge.net

This is a PC/SC connection plugin for the GlobalPlatform Library.

For more information contact the author through the mailing list at:

http://sourceforge.net/projects/globalplatform/

# Debug Output

If you experience problems a DEBUG output is always helpful.
Set the variable GLOBALPLATFORM_DEBUG=1 in the environment. You can set
the logfile with GLOBALPLATFORM_LOGFILE=<file>. Under Windows by
default C:\Temp\GlobalPlatform.log is chosen. The log file must be
writable for the user. The default log file under Unix systems is
/tmp/GlobalPlatform.log. But usually syslog is available and this will
be used by default, so you may have to specify the log file manually,
if you don't have access to the syslog or don't want to use it.
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

## FreeBSD

Under FreeBSD the pcsc-lite libraries are not detected automatically. So you have to specify the locations:

```bash
cmake -DPCSC_INCLUDE_DIRS=/usr/local/include -DPCSC_LIBRARIES=/usr/local/lib/libpcsclite.so
```

## Windows
-------------------------

After changing CMake parameters you must rebuild the files and delete the CMakeCache.txt file.

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

#### CMake
http://www.cmake.org/
--> CMake 3.5.0 or higher

### Compile

* Launch Visual Studio Command Prompt / Developer Command Prompt

```
cd \path\to\gppcscconnectionplugin
cmake -G "NMake Makefiles" - for a release version
cmake -G "NMake Makefiles" -DDEBUG=1 - for a debug version  
```

* CMake looks for PC/SC ##

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
  `cmake -G "Visual Studio 10"` - Replace with your VS version
  You must have to remove the `CMakeCache.txt` before when using a different generator.

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

```
dput gpsnapshots-ppa libgppcscconnectionplugin1_1.2.2+3SNAPSHOT20120524080448+0200-0ubuntu1~precise.changes
```

You can create a Ubuntu/Debian package from a dsc file.

Execute:

```
dpkg-source -x libgppcscconnectionplugin1_1.2.2+3SNAPSHOT20120524080448+0200-0ubuntu1~precise.dsc
cd libgppcscconnectionplugin1-1.2.2+3
fakeroot debian/rules binary
```

## Debug Builds

To be able to debug the library enable the debug symbols:

```
cmake -DDEBUG=ON

```

## Testing

Testing is only supported under Linux for now. To generate the tests execute:

```
cmake -DTESTING=ON
make
make tests
```

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
