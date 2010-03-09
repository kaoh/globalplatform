!IFNDEF DEBUG
!MESSAGE Building release version.
!MESSAGE Use nmake with "DEBUG=1" if you want to build a debug version.
!ENDIF

!MESSAGE
!MESSAGE Possible Targets:
!MESSAGE ALL ["DEBUG=1"] - Build version.
!MESSAGE   -- Use nmake with TARGET_ARCH=X64 if you want to build a 64 bit library. --
!MESSAGE CLEAN - Delete Debug and Release directories
!MESSAGE PREBUILD - Builds a prebuild zipped version. VERSION=... must be set.
!MESSAGE
!MESSAGE You can specify additional SDK directories with SDK_LIB1= and SDK_LIB2=
!MESSAGE
!MESSAGE

all:
    -@cd src
    $(MAKE) -f Makefile.mak

clean:
    -@cd src
    $(MAKE) -f Makefile.mak CLEAN

prebuild:
    -@cd src
    $(MAKE) -f Makefile.mak PREBUILD
