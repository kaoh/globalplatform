!IFNDEF DEBUG
!MESSAGE Building release version.
!MESSAGE Use nmake with DEBUG= if you want to build a debug version.
!ENDIF

!MESSAGE
!MESSAGE Possible Targets:
!MESSAGE ALL [DEBUG=] - Build version.
!MESSAGE CLEAN - Delete Debug and Release directories
!MESSAGE PREBUILD - Builds a prebuild zipped version. VERSION= must be set.
!MESSAGE

# Directory name may not contain spaces
!IFDEF DEBUG
OUTDIR=Debug
!ELSE
OUTDIR=Release
!ENDIF

# replace with your path to the GlobalPlatform header files
# or specify on command line
GLOBALPLATFORM_INC=..\GlobalPlatform

# replace with your path to the GlobalPlatform library files
# or specify on command line
GLOBALPLATFORM_LIB=..\GlobalPlatform\$(OUTDIR)

!IF !EXIST($(GLOBALPLATFORM_INC))
!ERROR Your path to the header files for GlobalPlatform is wrong. \
Replace it in the Makefile or call nmake with GLOBALPLATFORM_INC=<PATH_TO_GLOBALPLATFORM_HEADERS>
!ENDIF

!IF !EXIST($(GLOBALPLATFORM_LIB))
!ERROR Your path to the library files for GlobalPlatform is wrong. \
Replace it the Makefile or call nmake with GLOBALPLATFORM_LIB=<PATH_TO_GLOBALPLATFORM_LIBS>
!ENDIF


OBJS=$(OUTDIR)/GPShell.obj


APP_NAME=GPShell # the name of the application

CPP=cl

!IFDEF DEBUG
CPPFLAGS=/Od /I $(GLOBALPLATFORM_INC) /D "WIN32" /D "_DEBUG" /D "DEBUG" /D "_CONSOLE" /D "_UNICODE" \
/D "UNICODE" /RTC1 /MD /Fo$(OUTDIR)/ /W3 /nologo /ZI /TC
!ELSE
CPPFLAGS=/O2 /I $(GLOBALPLATFORM_INC) /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_UNICODE" \
/D "UNICODE" /FD /MD /Fo$(OUTDIR)/ /W3 /nologo /Zi /TC
!ENDIF

LINK=link

!IFDEF DEBUG
LFLAGS=/OUT:$(OUTDIR)/$(APP_NAME).exe /NOLOGO /LIBPATH:$(GLOBALPLATFORM_LIB) /DEBUG /PDB:$(OUTDIR)/$(APP_NAME).pdb \
/SUBSYSTEM:CONSOLE /MACHINE:X86 GlobalPlatform.lib winscard.lib kernel32.lib user32.lib gdi32.lib winspool.lib \
comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib
!ELSE
LFLAGS=/OUT:$(OUTDIR)/$(APP_NAME).exe /INCREMENTAL:NO /NOLOGO /LIBPATH:$(GLOBALPLATFORM_LIB) /SUBSYSTEM:CONSOLE \
/OPT:REF /OPT:ICF /MACHINE:X86 GlobalPlatform.lib winscard.lib kernel32.lib user32.lib gdi32.lib \
winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib
!ENDIF

all: create_dirs $(OUTDIR)/$(APP_NAME).exe

create_dirs:
	-@mkdir $(OUTDIR)


# compilation and linking
$(OUTDIR)/$(APP_NAME).exe: $(OBJS) version.res
	$(LINK) $(LFLAGS) $(OBJS) version.res

$(OBJS): $(@B).c
	$(CPP) $(CPPFLAGS) /c /Fd$(OUTDIR)/%|pfF %|pfF.c

version.res : version.rc
!IFDEF DEBUG
	rc /dDEBUG /i "$(MSSDK)\Include\mfc" version.rc
!ELSE
	rc /i "$(MSSDK)\Include\mfc" version.rc
!ENDIF

VERSION=1.4.1
DIR=GPShell-$(VERSION)

PREBUILD:	clean_package bin_package

bin_package:
	rm -rf $(DIR)
	mkdir $(DIR)
	cp Release/GPShell.exe GlobalPlatform.dll ssleay32.dll \
	libeay32.dll zlib1.dll LICENSE README CHANGES COPYING AUTHORS \
	helloInstall.txt helloDelete.txt helloInstallGP211.txt helloDeleteGP211.txt \
	list.txt listgp211.txt replacekey-cosmo-gp211.txt recyclekey-cosmo-gp211.txt \
	helloDeletegemXpressoProR3_2E64.txt  helloInstallgemXpressoProR3_2E64.txt \
	listgemXpressoProR3_2E64.txt HelloWorld.bin HelloWorld.cap \
	helloInstallCyberflexe-gate32k.txt helloInstallCyberflexAccess64k.txt \
	helloInstallNokia6131NFC.txt HelloWorld.cap.transf $(DIR)
	zip GPShell-$(VERSION).zip $(DIR)/*

clean_package:
	rm -rf "GPShell-$(VERSION).zip" "$(DIR)" "$(SRCDIR)"