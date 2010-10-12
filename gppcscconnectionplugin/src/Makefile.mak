
!include makefile.inc

# Directory name may not contain spaces
!IFDEF DEBUG
OUTDIR=Debug
!ELSE
OUTDIR=Release
!ENDIF

OBJS=$(OUTDIR)/stdafx.obj $(OUTDIR)/DLLMain.obj $(OUTDIR)/gppcscconnectionplugin.obj \
$(OUTDIR)/util.obj

LIB_NAME=GPPcScConnectionPlugin # the name of the library

CPP=cl

!IFDEF DEBUG
CPPFLAGS=/Od -I ../../globalplatform/src /D "WIN32" /D "_DEBUG" /D "DEBUG" /D "_CONSOLE" /D "OPGP_PL_EXPORTS" /D "_UNICODE" \
/D "_WINDLL" /D "UNICODE" /RTC1 /MD /Fo$(OUTDIR)/ /W3 /nologo /ZI /TC /D _CRT_SECURE_NO_WARNINGS
!ELSE
CPPFLAGS=/O2 -I ../../globalplatform/src /D "WIN32" /D "DEBUG" /D "_CONSOLE" /D "OPGP_PL_EXPORTS" /D "_UNICODE" \
/D "_WINDLL" /D "UNICODE" /FD /MD /Fo$(OUTDIR)/ /W3 /nologo /Zi /TC /D _CRT_SECURE_NO_WARNINGS
!ENDIF

LINK=link
LIB=lib

# Define dummy SDK_LIB1 for additional libraries if not given
!IFNDEF SDK_LIB1
SDK_LIB1=C:\DUMMY
!ENDIF

# Define dummy SDK_LIB2 for additional libraries if not given
!IFNDEF SDK_LIB2
SDK_LIB2=C:\DUMMY
!ENDIF

# Define dummy SDK_LIB3 for additional libraries if not given
!IFNDEF SDK_LIB3
SDK_LIB3=C:\DUMMY
!ENDIF

# Define dummy SDK_LIB4 for additional libraries if not given
!IFNDEF SDK_LIB4
SDK_LIB4=C:\DUMMY
!ENDIF

!IFNDEF TARGET_ARCH
TARGET_ARCH=X86
!ENDIF

!IFDEF DEBUG
LFLAGS=/OUT:$(OUTDIR)/$(LIB_NAME).dll /NOLOGO /LIBPATH:../../globalplatform/src/$(OUTDIR) /LIBPATH:"$(SDK_LIB1)" /LIBPATH:"$(SDK_LIB2)" /DLL /DEBUG /PDB:$(OUTDIR)/$(LIB_NAME).pdb \
/SUBSYSTEM:CONSOLE /MACHINE:$(TARGET_ARCH) globalplatform.lib winscard.lib kernel32.lib
!ELSE
LFLAGS=/OUT:$(OUTDIR)/$(LIB_NAME).dll /NODEFAULTLIB /INCREMENTAL:NO /NOLOGO /LIBPATH:"$(SDK_LIB1)" /LIBPATH:"$(SDK_LIB3)" /LIBPATH:"$(SDK_LIB4)" \
/LIBPATH:../../globalplatform/src/$(OUTDIR) /DLL /SUBSYSTEM:CONSOLE \
/OPT:REF /OPT:ICF /MACHINE:$(TARGET_ARCH) msvcrt_win2000.obj msvcrt.lib globalplatform.lib winscard.lib kernel32.lib
!ENDIF

!IFDEF STATIC
all: create_dirs $(OUTDIR)/$(LIB_NAME).lib
!ELSE
all: create_dirs $(OUTDIR)/$(LIB_NAME).dll
!ENDIF

create_dirs:
	-@mkdir $(OUTDIR)


# compilation and linking
$(OUTDIR)/$(LIB_NAME).dll: $(OBJS) version.res
	$(LINK) $(LFLAGS) $(OBJS) version.res
	$(_VC_MANIFEST_EMBED_DLL)

$(OUTDIR)/$(LIB_NAME).lib: $(OBJS) version.res
	$(LIB) $(LIBFLAGS) $(OBJS) version.res
	$(_VC_MANIFEST_EMBED_DLL)

$(OBJS): $(@B).c
	$(CPP) $(CPPFLAGS) /c /Fd$(OUTDIR)/%|pfF %|pfF.c

version.res : version.rc
!IFDEF DEBUG
	$(RC) /dDEBUG /i "$(MSSDK)\Include\mfc" version.rc
!ELSE
	$(RC) /i "$(MSSDK)\Include\mfc" version.rc
!ENDIF

# run doxygen
doc: do-doc

VERSION=1.1.0
PREBUILDDIR="GPPCSCConnectionPlugin-$(VERSION)"

prebuild: all
	-@del /S /F /Q $(PREBUILDDIR)
	-@mkdir $(PREBUILDDIR)
	cp Release/gppcscconnectionplugin.dll ../ChangeLog ../README ../NEWS ../COPYING ../COPYING.LESSER ../AUTHORS  $(PREBUILDDIR)
	zip -r $(PREBUILDDIR).zip $(PREBUILDDIR)/*

clean:
	-@rd /S /Q Debug
	-@rd /S /Q Release
	-@rd /S /Q Doc
	-@del version.res
	$(_VC_MANIFEST_CLEAN)

do-doc:
	-@mkdir Doc
	doxygen Doxyfile.cfg

!include makefile.targ.inc
