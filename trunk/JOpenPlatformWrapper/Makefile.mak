!IFNDEF DEBUG
!MESSAGE Building release version.
!MESSAGE Use nmake with DEBUG= if you want to build a debug version.
!ENDIF

!MESSAGE
!MESSAGE Possible Targets:
!MESSAGE ALL [DEBUG=] - Build version.
!MESSAGE CLEAN - Delete Debug and Release directories
!MESSAGE
!MESSAGE Arguments:
!MESSAGE	OP_INC       - The path to the headers of OpenPlatform
!MESSAGE	OP_LIB       - The path to the link library (.lib) of OpenPlatform
!MESSAGE	JAVA_INC     - Path to the JAVA header files
!MESSAGE	JAVA_INC_W32 - Path to the JAVA W32 header files
!MESSAGE

# replace with your path to the OpenPlatform header files
# or specify on command line
OP_INC=C:\Dokumente und Einstellungen\Widerstand\Eigene Dateien\Visual Studio Projects\OpenPlatform

# replace with your path to the JAVA header files
# or specify on command line
JAVA_INC=E:\Programme\jdk1.5.0_01\include

# replace with your path to the JAVA W32 header files
# or specify on command line
JAVA_INC_W32=E:\Programme\jdk1.5.0_01\include\win32

# replace with your path to the OpenPlatform library files
# or specify on command line excluding the Release or Debug directory
OP_LIB=C:\Dokumente und Einstellungen\Widerstand\Eigene Dateien\Visual Studio Projects\OpenPlatform

!IF !EXIST("$(OP_INC)")
!ERROR Your path to the header files for OpenPlatform is wrong. \
Replace it in the Makefile or call nmake with OPENSSL_INC=<PATH_TO_OP_HEADERS>
!ENDIF

!IF !EXIST("$(JAVA_INC)")
!ERROR Your path to the header files for Java is wrong. \
Replace it in the Makefile or call nmake with JAVA_INC=<PATH_TO_JAVA_HEADERS>
!ENDIF

!IF !EXIST("$(JAVA_INC_W32)")
!ERROR Your path to the header files for Java W32 is wrong. \
Replace it in the Makefile or call nmake with JAVA_INC_W32=<PATH_TO_JAVA_W32_HEADERS>
!ENDIF

!IF !EXIST("$(OP_LIB)")
!ERROR Your path to the library files for OP \
excluding the Release or Debug directory is wrong \
Replace it in the Makefile or call nmake with OP_LIB=<PATH_TO_OP_LIBS>
!ENDIF

# Directory name may not contain spaces
!IFDEF DEBUG
OUTDIR=Debug
!ELSE
OUTDIR=Release
!ENDIF

!IF !EXIST("$(OP_LIB)/$(OUTDIR)")
!MESSAGE "$(OP_LIB)/$(OUTDIR)"
!ERROR Your path to the library files for OpenPlatform is wrong. \
It is assumed that the library is in the directory Debug or Release in the \
OP_LIB directory.
!ENDIF

OBJS=$(OUTDIR)/stdafx.obj $(OUTDIR)/DLLMain.obj $(OUTDIR)/JOpenPlatformWrapper.obj

LIB_NAME=JOpenPlatformWrapper # the name of the library

CPP=cl

!IFDEF DEBUG
CPPFLAGS=/Od /I "$(OP_INC)" /I "$(JAVA_INC_W32)" /I "$(JAVA_INC)" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_USRDLL" \
/D "_UNICODE" /D "_WINDLL" /GZ /MD /Fo$(OUTDIR)/ /W3 /nologo /c /ZI /TP
!ELSE
CPPFLAGS=/O2 /I "$(OP_INC)" /I "$(JAVA_INC_W32)" /I "$(JAVA_INC)" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_USRDLL" \
/D "_UNICODE" /D "_WINDLL" /FD /MD /Fo$(OUTDIR)/ /W3 /nologo /c /Zi /TP
!ENDIF

LINK=link

!IFDEF DEBUG
LFLAGS=/OUT:"$(OUTDIR)/$(LIB_NAME).dll" /NOLOGO /LIBPATH:"$(OP_LIB)/$(OUTDIR)" /DLL /DEBUG /PDB:"$(OUTDIR)/$(LIB_NAME).pdb" \
/SUBSYSTEM:CONSOLE /MACHINE:X86 OpenPlatform.lib kernel32.lib user32.lib gdi32.lib winspool.lib \
comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib
!ELSE
LFLAGS=/OUT:"$(OUTDIR)/$(LIB_NAME).dll" /INCREMENTAL:NO /NOLOGO /LIBPATH:"$(OP_LIB)/$(OUTDIR)" /DLL /SUBSYSTEM:CONSOLE \
/OPT:REF /OPT:ICF /MACHINE:X86 OpenPlatform.lib kernel32.lib user32.lib gdi32.lib \
winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib
!ENDIF

all: create_dirs $(OUTDIR)/$(LIB_NAME).dll

create_dirs:
	-@mkdir $(OUTDIR)

version.res : version.rc version.h
!IFDEF DEBUG
	rc /dDEBUG version.rc
!ELSE
	rc version.rc
!ENDIF

# compilation and linking
"$(OUTDIR)/$(LIB_NAME).dll": $(OBJS) version.res
	$(LINK) $(LFLAGS) $(OBJS) version.res


$(OBJS): $(@B).c
	$(CPP) $(CPPFLAGS) /c /Fd$(OUTDIR)/%|pfF %|pfF.c

clean:
	-@rd /S /Q Debug
	-@rd /S /Q Release