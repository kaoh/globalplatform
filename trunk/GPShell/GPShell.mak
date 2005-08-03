# Microsoft Developer Studio Generated NMAKE File, Based on GPShell.dsp
!IF "$(CFG)" == ""
CFG=GPShell - Win32 Debug
!MESSAGE No configuration specified. Defaulting to GPShell - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "GPShell - Win32 Release" && "$(CFG)" != "GPShell - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "GPShell.mak" CFG="GPShell - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "GPShell - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "GPShell - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

# replace with your path to the OpenPlatform header files
# or specify on command line
OPENPLATFORM_INC=..\OpenPlatform

# replace with your path to the OpenPlatform library files
# or specify on command line
OPENPLATFORM_LIB_DEBUG=..\OpenPlatform\Debug
OPENPLATFORM_LIB_RELEASE=..\OpenPlatform\Release

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "GPShell - Win32 Release"

OUTDIR=.\GPShell___Win32_Release
INTDIR=.\GPShell___Win32_Release
# Begin Custom Macros
OutDir=.\GPShell___Win32_Release
# End Custom Macros

ALL : "$(OUTDIR)\GPShell.exe"


CLEAN :
	-@erase "$(INTDIR)\GPShell.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(OUTDIR)\GPShell.exe"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/I $(OPENPLATFORM_INC) /nologo /ML /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /D "UNICODE" /D "_UNICODE" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 

BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\GPShell.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=/LIBPATH:$(OPENPLATFORM_LIB_RELEASE) kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib OpenPlatform.lib /nologo /subsystem:console /incremental:no /pdb:"$(OUTDIR)\GPShell.pdb" /machine:I386 /out:"$(OUTDIR)\GPShell.exe" 
LINK32_OBJS= \
	"$(INTDIR)\GPShell.obj"

"$(OUTDIR)\GPShell.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "GPShell - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

ALL : "$(OUTDIR)\GPShell.exe"


CLEAN :
	-@erase "$(INTDIR)\GPShell.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(INTDIR)\vc60.pdb"
	-@erase "$(OUTDIR)\GPShell.exe"
	-@erase "$(OUTDIR)\GPShell.ilk"
	-@erase "$(OUTDIR)\GPShell.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/I $(OPENPLATFORM_INC) /nologo /MLd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "DEBUG" /D "_CONSOLE" /D "_MBCS" /D "UNICODE" /D "_UNICODE" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /GZ /c 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\GPShell.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=/LIBPATH:$(OPENPLATFORM_LIB_DEBUG) kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib OpenPlatform.lib /nologo /subsystem:console /incremental:yes /pdb:"$(OUTDIR)\GPShell.pdb" /debug /machine:I386 /out:"$(OUTDIR)\GPShell.exe" /pdbtype:sept 
LINK32_OBJS= \
	"$(INTDIR)\GPShell.obj"

"$(OUTDIR)\GPShell.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) $(LINK32_FLAGS) $(LINK32_OBJS)
#    $(LINK32) @<<
#  $(LINK32_FLAGS) $(LINK32_OBJS)
#<<

!ENDIF 

.c{$(INTDIR)}.obj::
   $(CPP) $(CPP_PROJ) $<
#   $(CPP) @<<
#   $(CPP_PROJ) $< 
#<<

.cpp{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("GPShell.dep")
!INCLUDE "GPShell.dep"
!ELSE 
!MESSAGE Warning: cannot find "GPShell.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "GPShell - Win32 Release" || "$(CFG)" == "GPShell - Win32 Debug"
SOURCE=.\GPShell.c

"$(INTDIR)\GPShell.obj" : $(SOURCE) "$(INTDIR)"



!ENDIF 

