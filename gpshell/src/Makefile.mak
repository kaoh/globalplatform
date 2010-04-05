
!include makefile.inc

# Directory name may not contain spaces
!IFDEF DEBUG
OUTDIR=Debug
!ELSE
OUTDIR=Release
!ENDIF

OBJS=$(OUTDIR)/GPShell.obj


APP_NAME=GPShell # the name of the application

CPP=cl

!IFDEF DEBUG
CPPFLAGS=/Od -I ../../globalplatform/src /D "WIN32" /D "_DEBUG" /D "DEBUG" /D "_CONSOLE" /D "_UNICODE" \
/D "UNICODE" /RTC1 /MD /Fo$(OUTDIR)/ /W3 /nologo /ZI /TC /D _CRT_SECURE_NO_WARNINGS
!ELSE
CPPFLAGS=/O2 -I ../../globalplatform/src /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_UNICODE" \
/D "UNICODE" /FD /MD /Fo$(OUTDIR)/ /W3 /nologo /Zi /TC /D _CRT_SECURE_NO_WARNINGS
!ENDIF

LINK=link

!IFDEF DEBUG
LFLAGS=/OUT:$(OUTDIR)/$(APP_NAME).exe /NOLOGO /LIBPATH:../../globalplatform/src/$(OUTDIR) /DEBUG /PDB:$(OUTDIR)/$(APP_NAME).pdb \
/SUBSYSTEM:CONSOLE /MACHINE:X86 globalplatform.lib winscard.lib kernel32.lib user32.lib gdi32.lib winspool.lib \
comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib
!ELSE
LFLAGS=/OUT:$(OUTDIR)/$(APP_NAME).exe /INCREMENTAL:NO /NOLOGO /LIBPATH:../../globalplatform/src/$(OUTDIR) /SUBSYSTEM:CONSOLE \
/OPT:REF /OPT:ICF /MACHINE:X86 globalplatform.lib winscard.lib kernel32.lib user32.lib gdi32.lib \
winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib
!ENDIF

all: create_dirs $(OUTDIR)/$(APP_NAME).exe

create_dirs:
	-@mkdir $(OUTDIR)


# compilation and linking
$(OUTDIR)/$(APP_NAME).exe: $(OBJS) version.res
	$(LINK) $(LFLAGS) $(OBJS) version.res
	$(_VC_MANIFEST_EMBED_EXE)

$(OBJS): $(@B).c
	$(CPP) $(CPPFLAGS) /c /Fd$(OUTDIR)/%|pfF %|pfF.c

version.res : version.rc
!IFDEF DEBUG
	rc /dDEBUG /i "$(MSSDK)\Include\mfc" version.rc
!ELSE
	rc /i "$(MSSDK)\Include\mfc" version.rc
!ENDIF

clean:
	-@rd /S /Q Debug
	-@rd /S /Q Release
	-@del version.res
	$(_VC_MANIFEST_CLEAN)

VERSION=1.4.3
DIR=GPShell-$(VERSION)

PREBUILD:	clean_package bin_package

bin_package:
	rm -rf $(DIR)
	mkdir $(DIR)
	cp Debug/GPShell.exe ../../globalplatform/src/Debug/GlobalPlatform.dll ../../globalplatform\src\GlobalPlatform-6.0.0\ssleay32.dll \
	../../gppcscconnectionplugin/src/Debug/GPPcScConnectionPlugin.dll \
	../../globalplatform\src\GlobalPlatform-6.0.0\libeay32.dll ../../globalplatform\src\GlobalPlatform-6.0.0/zlib1.dll ../../globalplatform/src/GlobalPlatform-6.0.0/license* ../README ../COPYING ../AUTHORS \
	../helloInstall.txt ../helloDelete.txt ../helloInstallGP211.txt ../helloDeleteGP211.txt \
	../list.txt ../listgp211.txt ../replacekey-cosmo-gp211.txt ../recyclekey-cosmo-gp211.txt \
	../helloDeletegemXpressoProR3_2E64.txt  ../helloInstallgemXpressoProR3_2E64.txt \
	../listgemXpressoProR3_2E64.txt ../helloworld.cap \
	../helloInstallCyberflexe-gate32k.txt ../helloInstallCyberflexAccess64k.txt \
	../helloInstallNokia6131NFC.txt ../helloworld.cap.transf ../helloInstallOberthurCosmo64.txt \
	../listJCOP10.txt ../listPalmeraProtectV5.txt ../helloInstallPalmeraProtectV5.txt ../helloInstallSmartCafeExpert30.txt \
	../helloInstallJCOP10.txt ../helloInstallJCOP31.txt ../helloInstallJCOP21OrJTopV15.txt ../get_data.txt ../send_APDU.txt $(DIR)
	zip GPShell-$(VERSION).zip $(DIR)/*

clean_package:
	rm -rf "GPShell-$(VERSION).zip" "$(DIR)" "$(SRCDIR)"

!include makefile.targ.inc
