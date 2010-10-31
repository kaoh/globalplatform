#!/bin/sh
./configure --enable-debug PCSCLITE_CFLAGS=-I/Developer/SDKs/MacOSX10.5.sdk/System/Library/Frameworks/PCSC.framework/Headers LDFLAGS=-L/opt/local/lib CFLAGS=-I/opt/local/include GLOBALPLATFORM_CFLAGS=-I/opt/local/include/globalplatform
make