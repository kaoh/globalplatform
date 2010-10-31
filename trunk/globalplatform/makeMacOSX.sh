#!/bin/sh
./configure --enable-debug PCSCLITE_CFLAGS=-I/Developer/SDKs/MacOSX10.5.sdk/System/Library/Frameworks/PCSC.framework/Headers
make