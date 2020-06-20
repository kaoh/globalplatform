#!/bin/sh
CMD="rm -f CMakeDoxy* && rm -f CTest* && rm -f install_manifest.txt && rm -f CMakeCache.txt && rm -f cmake_install.cmake && rm -rf CMakeFiles && rm -rf _CPack_Packages && rm -f CPack* && rm -rf src/CMakeFiles"
$(${CMD})
cd gpshell 
$(${CMD})
cd ..
cd globalplatform
$(${CMD})
cd ..
cd gppcscconnectionplugin
$(${CMD})
cd ..
