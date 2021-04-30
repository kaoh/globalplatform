#!/bin/bash
CMD1="rm -f CMakeDoxy* && rm -f CTest* && rm -f install_manifest.txt && rm -f CMakeCache.txt && rm -f cmake_install.cmake"
CMD2="rm -rfd CMakeFiles && rm -rf _CPack_Packages && rm -f CPack* && rm -rfd src/CMakeFiles"
$(${CMD1})
$(${CMD2})
cd gpshell 
$(${CMD1})
$(${CMD2})
cd ..
cd globalplatform
$(${CMD1})
$(${CMD2})
cd ..
cd gppcscconnectionplugin
$(${CMD1})
$(${CMD2})
cd ..
