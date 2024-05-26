echo "Don't forget to update the path to your local winsdk"
./build/avcleaner.bin "$1" --strings=true -- -D "_WIN64" -D "_UNICODE" -D "UNICODE" -D "_WINSOCK_DEPRECATED_NO_WARNINGS"\
     "-I" "/home/kali/new_evasion_tools/avcleaner-master/Include/10.0.22621.0/ucrt" \
     "-I" "/home/kali/new_evasion_tools/avcleaner-master/Include/10.0.22621.0/shared" \
     "-I" "/home/kali/new_evasion_tools/avcleaner-master/Include/10.0.22621.0/um" \
     "-I" "/home/kali/new_evasion_tools/avcleaner-master/Include/10.0.22621.0/winrt" \
     "-I" "/home/kali/.wine/drive_c/TDM-GCC-64/x86_64-w64-mingw32/include/" \
     "-w" \
     "-fdebug-compilation-dir"\
     "-fno-use-cxa-atexit" "-fms-extensions" "-fms-compatibility" \
     "-fms-compatibility-version=19.15.26726" "-std=c++14" "-fdelayed-template-parsing" "-fobjc-runtime=gcc" "-fcxx-exceptions" "-fexceptions" "-fdiagnostics-show-option" "-fcolor-diagnostics" "-x" "c++" -ferror-limit=1900 -target x86_64-pc-windows-msvc19.15.26726\
       "-fsyntax-only" "-disable-free" "-disable-llvm-verifier" "-discard-value-names"\
       "-dwarf-column-info" "-debugger-tuning=gdb" "-momit-leaf-frame-pointer" "-v"
###      "-I" "/home/kali/new_evasion_tools/avcleaner-master/Include_new"\

    #  "-I" "/usr/local/Cellar/llvm/9.0.1"#"/usr/lib/clang/16/include/" \
    #  "-I" "/usr/local/Cellar/llvm/9.0.1"#"/usr/lib/clang/8.0.1/" \
