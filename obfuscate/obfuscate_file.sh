./build_2/avcleaner.bin "$1" --strings=true -- -D "_WIN64" -D "_UNICODE" -D "UNICODE" -D "_WINSOCK_DEPRECATED_NO_WARNINGS"\
     "-I" "/usr/lib/clang/16.0.6/include" \
     "-I" "./Include/10.0.22621.0/ucrt" \
     "-I" "./Include/10.0.22621.0/shared" \
     "-I" "./Include/10.0.22621.0/um" \
     "-I" "./Include/10.0.22621.0/winrt" \
     "-I" "./include" \
     "-I" "./New_Include" \
     "-w" \
     "-fdebug-compilation-dir" \
     "-fno-use-cxa-atexit" "-fms-extensions" "-fms-compatibility" \
     "-fms-compatibility-version=19.15.26726" "-std=c++14" "-fdelayed-template-parsing" "-fobjc-runtime=gcc" "-fcxx-exceptions" "-fexceptions" "-fdiagnostics-show-option" "-fcolor-diagnostics" "-x" "c++" -ferror-limit=8900 -target x86_64-pc-windows-msvc19.15.26726\
       "-fsyntax-only" "-disable-free" "-disable-llvm-verifier" "-discard-value-names"\
       "-dwarf-column-info" "-debugger-tuning=gdb" "-momit-leaf-frame-pointer" "-v"
