#!/bin/bash

# Update and upgrade packages
echo "[*] Installing required packages for BOAZ evasion tool..."
echo "[*] Updating and upgrading packages..."
sudo apt update && sudo apt upgrade -y
sudo apt install 
sudo apt install osslsigncode -y
pip3 install pyopenssl
sudo apt install build-essential -y

# Install required packages
sudo apt install -y git cmake ninja-build python3 gcc g++ zlib1g-dev wine mingw-w64 mingw-w64-tools x86_64-w64-mingw32-g++

if [ -f "./donut" ]; then
    echo "'donut' is already installed in the current directory."
else
    echo "'donut' not found. Installing..."
fi

echo "Installing pe2sh..."

if [ -f "./pe2shc.exe" ]; then
    echo "'pe2shc.exe' is already installed in the current directory."
else
    echo "'pe2shc.exe' not found. Installing..."
fi


echo "Installing custom obfuscator based on avcleaner..."
if [ -f "./avcleaner_bin/avcleaner.bin" ]; then
    echo "'avcleaner.bin' is already installed in the current directory."
else
    echo "'avcleaner.bin' not found. Installing..."
fi

## Install Mangle: 
## Run commands: 
# Check if Mangle program exists
if [ ! -f ./signature/Mangle ]; then
  # Clone the Mangle repository
  git clone https://github.com/optiv/Mangle.git

  # Navigate to the Mangle directory
  cd Mangle

  # Get the required Go package
  go get github.com/Binject/debug/pe

  # Build the Mangle program
  go build Mangle.go

  # Move the built executable to the signature directory
  mv Mangle ../signature/

  # Navigate back to the original directory
  cd ..

  # Remove the Mangle directory
  rm -rf Mangle
fi


# Install pyMetaTwin
echo "Installing pyMetaTwin..."
# check if signature/metatwin.py file exists, if not git clone a fork of it, otherwise cd into it
if [ ! -f "./signature/metatwin.py" ]; then
    git clone https://github.com/thomasxm/pyMetaTwin
    cp -r pyMetaTwin/* signature
    cd signature
else
    cd signature
    fi
# Install metatwin dependencies anyway.
if [ ! -f "./metatwin.py" ]; then
    chmod +x install.sh
    sudo ./install.sh
else
    chmod +x install.sh
    sudo ./install.sh 
fi
cd ..

# Install Syswhisper2 (adjust with actual repository if different)
echo "Installing Syswhisper2..."
git clone https://github.com/jthuraisamy/SysWhispers2
cd syswhisper2
python3 ./syswhispers.py --preset common -o syscalls_common
cd ..

# Clone and build llvm-obfuscator (Akira-obfuscator)
echo "Cloning and building Akira llvm-obfuscator..."
git clone https://github.com/thomasxm/Akira-obfuscator.git
cd Akira-obfuscator && mkdir -p akira_built
cd akira_built && cmake -DCMAKE_CXX_FLAGS="" -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_ASSERTIONS=ON -DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra;lld;lldb" -G "Ninja" ../llvm
ninja -j2
mv ./akira_built/* ../../akira_built/
echo "start unit test:"
cd ../../ && ./akira_built/bin/clang++ -D nullptr=NULL -mllvm -irobf-indbr -mllvm -irobf-icall -mllvm -irobf-indgv -mllvm -irobf-cse -mllvm -irobf-cff -target x86_64-w64-mingw32 loader2_test.c classic_stubs/syscalls.c ./classic_stubs/syscallsstubs.std.x64.s -o test.exe -v -L/usr/lib/gcc/x86_64-w64-mingw32/12-win32 -L./clang_test_include -I./c++/ -I./c++/mingw32/ -lws2_32 -lpsapi ./normal_api.c
wine ./test.exe

# Clone and build Pluto
echo "Cloning and building Pluto-obfuscator..."
git clone https://github.com/thomasxm/Pluto.git
cd Pluto && mkdir -p pluto_build && cd pluto_build
cmake -G Ninja -S .. -B build -DCMAKE_C_COMPILER="gcc" -DCMAKE_CXX_COMPILER="g++" -DCMAKE_INSTALL_PREFIX="../llvm_obfuscator_pluto/" -DCMAKE_BUILD_TYPE=Release
ninja -j2 -C build install
mkdir -p ../../../llvm_obfuscator_pluto
mv ./install/* ../../../llvm_obfuscator_pluto
echo "start unit test:"
cd ../../../ && ./llvm_obfuscator_pluto/bin/clang++ -D nullptr=NULL -O2 -flto -fuse-ld=lld -mllvm -passes=mba,sub,idc,bcf,fla,gle -Xlinker -mllvm -Xlinker -passes=hlw,idc -target x86_64-w64-mingw32 loader2_test.c ./classic_stubs/syscalls.c ./classic_stubs/syscallsstubs.std.x64.s -o ./notepad_llvm.exe -v -L/usr/lib/gcc/x86_64-w64-mingw32/12-win32 -L./clang_test_include -I./c++/ -I./c++/mingw32/ ./normal_api.c ./sweet_sleep.c ./anti_emu.c -lws2_32 -lpsapi
wine ./notepad_llvm.exe
echo "Installation and setup completed!"

## Main linker:
## Check if pyinstaller is installed, if not install it:
if [ ! -f "/usr/local/bin/pyinstaller" ]; then
    echo "Installing pyinstaller..."
    pip3 install pyinstaller
else
    echo "Pyinstaller is already installed."
fi

#!/bin/bash

# Check if PyInstaller is installed
if ! command -v pyinstaller &> /dev/null
then
    echo "PyInstaller is not installed. Installing PyInstaller..."
    # Install PyInstaller
    pip install pyinstaller
    if [ $? -ne 0 ]; then
        echo "Failed to install PyInstaller. Exiting."
        exit 1
    fi
else
    echo "PyInstaller is already installed."
fi

# Run PyInstaller to create a single executable
echo "Running PyInstaller..."
pyinstaller --onefile Boaz.py

if [ $? -eq 0 ]; then
    echo "Executable created successfully."
else
    echo "Failed to create the executable."
    exit 1
fi

echo "Setup completed successfully."
echo "Main program can be run with python3 Boaz.py or ./Boaz"