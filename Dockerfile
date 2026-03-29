# Stage 1: Builder
FROM kalilinux/kali-rolling as builder
ENV DEBIAN_FRONTEND=noninteractive

# Replace broken/incomplete sources.list and install everything
RUN echo "deb http://http.kali.org/kali kali-rolling main non-free contrib" > /etc/apt/sources.list && \
    dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get install -y \
    git build-essential python3 python3-pip python3-venv \
    wine64 wine32:i386 \
    gcc-mingw-w64 g++-mingw-w64 mingw-w64 \
    binutils-mingw-w64 curl unzip ninja-build clang nasm \
    gcc-multilib g++-multilib sudo

    
RUN mkdir -p /usr/lib/gcc/x86_64-w64-mingw32/12-win32

WORKDIR /boaz
COPY . .

RUN chmod +x requirements.sh && \
    sed -i 's/sudo //g' requirements.sh && \
    python3 -m venv venv && \
    . ./venv/bin/activate && \
    pip install --upgrade pip && \
    bash requirements.sh && \
    ./venv/bin/pip install pyinstaller && \
    ./venv/bin/pyinstaller --onefile Boaz.py

# Stage 2: Runtime
FROM kalilinux/kali-rolling
ENV DEBIAN_FRONTEND=noninteractive
ENV DISPLAY=
ENV WINEDEBUG=-all



RUN echo "deb http://http.kali.org/kali kali-rolling main non-free contrib" > /etc/apt/sources.list && \
dpkg --add-architecture i386 && \
apt-get update && \
apt-get install -y \
git build-essential python3 python3-pip python3-venv \
wine64 wine32:i386 \
mingw-w64 gcc-mingw-w64 g++-mingw-w64 \
binutils-mingw-w64 curl unzip ninja-build clang nasm \
gcc-multilib g++-multilib


RUN echo "deb http://deb.debian.org/debian bookworm main" > /etc/apt/sources.list.d/debian-bookworm.list && \
    apt update && \
    apt install -y libclang-cpp16 libllvm16 && \
    rm /etc/apt/sources.list.d/debian-bookworm.list && \
    apt clean && \
    rm -rf /var/lib/apt/lists/*


WORKDIR /boaz
COPY --from=builder /boaz /boaz

RUN [ -f requirements.txt ] || pip3 freeze > requirements.txt
RUN pip3 install --break-system-packages -r requirements.txt || true

ENTRYPOINT ["python3", "/boaz/Boaz.py"]
