#!/bin/bash

# pyMetaTwin Dependency Installation Script

if [ "$(id -u)" -ne 0 ]; then
	echo "[!] Must be run as root"
	exit 1
fi

# Update package list
echo "[+] Updating package list"
sudo apt-get update

# Install Wine
echo "[+] Installing Wine"
sudo apt-get install -y wine

# Install Python 3 if not already installed
echo "[+] Installing Python 3"
sudo apt-get install -y python3 python3-pip

# Install python package subprocess32
echo "[+] Installing python package subprocess32"
sudo pip3 install subprocess32

echo "[+] Installation complete"