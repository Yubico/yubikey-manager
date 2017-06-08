#! /usr/bin/env bash

sudo apt-get update -qq

# Add yubico ppa
sudo apt-get install -qq software-properties-common
sudo add-apt-repository -y ppa:yubico/stable

sudo apt-get update -qq && apt-get -qq upgrade

# Install development dependencies
# for both Python 2 and Python 3
sudo apt-get install -qq \
    python-pip \
    python3-pip \
    python-pyscard \
    python3-pyscard \
    python-cryptography \
    python3-cryptography \
    python-openssl \
    python3-openssl \
    libykpers-1-1 \
    libu2f-host0 \
    libssl-dev \
    libpcsclite-dev \
    pcscd \
    libffi-dev \
    yubico-piv-tool \
    yubikey-personalization

pip install --upgrade pip
pip3 install --upgrade pip

# Install flake8 for linting
pip install pre-commit flake8

# Install editable version of repository with python 3, install pre-commit hook
cd /vagrant && pip3 install -e . && chown -R ubuntu . && pre-commit install

# Add a very permissive udev rule to be able to access YubiKey Slots over ssh
echo 'ATTRS{idVendor}=="1050", MODE="0777"' > /etc/udev/rules.d/99-yubico.rules

# To see if USB filter is working:
# > lsusb
