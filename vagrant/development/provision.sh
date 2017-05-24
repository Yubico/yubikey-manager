#! /usr/bin/env bash

# Install development dependencies
sudo apt-get update -qq
sudo apt-get install -qq software-properties-common
sudo add-apt-repository -y ppa:yubico/stable
sudo apt-get update -qq && apt-get -qq upgrade
sudo apt-get install -qq \
    python-pip \
    python3-pip \
    python-pyscard \
    python3-pyscard \
    python3-cryptography \
    python-cryptography \
    libykpers-1-1 \
    libu2f-host0 \
    libssl-dev \
    libpcsclite-dev \
    pcscd \
    libffi-dev
pip install --upgrade pip
pip3 install --upgrade pip

# Install flake8 for linting
pip install pre-commit flake8

# Install editable version of repository, install pre-commit hook
cd /vagrant && chown -R ubuntu . && pip install -e . && pre-commit install

# Add a very permissive udev rule to be able to access YubiKey Slots over ssh
echo 'ATTRS{idVendor}=="1050", MODE="0777"' > /etc/udev/rules.d/99-yubico.rules
