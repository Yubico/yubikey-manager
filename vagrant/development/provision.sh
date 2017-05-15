#! /usr/bin/env bash
sudo apt-get update -qq
sudo apt-get install -qq software-properties-common
sudo add-apt-repository -y ppa:yubico/stable
sudo apt-get update -qq && apt-get -qq upgrade
sudo apt-get install -qq \
    python-pip \
    python-pyscard \
    python-cryptography \
    libykpers-1-1 \
    libu2f-host0 \
    libssl-dev \
    libpcsclite-dev \
    pcscd \
    libffi-dev
pip install --upgrade pip
pip install pre-commit flake8
git clone --recursive https://github.com/Yubico/yubikey-manager.git
cd yubikey-manager && pip install -e . && chown -R ubuntu . && pre-commit install
