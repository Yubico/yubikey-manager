FROM ubuntu:xenial
RUN apt-get -qq update -y && apt-get -qq upgrade
RUN apt-get install -qq python-pyscard
RUN apt-get install -qq \
    git \ 
    python\
    python3 \
    python-all \
    python3-all \
    python-pip \
    python3-pip \
    python-setuptools \
    python3-setuptools \
    python3-pyscard \
    python-usb \
    python3-usb \
    python-six \
    python3-six \
    python-cryptography \
    python3-cryptography \
    python-click \
    python3-click \
    python-enum34 \
    libykpers-1-1 \
    libu2f-host0 \
    pcscd \
    debhelper \
    devscripts
RUN git clone --recursive https://github.com/Yubico/yubikey-manager
RUN cd yubikey-manager && debuild -us -uc
RUN mkdir /deploy
RUN mv /yubikey-manager_* /deploy
RUN mv /python3-yubikey-manager_* /deploy
RUN mv /python-yubikey-manager_* /deploy
RUN cd / && tar czf yubikey-manager-debian-builds.tar.gz deploy

