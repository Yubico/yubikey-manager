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
    python-openssl \
    python3-openssl \
    python-enum34 \
    libykpers-1-1 \
    libu2f-host0 \
    pcscd \
    debhelper \
    devscripts
COPY . yubikey-manager
RUN cd yubikey-manager && debuild -us -uc
RUN mkdir /deb
RUN mv /yubikey-manager_* /deb
RUN mv /python3-yubikey-manager_* /deb
RUN mv /python-yubikey-manager_* /deb
RUN cd / && tar czf yubikey-manager-debian-builds.tar.gz deb
