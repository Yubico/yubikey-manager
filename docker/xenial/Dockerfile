FROM ubuntu:xenial
RUN mkdir /deb
RUN apt-get -qq update
RUN apt-get install -qq software-properties-common
RUN add-apt-repository -y ppa:yubico/stable
RUN apt-get -qq update && apt-get -qq upgrade && apt-get install -y git devscripts equivs
COPY debian/control /yubikey-manager/debian/control
RUN yes | mk-build-deps -i /yubikey-manager/debian/control

COPY . /yubikey-manager
RUN cd /yubikey-manager && debuild -us -uc

RUN mv /yubikey-manager_* /python3-yubikey-manager_* /python-yubikey-manager_* /deb
RUN tar czf /yubikey-manager-debian-packages.tar.gz /deb
