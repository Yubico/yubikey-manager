FROM ubuntu:xenial
RUN apt-get -qq update -y && apt-get -qq upgrade
RUN apt-get install -y git devscripts equivs
COPY . yubikey-manager
WORKDIR yubikey-manager
RUN yes | mk-build-deps -i debian/control
RUN debuild -us -uc
RUN mkdir /deb
RUN mv /yubikey-manager_* /deb
RUN mv /python3-yubikey-manager_* /deb
RUN mv /python-yubikey-manager_* /deb
RUN cd / && tar czf yubikey-manager-debian-packages.tar.gz deb
