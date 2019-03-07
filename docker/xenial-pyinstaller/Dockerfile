FROM ubuntu:xenial
RUN apt-get -qq update
RUN apt-get install -qq software-properties-common
RUN add-apt-repository -y ppa:yubico/stable
RUN apt-get -qq update && apt-get -qq upgrade && apt-get install -y libykpers-1-1 python3-pip python3-pyscard swig libpcsclite-dev
RUN apt-get -qq update && apt-get -qq upgrade && apt-get install -y git devscripts equivs
COPY debian/control /yubikey-manager/debian/control
RUN yes | mk-build-deps -i /yubikey-manager/debian/control
COPY . /yubikey-manager
RUN cd /yubikey-manager && pip3 install . && pip3 install pyinstaller && pyinstaller --console --onefile --clean ykman.spec
