FROM centos:7
ENV LANG en_US.UTF-8
ENV LC_ALL en_US.UTF-8
RUN yum -y install gcc rpm-build rpm-devel rpmlint make python bash coreutils diffutils patch rpmdevtools wget python-setuptools
RUN yum -y install epel-release
RUN yum-config-manager --enable epel-testing
RUN yum repolist
RUN yum -y install python36 python36-devel python36-cryptography python36-setuptools
RUN rpmdev-setuptree
RUN wget https://www.cora.nwra.com/~orion/fedora/python3-pyOpenSSL-17.3.0-1.el7.src.rpm
RUN rpmbuild --rebuild python3-pyOpenSSL-*.src.rpm
RUN yum -y install /root/rpmbuild/RPMS/noarch/python36-pyOpenSSL-*.noarch.rpm

COPY . /yubikey-manager
RUN spectool -g -R yubikey-manager/yubikey-manager.spec
RUN yum-builddep -y yubikey-manager/yubikey-manager.spec
RUN cd yubikey-manager && rpmbuild -bs yubikey-manager.spec && rpmbuild -bb yubikey-manager.spec
RUN yum -y install /root/rpmbuild/RPMS/noarch/python3-yubikey-manager-*.rpm
RUN yum -y install /root/rpmbuild/RPMS/noarch/yubikey-manager-*.rpm
RUN ykman --version
