FROM centos:7
ENV LANG en_US.UTF-8
ENV LC_ALL en_US.UTF-8
RUN yum -y install gcc rpm-build rpm-devel \
    rpmlint make python bash coreutils diffutils \
    patch rpmdevtools wget python-setuptools \
    epel-release python36 python36-devel \
    python36-cryptography python36-setuptools
RUN yum-config-manager --enable epel-testing
RUN rpmdev-setuptree
COPY . /yubikey-manager
RUN spectool -g -R yubikey-manager/yubikey-manager.spec
RUN yum-builddep -y yubikey-manager/yubikey-manager.spec
RUN cd yubikey-manager && rpmbuild -bs yubikey-manager.spec && rpmbuild -bb yubikey-manager.spec
RUN yum -y install /root/rpmbuild/RPMS/noarch/python3-yubikey-manager-*.rpm
RUN yum -y install /root/rpmbuild/RPMS/noarch/yubikey-manager-*.rpm
RUN ykman --version
RUN mkdir /rpms
RUN mv /root/rpmbuild/RPMS/noarch/*.rpm /rpms
RUN tar czvf /yubikey-manager-centos7-rpms.tar.gz /rpms
