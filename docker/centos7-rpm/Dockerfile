FROM centos:7
RUN yum -y install gcc rpm-build rpm-devel rpmlint make python bash coreutils diffutils patch rpmdevtools
RUN yum -y install epel-release
RUN yum-config-manager --enable epel-testing
RUN yum repolist
RUN yum -y install python36
COPY . /yubikey-manager
RUN rpmdev-setuptree
RUN spectool -g -R yubikey-manager/yubikey-manager.spec
# Fails because no python3-pyopenssl available
#RUN yum-builddep -y yubikey-manager/yubikey-manager.spec
#RUN cd yubikey-manager && rpmbuild -bs yubikey-manager.spec
