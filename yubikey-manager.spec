Name:           yubikey-manager
Version:        2.1.0
Release:        1%{?dist}
Summary:        Python library and command line tool for configuring a YubiKey

License:        BSD
URL:            https://developers.yubico.com/yubikey-manager/
Source0:        https://developers.yubico.com/yubikey-manager/Releases/yubikey-manager-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python36-devel swig pcsc-lite-devel
# install_requires from setup.py
# todo: add python36-openssl
BuildRequires:  python36-setuptools python36-six python36-pyscard python36-pyusb python36-click python36-cryptography python36-fido2
Requires:       python3-%{name}

%description
Command line tool for configuring a YubiKey.

%package -n python3-%{name}
Summary:        Python library for configuring a YubiKey
Requires:       ykpers pcsc-lite

%description -n python3-%{name}
Python library for configuring a YubiKey.

%prep
%autosetup -n %{name}-%{version}

%build
%py3_build

%install
%py3_install

%check
%{__python3} setup.py test

%files -n python3-%{name}
%license COPYING
%doc NEWS
%{python3_sitelib}/*

%files
%{_bindir}/ykman
