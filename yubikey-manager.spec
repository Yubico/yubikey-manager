%{?python_enable_dependency_generator}
%global commit e17b3deed5ae8c983766943e71a13f7f15a99334
%global shortcommit %(c=%{commit}; echo ${c:0:7})
%global owner Yubico

Name:           yubikey-manager
Version:        2.0.0
Release:        4.git%{shortcommit}%{?dist}
Summary:        Python library and command line tool for configuring a YubiKey

License:        BSD
URL:            https://github.com/%{owner}/%{name}/
Source0:        https://github.com/%{owner}/%{name}/archive/%{commit}.tar.gz#/%{name}-%{shortcommit}.tar.gz

BuildArch:      noarch
BuildRequires:  python36-devel swig pcsc-lite-devel
# install_requires from setup.py
BuildRequires:  python36-six python36-pyscard python36-pyusb python36-click python36-cryptography python36-pyopenssl python36-fido2
Requires:       python3-%{name}

%description
Command line tool for configuring a YubiKey.

%package -n python3-%{name}
Summary:        Python library for configuring a YubiKey
Requires:       ykpers pcsc-lite

%{?python_provide:%python_provide python3-%{name}}

%description -n python3-%{name}
Python library for configuring a YubiKey.

%prep
%autosetup -n %{name}-%{commit}

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

%changelog
* Sun Feb 03 2019 Fedora Release Engineering <releng@fedoraproject.org> - 2.0.0-4.gite17b3de
- Rebuilt for https://fedoraproject.org/wiki/Fedora_30_Mass_Rebuild

* Wed Jan 09 2019 Gerald Cox <gbcox@fedoraproject.org> - 2.0.0-3.gite17b3de
- Upstream release - rhbz#1655888

* Tue Jan 01 2019 Igor Gnatenko <ignatenkobrain@fedoraproject.org> - 2.0.0-2.git1c707b2
- Enable python dependency generator

* Mon Dec 31 2018 Gerald Cox <gbcox@fedoraproject.org> - 2.0.0-1.git1c707b2
- Upstream release - rhbz#1655888

* Sat Jul 14 2018 Fedora Release Engineering <releng@fedoraproject.org> - 0.6.0-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_29_Mass_Rebuild

* Tue Jun 19 2018 Miro Hrončok <mhroncok@redhat.com> - 0.6.0-3
- Rebuilt for Python 3.7

* Mon May 7 2018 Seth Jennings <sethdjennings@gmail.com> - 0.6.0-2
- add u2f-host as dependency

* Wed May 2 2018 Seth Jennings <sethdjennings@gmail.com> - 0.6.0-1
- Upstream release

* Fri Feb 09 2018 Fedora Release Engineering <releng@fedoraproject.org> - 0.4.0-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_28_Mass_Rebuild

* Wed Aug 9 2017 Seth Jennings <sethdjennings@gmail.com> - 0.4.0-1
- New package
- Upstream release
