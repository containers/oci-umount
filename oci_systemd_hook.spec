Name:           oci_systemd_hook
Version:        0.1.3
Release:        1%{?dist}
Summary:        OCI systemd hook for docker
Group:          Applications/Text
License:        GPLv3+
URL:            https://github.com/mrunalp/hooks
Source:         https://github.com/mrunalp/hooks/archive/v%{version}.tar.gz

BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  yajl-devel
BuildRequires:  libselinux-devel

Requires: docker

%description
OCI systemd hooks enable running systemd in a docker container.

%prep
%setup -q -n hooks-%{version}

%build
autoreconf -i
%configure --libexecdir=/usr/libexec/docker/hooks.d/
make %{?_smp_mflags}

%install
%make_install

%files
%{_libexecdir}/docker/hooks.d/oci_systemd_hook
%{_mandir}/man1/oci_systemd_hook.1*
%doc README.md LICENSE

%changelog
* Mon Nov 22 2015 Mrunal Patel <mrunalp@gmail.com> - 0.1.2
- Fix bug in man page installation
* Mon Nov 22 2015 Mrunal Patel <mrunalp@gmail.com> - 0.1.3
- Add man pages
* Mon Nov 22 2015 Mrunal Patel <mrunalp@gmail.com> - 0.1.2
- Initial RPM release
