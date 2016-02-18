%global provider        github
%global provider_tld    com
%global project         projectatomic
%global repo            oci-systemd-hook
# https://github.com/projectatomic/oci-register-machine
%global provider_prefix %{provider}.%{provider_tld}/%{project}/%{repo}
%global import_path     %{provider_prefix}
%global commit          fb2a8b5f6c5f86b5fe2b60bdd1c6f13025702ea1
%global shortcommit     %(c=%{commit}; echo ${c:0:7})
#define license tag if not already defined
%{!?_licensedir:%global license %doc}

Name:           oci-systemd-hook
Version:        0.1.4
Release:        1.git%{shortcommit}%{?dist}
Summary:        OCI systemd hook for docker
Group:          Applications/Text
License:        GPLv3+
URL:            https://%{provider_prefix}
Source0:        https://%{provider_prefix}/archive/%{commit}/%{repo}-%{shortcommit}.tar.gz

BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  yajl-devel
BuildRequires:  libselinux-devel
BuildRequires:  libmount-devel
BuildRequires:  golang-github-cpuguy83-go-md2man

%description
OCI systemd hooks enable running systemd in a OCI runc/docker container.

%prep
%setup -q -n %{repo}-%{commit}

%build
autoreconf -i
%configure --libexecdir=/usr/libexec/oci/hooks.d/
make %{?_smp_mflags}

%install
%make_install

%files
%{_libexecdir}/oci/hooks.d/oci-systemd-hook
%{_mandir}/man1/oci-systemd-hook.1*
%doc README.md
%license LICENSE

%changelog
* Thu Feb 18 2016 Dan Walsh <dwalsh@redhat.com> - 0.1.4
- Fix up to prepare for review

* Mon Nov 23 2015 Mrunal Patel <mrunalp@gmail.com> - 0.1.3
- Fix bug in man page installation
* Mon Nov 23 2015 Mrunal Patel <mrunalp@gmail.com> - 0.1.2
- Add man pages
* Mon Nov 23 2015 Mrunal Patel <mrunalp@gmail.com> - 0.1.1
- Initial RPM release
