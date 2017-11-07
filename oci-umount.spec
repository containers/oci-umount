%global provider        github
%global provider_tld    com
%global project         projectatomic
%global repo            oci-umount
# https://github.com/projectatomic/oci-umount
%global provider_prefix %{provider}.%{provider_tld}/%{project}/%{repo}
%global import_path     %{provider_prefix}
%global commit          f034b5a7a33ae8496774d8747edc0ba370a6bcb1
%global shortcommit     %(c=%{commit}; echo ${c:0:7})

Name:           oci-umount
Version:        2.3
Release:        1.git%{shortcommit}%{?dist}
Summary:        OCI umount hook for docker
Group:          Applications/Text
License:        GPLv3+
URL:            https://%{provider_prefix}
Source0:        https://%{provider_prefix}/archive/%{commit}/%{repo}-%{shortcommit}.tar.gz

BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  pkgconfig(yajl)
BuildRequires:  pkgconfig(libselinux)
BuildRequires:  pkgconfig(mount)
BuildRequires:  golang-github-cpuguy83-go-md2man

%description
OCI umount hooks unmount potential leaked mount points in a containers
mount namespaces

%prep
%setup -q -n %{repo}-%{commit}

%build
autoreconf -i
%configure --libexecdir=/usr/libexec/oci/hooks.d/
make %{?_smp_mflags}

%install
%make_install

#define license tag if not already defined
%{!?_licensedir:%global license %doc}
%files
%{_libexecdir}/oci/hooks.d/oci-umount
%{_mandir}/man1/oci-umount.1*
%doc README.md
%license LICENSE
%config(noreplace) %{_sysconfdir}/oci-umount.conf
%dir /%{_libexecdir}/oci
%dir /%{_libexecdir}/oci/hooks.d
%dir /%{_sysconfdir}/containers/oci/hooks.d
%dir /usr/share/containers/oci/hooks.d
/usr/share/containers/oci/hooks.d/oci-umount.json
/usr/share/oci-umount/oci-umount.d
/usr/share/oci-umount/oci-umount-options.conf
%ghost /etc/oci-umount/oci-umount.d
%ghost /etc/oci-umount/oci-umount-options.conf


%changelog
* Tue Nov 7 2017 Dan Walsh <dwalsh@redhat.com> - 2.3.1
- Add support for new config file to turn down the logging.

* Thu Sep 21 2017 Dan Walsh <dwalsh@redhat.com> - 2.2.1
- Add support for alternate configuration files in /etc/oci-umount/oci-umount.d and
  /usr/share/oci-umount/oci-umount.d
- Support /* syntax to allow us to specify all mountpoints below a path.
* Wed Aug 16 2017 Dan Walsh <dwalsh@redhat.com> - 2.1.1
- Add support for /usr/share/containers/oci/hooks.d json files

* Wed May 17 2017 Dan Walsh <dwalsh@redhat.com> - 0.1.1
- Initial RPM release
