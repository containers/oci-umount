%global provider        github
%global provider_tld    com
%global project         projectatomic
%global repo            oci-umount
# https://github.com/projectatomic/oci-register-machine
%global provider_prefix %{provider}.%{provider_tld}/%{project}/%{repo}
%global import_path     %{provider_prefix}
%global commit          de345df3c18a6abfc8d9cf3822405c0e1bbe65c9
%global shortcommit     %(c=%{commit}; echo ${c:0:7})

Name:           oci-umount
Version:        0.1
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
%dir /%{_libexecdir}/oci
%dir /%{_libexecdir}/oci/hooks.d

%changelog
* Wed May 17 2017 Dan Walsh <dwalsh@redhat.com> - 0.1.1
- Initial RPM release
