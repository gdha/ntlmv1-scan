%global upstream_version %(awk -F'"' '/^#define VERSION / {print $2; exit}' %{SOURCE1})

Name:           ntlmv1scan
Version:        %{upstream_version}
Release:        1%{?dist}
Summary:        Detect NTLMv1 authentication traffic on SMB sessions

License:        GPL-3.0-only
URL:            https://github.com/gdha/ntlmv1-scan
Source0:        %{name}-%{version}.tar.gz
Source1:        ntlmv1scan.h

BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  gcc
BuildRequires:  make

%description
ntlmv1scan captures Linux network traffic and reports potential NTLMv1
authentication usage on SMB sessions.

%prep
%autosetup -n %{name}-%{version}

%build
autoreconf -vfi
%configure
%make_build

%install
%make_install

%files
%license COPYING
%doc README.md AUTHORS
%{_bindir}/ntlmv1scan
%{_mandir}/man8/ntlmv1scan.8*

%changelog
* Thu Apr 16 2026 Maintainer <maintainer@example.com> - %{version}-1
- Initial RPM packaging
