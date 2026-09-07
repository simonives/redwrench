# This spec file follows rust2rpm conventions. Once the crate is ready
# for packaging, regenerate it properly on a Fedora machine with:
#   rust2rpm redwrench
# and reconcile any differences with this hand-written starting point,
# rather than trusting this file as final.

%global crate redwrench

Name:           %{crate}
Version:        0.1.0
Release:        1%{?dist}
Summary:        A security-conscious MCP server for Fedora hardware and OS control

License:        MIT OR Apache-2.0
URL:            https://github.com/simonives/redwrench
Source0:        %{crate}-%{version}.crate

BuildRequires:  rust-packaging >= 21

%description
%{summary}.

%prep
%autosetup -n %{crate}-%{version} -p1

%build
%cargo_build

%install
%cargo_install

%files
%license LICENSE-MIT LICENSE-APACHE
%{_bindir}/%{crate}
%{_mandir}/man1/%{crate}.1*

%changelog
* Sun Sep 07 2026 Simon Ives <redwrench@example.invalid> - 0.1.0-1
- Initial packaging
