# This spec file follows rust2rpm conventions. Once the crate is ready
# for packaging, regenerate it properly on a Fedora machine with:
#   rust2rpm redwrench
# and reconcile any differences with this hand-written starting point,
# rather than trusting this file as final. In particular, rust2rpm emits
# its own %prep/%build/%install bodies and a generated -devel subpackage;
# the man page, unit file, and config handling below are the parts worth
# carrying across.

%global crate redwrench

Name:           %{crate}
Version:        1.0.1
Release:        1%{?dist}
Summary:        A security-conscious MCP server for Fedora hardware and OS control

License:        MIT OR Apache-2.0
URL:            https://github.com/simonives/redwrench
Source0:        %{crate}-%{version}.crate
Source1:        %{crate}.service

BuildRequires:  rust-packaging >= 21
BuildRequires:  systemd-rpm-macros

%description
%{summary}.

RedWrench exposes hardware and OS control on a Fedora machine to AI coding
agents running elsewhere on the network. Every invocation is filtered
through an ordered allow/deny policy engine and recorded in the systemd
journal.

%prep
%autosetup -n %{crate}-%{version} -p1

%build
%cargo_build

%install
%cargo_install

# The man page is generated at build time by build.rs into the crate's
# OUT_DIR, which %cargo_install does not install. The OUT_DIR path carries
# a build-hash suffix, so glob for it rather than hardcoding it, and fail
# loudly if the build script did not produce one (a silent skip here is
# what previously left %files referencing a file nothing installed).
install -d %{buildroot}%{_mandir}/man1
_rw_man=$(find target -type f -name '%{crate}.1' -path '*/out/*' | head -n1)
test -n "${_rw_man}" || { echo "generated man page not found under target/" >&2; exit 1; }
install -p -m 0644 "${_rw_man}" %{buildroot}%{_mandir}/man1/%{crate}.1

install -D -p -m 0644 %{SOURCE1} %{buildroot}%{_unitdir}/%{crate}.service

# The config file is shipped empty and root-only. It cannot be shipped
# populated: it must contain a bearer token unique to this machine, and the
# server refuses to authenticate anything against an empty token. The admin
# is expected to write a real bind_address, a freshly generated
# bearer_token, and a tier before enabling the service. See README.md for a
# worked example.
install -d -m 0755 %{buildroot}%{_sysconfdir}/%{crate}
install -p -m 0600 /dev/null %{buildroot}%{_sysconfdir}/%{crate}/config.toml

%post
%systemd_post %{crate}.service

%preun
%systemd_preun %{crate}.service

%postun
%systemd_postun_with_restart %{crate}.service

%files
%license LICENSE-MIT LICENSE-APACHE
%doc README.md
%{_bindir}/%{crate}
%{_mandir}/man1/%{crate}.1*
%{_unitdir}/%{crate}.service
%dir %attr(0755, root, root) %{_sysconfdir}/%{crate}
%config(noreplace) %attr(0600, root, root) %{_sysconfdir}/%{crate}/config.toml

%changelog
* Sun Sep 07 2026 Simon Ives <redwrench@example.invalid> - 0.1.0-1
- Initial packaging
