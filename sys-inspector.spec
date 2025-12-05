#
# spec file for package sys-inspector
#
# Copyright (c) 2025 Mario Luz
#

Name:           sys-inspector
Version:        0.30.7
Release:        2%{?dist}
Summary:        eBPF-based System Inspector and Forensic Tool

License:        GPL-3.0-only
URL:            https://github.com/mariosergiosl/sys-inspector
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch

# Build Dependencies
BuildRequires:  python3-devel
BuildRequires:  python3-setuptools
BuildRequires:  fdupes

# Runtime Dependencies (CRITICAL for eBPF)
Requires:       python3
Requires:       python3-bcc
Requires:       kernel-devel
Requires:       binutils

%description
Sys-Inspector is an advanced observability tool leveraging eBPF technology.
It provides real-time analysis of:
- Process Execution (execve) with Hash Calculation
- File I/O (openat, vfs_read/write) with Zoning/HCTL info
- Network Connections (TCPv4)
- Memory Usage (RSS vs VSZ)
- Security Contexts (SSH Origin, Sudo, AppArmor)

Designed for SREs and Forensic Analysts.

%prep
%setup -q

%build
%python3_build

%install
%python3_install
# Fix duplicate files if any
%fdupes %{buildroot}%{python3_sitelib}

%files
%doc README.md ROADMAP.md CHANGELOG.md
%license LICENSE.md
%{_bindir}/sys-inspector
%{python3_sitelib}/sys_inspector/
%{python3_sitelib}/inspector.py
%{python3_sitelib}/__pycache__/*
%{python3_sitelib}/sys_inspector-*.egg-info/

%changelog
* Fri Nov 28 2025 Mario Luz <mario.mssl@gmail.com> - 0.20.0
- Release v0.20.0: Enterprise Forensic features, HCTL mapping, and HTML Reporting.