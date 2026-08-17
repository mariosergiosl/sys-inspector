# ==============================================================================
# FILE: sys-inspector.spec
# DESCRIPTION: RPM Spec file for Sys-Inspector (multi-package by role)
# AUTHOR: Mario Luz
# ==============================================================================

Name:           sys-inspector
Version:        1.0.1
Release:        1%{?dist}
Summary:        System inspector and forensic tool using eBPF (Multi-Agent/Web)

Group:          System/Monitoring
License:        AGPL-3.0-only
URL:            https://github.com/mariosergiosl/sys-inspector
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch

# Build Dependencies
BuildRequires:  python3-devel
BuildRequires:  python3-setuptools
BuildRequires:  fdupes
BuildRequires:  systemd-rpm-macros

# ------------------------------------------------------------------------------
# DEPENDENCIAS POR PAPEL
#
# O pacote base carrega apenas o que TODO papel precisa. Antes ele exigia tudo,
# e o resultado media-se em campo: um agente instalado no gateway trouxe doze
# pacotes de servidor web (Flask, Jinja2, Werkzeug, Babel e cadeia) para um host
# sob inspecao que jamais os usaria, enquanto o servidor era obrigado a instalar
# bcc e os cabecalhos do kernel que nunca carregou.
#
# Nos dois casos o custo real nao e disco: e superficie de ataque acrescentada
# onde nao ha funcao que a justifique, justamente pela ferramenta que existe
# para reduzi-la.
# ------------------------------------------------------------------------------
Requires:       python3
Requires:       python3-cryptography
Requires:       python3-PyYAML

%{?systemd_requires}

%description
Sys-Inspector is an advanced observability tool leveraging eBPF technology.
It provides real-time analysis of process execution, file I/O, network
connections, and security contexts.
It provides real-time analysis of:
- Process Execution (execve) with Hash Calculation
- File I/O (openat, vfs_read/write) with Zoning/HCTL info
- Network Connections (TCPv4)
- Memory Usage (RSS vs VSZ)
- Security Contexts (SSH Origin, Sudo, AppArmor)
- Multi-Agent Fleet Monitoring (Web Dashboard)
- Forensic Time Machine (Historical Snapshots)
It ships a Multi-Agent architecture, Fleet View, FHS compliant paths and
native systemd integration.
Designed for SREs and Forensic Analysts.

# ------------------------------------------------------------------------------
# SUBPACOTE: AGENTE
# ------------------------------------------------------------------------------
%package agent
Summary:        Sys-Inspector collection agent (eBPF)
Requires:       %{name} = %{version}-%{release}
Requires:       python3-bcc
Requires:       kernel-devel
Requires:       binutils
%if 0%{?suse_version}
Recommends:     %{name}-scenarios = %{version}-%{release}
%endif

%description agent
Collection side of Sys-Inspector: attaches eBPF probes and captures process,
file and network activity on the inspected host.

Installs no web server. The host under investigation should carry only what the
collection itself requires, so that the tool does not add attack surface to the
very machine it is there to examine.

Captures are encrypted with the analyst public key before touching disk, and the
agent never holds the private key: a compromised host cannot read what has
already been collected on it.

# ------------------------------------------------------------------------------
# SUBPACOTE: SERVIDOR
# ------------------------------------------------------------------------------
%package server
Summary:        Sys-Inspector central server (fleet, ingestion, reports)
Requires:       %{name} = %{version}-%{release}
Requires:       python3-Flask

%description server
Server side of Sys-Inspector: receives captures from the fleet, stores them and
renders the forensic reports.

Requires no eBPF and no kernel headers. The server never opens a connection to
an agent; agents ask and write, which is what allows the inspected host to keep
no listening service.

# ------------------------------------------------------------------------------
# SUBPACOTE: CENARIOS DE TESTE
# ------------------------------------------------------------------------------
%package scenarios
Summary:        Sys-Inspector detection test scenarios (laboratory only)
Requires:       %{name} = %{version}-%{release}

%description scenarios
Test scenarios used to verify that detection actually works, by generating the
observable behaviour of known techniques and checking that the capture sees it.

LABORATORY USE ONLY. These scenarios create files, processes and network noise
on the machine where they run, and are meant for calibration on hosts dedicated
to that purpose, never on a system under investigation or in service.

They act only on the local host.
There is no network scanning, no remote exploitation, and
no functional exploit code: what is reproduced is the observable behaviour of a
technique, not a weapon. Everything created is removed afterwards.

The purpose is to prove the detection works, which is why the expected signal of
each scenario is declared alongside it.

%prep
%setup -q

%build
%python3_build

%install
%python3_install
# Fix duplicate files if any
%fdupes %{buildroot}%{python3_sitelib}

# Create FHS state and log directories
mkdir -p %{buildroot}/etc/sys-inspector
mkdir -p %{buildroot}/var/lib/sys-inspector
mkdir -p %{buildroot}/var/log/sys-inspector/reports
# SUSE Policy: Move systemd unit file from /etc to /usr/lib
mkdir -p %{buildroot}%{_unitdir}
if [ -f %{buildroot}/etc/systemd/system/sys-inspector.service ]; then
    mv %{buildroot}/etc/systemd/system/sys-inspector.service %{buildroot}%{_unitdir}/
fi
# SUSE convention: rc symlink for the service (rcsys-inspector -> service),
# fixes rpmlint suse-missing-rclink.
mkdir -p %{buildroot}%{_sbindir}
ln -sf %{_sbindir}/service %{buildroot}%{_sbindir}/rc%{name}

%pre
%service_add_pre sys-inspector.service

%post
%service_add_post sys-inspector.service

%preun
%service_del_preun sys-inspector.service

%postun
%service_del_postun sys-inspector.service

# ------------------------------------------------------------------------------
# ARQUIVOS
#
# O codigo-fonte NAO e dividido: o mesmo pacote base carrega todos os modulos, e
# main.py importa o controlador sob demanda, de modo que o modo servidor nunca
# toca no codigo de eBPF e vice-versa. Dividir os arquivos criaria dois lugares
# para a mesma logica; o que se divide sao as DEPENDENCIAS, que e onde esta o
# custo real.
# ------------------------------------------------------------------------------
%files
%defattr(-,root,root,-)
%doc README.md ROADMAP.md CHANGELOG.md
%license LICENSE.md
%{_bindir}/sys-inspector
%{_bindir}/setup_env.sh
%{_bindir}/install_deps.sh
%{_bindir}/install_service.bash
%{_bindir}/generate_keys.py
%{_sbindir}/rcsys-inspector
%{python3_sitelib}/*

%files agent
%defattr(-,root,root,-)

%files server
%defattr(-,root,root,-)

%files scenarios
%defattr(-,root,root,-)
%{_bindir}/chaos_maker.sh

# ==============================================================================
# Configuration and systemd files
# ==============================================================================
# Configuration Files (FHS)
%dir /etc/sys-inspector
%config(noreplace) /etc/sys-inspector/config.yaml
# Systemd Unit File
%{_unitdir}/sys-inspector.service
# State and Log Directories (FHS)
%dir %attr(0750,root,root) /var/lib/sys-inspector
%dir %attr(0750,root,root) /var/log/sys-inspector
%dir %attr(0750,root,root) /var/log/sys-inspector/reports

%changelog
* Mon Aug 17 2026 Mario Luz <mario.mssl@gmail.com> - 1.0.1-1
- Fixed: file-ownership provenance now falls back to dpkg (resilient to usrmerge and alternatives) when rpm is present but does not own the file, so it works on Debian/Ubuntu hosts; content verification runs only under a real rpm owner.
- Changed: restored a green CI by clearing the flake8/pylint backlog and ignoring style-only checks with a documented rationale.
* Thu Aug 13 2026 Mario Luz <mario.mssl@gmail.com> - 1.0.0-1
- Added: answer contract per finding (D-022) with a confidence level (confirmed/probable/heuristic) and a custody level (metadata/hash/full), so the report never presents a heuristic as a fact and states what was preserved.
- Added: Manager command progress as a stepper (enqueued -> on the agent -> done/failed) with a live timer, replacing the flat status text.
- Added: report didactics and cross-tab coupling: per-finding evidence tooltips, a severity legend with the operator action, a "how to read" strip, and clickable pivots between Findings and ATT&CK in both directions.
- Fixed: version is now a single source across every screen, the custody stamp and the shell scripts; the Live UI, live and snapshot reports no longer hardcode a stale version.
* Thu Aug 06 2026 Mario Luz <mario.mssl@gmail.com> - 0.91.0-1
- Added: normalized Finding entity (single severity scale, explicit source, MITRE ATT&CK technique, attached evidence) and a persistence collector covering systemd units, cron/at, startup scripts, ld.so.preload, kernel module autoload, udev rules, PAM stacks and per-user authorized_keys.
- Added: first automated test suite (pytest) wired into CI.
- Changed: all execution modes unified on a single encrypted storage model and data shape; live and server modes restored.
- Fixed: snapshot hot columns were always zero; alert badge showed a raw score; host-controlled data was not escaped in the HTML report; rpmlint findings in the package.
* Sun Jul 12 2026 Mario Luz <mario.mssl@gmail.com> - 0.90.16-1
- Security: optional dashboard HTTP Basic Auth and HTTPS (self-signed auto-generation), XSS prevention in the Fleet/Inspector views, and setup-script PATH hardening.
- Fixed: pyproject/setup packaging conflict, honor general.log_level, leaf-node expander literal, duplicate EDR-WAIT badge, WARN score tooltip, and false-positive NET ERR on kernel threads.
- Changed: toolbar active-state indicator and symmetric Process By / Filters icons.
* Wed Mar 18 2026 Mario Luz <mario.mssl@gmail.com> - 0.90.14
- Release v0.90.14: FHS compliant paths, systemd integration, and PyPI and OBS sync.