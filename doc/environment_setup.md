# eBPF Development Environment Setup Guide (Hybrid Architecture)

## 1. Hybrid Architecture Overview

This project uses a hybrid architecture to mitigate the limitations of virtualized file systems while maintaining the convenience of host development tools.

```text
[ HOST: Windows 11 ]                                  [ GUEST: OpenSUSE 15.6 ]
.                                                     .
.   VSCode (Editor)                                   .   Kernel 6.4.x (eBPF)
.   `-- Remote SSH Plugin ------------------------->  .   `-- SSH Server (Root)
.                                                     .
.   Project Folder (NTFS)                             .   Mount Point (/opt/host)
.   C:\Users\<USER>\GitHub\sys-inspector <== Shared = .   /opt/host/Syncfolder
.                                                     .   `-- Source Code (Read/Write)
.                                                     .
.                                                     .   Native File System (Ext4)
.                                                     .   /root/venvs/sys-inspector
.                                                         `-- Python Binaries and Libs
```

## 2. Components and Configuration

### 2.1. Host (Windows 11)

* Editor: Visual Studio Code.
* Terminal: PowerShell / MobaXterm.
* Virtualization: Oracle VirtualBox 7.x.
* SSH Keys: Generated natively (ssh-keygen) and cleared via "ssh-keygen -R [IP]" when necessary.

### 2.2. Guest (OpenSUSE Leap 15.6)

* IP: Static (e.g., <VM_IP>).
* Kernel: Version 6.4.x (Updated via Kernel:stable repository or Backports for modern eBPF support).
* Shared Mount:
  * Source: Local Windows folder.
  * Destination: /opt/host/Syncfolder.
  * Driver: vboxsf.

### 2.3. Toolchain eBPF/BCC

Installed via Zypper and verified to ensure exact parity between Kernel and Headers:

* bcc-tools
* python3-bcc
* llvm / clang
* kernel-default-devel (Version MUST exactly match "uname -r").

## 3. Critical Directory Structure

Due to the inability of the vboxsf driver to create symbolic links (required for Python venv), the following separation was adopted:

| Purpose          | Path in VM                               | File System       |
| :---             | :---                                     | :---              |
| Source Code      | /opt/host/Syncfolder/.../sys-inspector   | vboxsf (NTFS/Win) |
| Virtual Env      | /root/venvs/sys-inspector                | ext4 (Native Linux)|

## 4. Step-by-Step Installation (From Scratch)

### PHASE 1: VirtualBox Configuration

1. VM Creation: Linux / openSUSE (64-bit). Minimum 4GB RAM (8GB recommended for LLVM compilation), Minimum 2 vCPUs.
2. Network (Critical): Change from "NAT" to "Bridged Adapter". This allows the VM to receive a local network IP accessible from Windows.
3. Shared Folders: Host Path points to your local project. Guest Path is "/opt/host". Check "Auto-mount" and "Make Permanent".

### PHASE 2: Guest OS Installation

1. Boot: Start with openSUSE Leap 15.6 ISO.
2. Partitioning (Critical Point): Select "Expert Partitioner". For the root partition (/), change the default file system from Btrfs to Ext4. Reason: Avoid disk filling by Snapper snapshots on small disks.
3. Software Selection: "Server" or "Desktop with XFCE". Add "Base Development".
4. Finish: Create root user and conclude installation.

### PHASE 3: System Configuration (Post-Installation)

1. Network Configuration: Run "yast lan". Set Static IP, Gateway, and DNS.
2. Enable SSH for Root: Edit "/etc/ssh/sshd_config", set "PermitRootLogin yes", restart service "systemctl restart sshd".
3. Shared Folder Prep: Add root to vboxsf group "usermod -aG vboxsf root".

### PHASE 4: Toolchain and Dependencies (Guest)

Run the following commands to install compilers and Kernel headers:

```bash
    # 1. Update Zypper
    zypper refresh
    
    # 2. Install Compilers and Dependencies
    zypper install -y git clang llvm make gcc python3 python3-pip python3-devel
    
    # 3. Install BCC Tools
    zypper install -y python3-bcc bcc-tools
    
    # 4. Install Kernel Headers
    zypper install -y kernel-devel kernel-default-devel
```

### PHASE 5: Host Configuration (Windows)

If you reinstalled the VM keeping the IP, clear the old key:

```bash
    ssh-keygen -R <VM_IP>
```

Test connection:

```bash
    ssh root@<VM_IP>
```

### PHASE 6: Hybrid Project Environment (Resolving Symlinks)

1. Navigate to project: cd /opt/host/Syncfolder/.../sys-inspector
2. Create Decoupled Virtual Environment: Do NOT create venv in the current folder.

```bash
    mkdir -p /root/venvs
    python3 -m venv /root/venvs/sys-inspector --system-site-packages
```

3. Install QA Tools:

```bash
    source /root/venvs/sys-inspector/bin/activate
    pip install black pylint flake8
```

### PHASE 7: VSCode Configuration (Remote SSH)

1. Connect using "Remote-SSH: Connect to Host..." -> root@<VM_IP>.
2. Install Extensions on Remote: Install "Python" (Microsoft) on the SSH target.
3. Configure Python Interpreter (Manual): Press F1 -> "Python: Select Interpreter" -> "Enter interpreter path...". Path: /root/venvs/sys-inspector/bin/python.
4. Disable Auto Creation: If VSCode offers to create a venv in the project folder, refuse.

## 5. Automation Scripts

The project contains scripts in "scripts/" to replicate the environment:

* install_deps.sh: Updates Zypper, installs compilers (LLVM/Clang), BCC tools, and checks the kernel headers version.
* setup_venv.sh: Creates the /root/venvs/sys-inspector (Ext4) directory, initializes the virtual environment with --system-site-packages (for global BCC access), and installs development dependencies (black, pylint, flake8).

## 6. Daily Workflow and Cheat Sheet

### Starting a Development Session

1. Open VSCode, connect via SSH.
2. Open Integrated Terminal.
3. Activate environment: source /root/venvs/sys-inspector/bin/activate

### Running the Inspector

Since the code uses eBPF, execution requires root privileges.

```bash
    sudo python3 main.py --mode local-live
```

### Quality Assurance (Linting)

Before committing, check if the code is clean:

```bash
    ./scripts/run_python_test.bash
```

### Generating Anomalies for Testing

To validate if the inspector detects malwares and improper use:

```bash
    ./scripts/chaos_maker.sh
```

    # To kill the malicious process (which ignores Ctrl+C):

```bash
    sudo pkill -9 -f ".kworker_fake"
```

## 7. Common Troubleshooting

* Error "Operation not permitted" creating venv: Occurs if trying to create .venv inside the project folder (shared). Solution: Use setup_venv.sh which points to /root/venvs.
* BCC Import Error: Occurs if venv is created without the --system-site-packages flag.
* eBPF Compilation Failure: Usually indicates a mismatch between "uname -r" and the "kernel-default-devel" package. Run "zypper install -f kernel-default-devel" and reboot.
