# Recover\(Remediate\)

## PATCHING

### WINDOWS

#### Single Hotfix update for Windows 7 or higher:

```text
C:\> wusa.exe C:\<PATH TO HOTFIX>\Windows6.0-
KB934307-x86.msu
```

#### Set of single hotfix updates for pre Windows 7 by running a batch script:

```text
@echo off
setlocal
set PATHTOFIXES=E:\hotfix
%PATHTOFIXES%\Q123456_w2k_sp4_x86.exe /2 /M
%PATHTOFIXES%\Ql23321_w2k_sp4_x86.exe /2 /M
%PATHTOFIXES%\Q123789_w2k_sp4_x86.exe /2 /M
```

#### To check and update Windows 7 or higher:

```text
C:\> wuauclt.exe /detectnow /updatenow
```

### LINUX

#### Ubuntu:

#### Fetch list of available updates:

```text
# apt-get update
```

#### Strictly upgrade the current packages:

```text
# apt-get upgrade
```

#### Install updates \(new ones\):

```text
# apt-get dist-upgrade
```

#### Red Hat Enterprise Linux 2.1,3,4:

```text
# up2date
```

#### To update non-interactively:

```text
# up2date-nox --update
```

#### To install a specific package:

```text
# up2date <PACKAGE NAME>
```

#### To update a specific package:

```text
# up2date -u <PACKAGE NAME>
```

#### Red Hat Enterprise Linux 5:

```text
# pup
```

#### Red Hat Enterprise Linux 6:

```text
# yum update
```

#### To list a specific installed package:

```text
# yum list installed <PACKAGE NAME>
```

#### To install a specific package:

```text
# yum install <PACKAGE NAME>
```

#### To update a specific package:

```text
# yum update <PACKAGE NAME>
```

#### Kali:

```text
# apt-get update && apt-get upgrade
```

### BACKUP

#### WINDOWS

#### Backup GPO Audit Policy to backup file:

```text
C:\> auditpol /backup /file:C\auditpolicy.csv
```

#### Restore GPO Audit Policy from backup file:

```text
C:\> auditpol /restore /file:C:\auditpolicy.csv
```

#### Backup All GPOs in domain and save to Path:

```text
PS C:\> Backup-Gpo -All -Path \\<SERVER>\<PATH TO
BACKUPS>
```

#### Restore All GPOs in domain and save to Path:

```text
PS C:\> Restore-GPO -All -Domain <INSERT DOMAIN
NAME> -Path \\Serverl\GpoBackups
```

#### Start Volume Shadow Service:

```text
C:\> net start VSS
```

#### List all shadow files and storage:

```text
C:\> vssadmin List ShadowStorage
```

#### List all shadow files:

```text
C:\> vssadmin List Shadows
```

#### Browse Shadow Copy for files/folders:

```text
C:\> mklink /d c:\<CREATE FOLDER>\<PROVIDE FOLDER
NAME BUT DO NOT CREATE>
\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyl\
```

#### Revert back to a selected shadow file on Windows Server and Windows 8:

```text
C:\> vssadmin revert shadow /shadow={<SHADOW COPY
ID>} /ForceDismount
```

#### List a files previous versions history using volrest.exe:

Ref. [https://www.microsoft.com/enus/](https://www.microsoft.com/enus/) download/details.aspx?id=17657

```text
C:\> "\Program Files (x86)\Windows Resource
Kits\Tools\volrest.exe" "\\localhost\c$\<PATH TO
FILE>\<FILE NAME>"
```

#### Revert back to a selected previous file version or @GMT file name for specific previous version using volrest.exe:

```text
C:\> subst Z: \\localhost\c$\$\<PATH TO FILE>
C:\> "\Program Files (x86)\Windows Resource
Kits\Tools\volrest.exe" "\\localhost\c$\<PATH TO
FILE>\<CURRENT FILE NAME OR @GMT FILE NAME FROM LIST
COMMAND ABOVE>" /R:Z:\
C:\> subst Z: /0
```

#### Revert back a directory and subdirectory files previous version using volrest.exe:

```text
C: \> "\Program Files (x86) \Windows Resource
Kits\Tools\volrest.exe" \\localhost\c$\<PATH TO
FOLDER\*·* /5 /r:\\localhost\c$\<PATH TO FOLDER>\
```

#### Revert back to a selected shadow file on Windows Server and Windows 7 and 10 using wmic:

```text
C:\> wmic shadowcopy call create Volume='C:\'
```

#### Create a shadow copy of volume C on Windows 7 and 10 using PowerShell:

```text
PS C:\> (gwmi -list
win32_shadowcopy).Create('C:\', 'ClientAccessible')
```

#### Create a shadow copy of volume C on Windows Server 2003 and 2008:

```text
C:\> vssadmin create shadow /for=c:
```

#### Create restore point on Windows:

```text
C:\> wmic.exe /Namespace:\\root\default Path
SystemRestore Call CreateRestorePoint "%DATE%", 100,
7
```

#### Start system restore points on Windows XP:

```text
C:\> sc config srservice start= disabled
C:\> reg add
"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows
NT\CurrentVersion\SystemRestore" /v DisableSR /t
REG_DWORD /d 1 /f
C:\> net stop srservice
```

#### List of restore points:

```text
PS C:\> Get-ComputerRestorePoint
```

#### Restore from a specific restore point:

```text
PS C:\> Restore-Computer -RestorePoint <RESTORE
POINT#> -Confirm
```

### LINUX

#### Reset root password in single user mode:

**Step 1:** Reboot system.

```text
# reboot -f
```

**Step 2:** Press ESC at GRUB screen.

**Step 3:** Select default entry and then 'e' for edit.

**Step 4:** Scroll down until, you see a line that starts with linux, linux16 or linuxefi.

**Step 5:** At end of that line leave a space and add without quote 'rw init=/bin/bash'

**Step 6:** Press Ctrl-X to reboot.

**Step 7:** After reboot, should be in single user mode and root, change password.

```text
# passwd
```

**Step 8:** Reboot system.

```text
# reboot -f
```

#### Reinstall a package:

```text
# apt-get install --reinstall <COMPROMISED PACKAGE
NAME>
```

#### Reinstall all packages:

```text
# apt-get install --reinstall $(dpkg --getselections
lgrep -v deinstall)
```

## KILL MALWARE PROCESS

### WINDOWS

#### Malware Removal:

Ref. [http://www.gmer.net/](http://www.gmer.net/)

```text
C:\> gmer.exe (GUI)
```

#### Kill running malicious file:

```text
C:\> gmer.exe -killfile
C:\WINDOWS\system32\drivers\<MALICIOUS FILENAME>.exe
```

#### Kill running malicious file in PowerShell:

```text
PS C:\> Stop-Process -Name <PROCESS NAME>
PS C:\> Stop-Process -ID <PID>
```

### LINUX

#### Stop a malware process:

```text
# kill <MALICIOUS PID>
```

#### Change the malware process from execution and move:

```text
# chmod -x /usr/sbin/<SUSPICIOUS FILE NAME>
# mkdir /home/quarantine/
# mv /usr/sbin/<SUSPICIOUS FILE NAME>
/home/quarantine/
```



















