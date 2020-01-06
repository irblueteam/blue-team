# Respond\(Analysis\)

## LIVE TRIAGE - WINDOWS

### SYSTEM INFORMATION

```text
C:\> echo %DATE% %TIME%
C:\> hostname
C:\> systeminfo
C:\> systeminfo I findstr /B /C:"OS Name" /C:"OS
Version"
C:\> wmic csproduct get name
C:\> wmic bios get serialnumber
C:\> wmic computersystem list brief
```

Ref. [https://technet.microsoft.com/en­](https://technet.microsoft.com/en­) us/sysinternals/psinfo.aspx

```text
C:\> psinfo -accepteula -s -h -d
```

### USER INFORMATION

```text
C:\> whoami
C:\> net users
C:\> net localgroup administrators
C:\> net group administrators
C:\> wmic rdtoggle list
C:\> wmic useraccount list
C:\> wmic group list
C:\> wmic netlogin get
name, lastlogon,badpasswordcount
C:\> wmic netclient list brief
C:\> doskey /history> history.txt
```

### NETWORK INFORMATION

```text
C:\> netstat -e
C:\> netstat -naob
C:\> netstat -nr
C:\> netstat -vb
C:\> nbtstat -s
C:\> route print
C:\> arp -a
C:\> ipconfig /displaydns
C:\> netsh winhttp show proxy
C:\> ipconfig /allcompartments /all
C:\> netsh wlan show interfaces
C:\> netsh wlan show all
C:\> reg query
"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Inte
rnet Settings\Connections\WinHttpSettings"
C:\> type %SYSTEMROOT%\system32\drivers\etc\hosts
C:\> wmic nicconfig get
descriptions,IPaddress,MACaddress
C:\> wmic netuse get
name,username,connectiontype, localname
```

### SERVICE INFORMATION

```text
C:\> at
C:\> tasklist
C:\> task list /SVC
C:\> tasklist /SVC /fi "imagename eq svchost.exe"
C:\> schtasks
C:\> net start
C:\> sc query
C:\> wmic service list brief I findstr "Running"
C:\> wmic service list conf ig
C:\> wmic process list brief
C:\> wmic process list status
C:\> wmic process list memory
C:\> wmic job list brief
PS C:\> Get-Service I Where-Object { $_.Status -eq
"running" }
```

#### List of all processes and then all loaded modules:

```text
PS C:\> Get-Process !select modules!Foreach­
Object{$_.modules}
```

### POLICY, PATCH AND SETTINGS INFORMATION

```text
C:\> set
C:\> gpresult /r
C:\> gpresult /z > <OUTPUT FILE NAME>.txt
C:\> gpresult /H report.html /F
C:\> wmic qfe
```

#### List GPO software installed:

```text
C:\> reg query
uHKLM\Software\Microsoft\Windows\Current
Version\Group Policy\AppMgmt"
```

### AUTORUN AND AUTOLOAD INFORMATION

```text
Startup information:
C:\> wmic startup list full
C:\> wmic ntdomain list brief
```

#### View directory contents of startup folder:

```text
C:\> dir
"%SystemDrive%\ProgramData\Microsoft\Windows\Start
Menu\P rog rams\Sta rtup"
C:\> dir "%SystemDrive%\Documents and Settings\All
Use rs\Sta rt Menu\Prog rams\Sta rtup"
C:\> dir %userprofile%\Start Menu\Programs\Startup
C:\> %ProgramFiles%\Startup\
C:\> dir C:\Windows\Start Menu\Programs\startup
C:\> dir
"C:\Users\%username%\AppData\Roaming\Microsoft\Windo
ws\Start Menu\Programs\Startup"
C:\> dir "C:\ProgramData\Microsoft\Windows\Start
Menu\P rog rams\Sta rtup"
C:\> dir "%APPDATA%\Microsoft\Windows\Start
Menu\Prog rams\Sta rtup"
C:\> dir "%ALLUSERSPROFILE%\Microsoft\Windows\Start
Menu\Prog rams\Sta rtup"
C:\> dir "%ALLUSERSPROFILE%\Start
Menu\P rog rams\Sta rtup"
C:\> type C:\Windows\winstart.bat
C:\> type %windir%\wininit.ini
C:\> type %windir%\win.ini
```

#### View autoruns, hide Microsoft files:

Ref. [https://technet.microsoft.com/en­](https://technet.microsoft.com/en­) us/sysinternals/bb963902.aspx

```text
C:\> autorunsc -accepteula -m
C:\> type C:\Autoexec.bat"
```

#### Show all autorun files, export to csv and check with VirusTotal:

```text
C:\> autorunsc.exe -accepteula -a -c -i -e -f -l -m
-v
```

#### HKEY\_CLASSES\_ROOT:

```text
C:\> reg query HKCR\Comfile\Shell\Open\Command
C:\> reg query HKCR\Batfile\Shell\Open\Command
C:\> reg query HKCR\htafile\Shell\Open\Command
C:\> reg query HKCR\Exefile\Shell\Open\Command
C:\> reg query HKCR\Exefiles\Shell\Open\Command
C:\> reg query HKCR\piffile\shell\open\command
```

#### HKEY\_CURRENT\_USERS:

```text
C:\> reg query uHKCU\Control Panel\Desktop"
C:\> reg query
HKCU\Software\Microsoft\Windows\CurrentVersion\Polic
ies\Explorer\Run
C:\> reg query
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
C:\> reg query
HKCU\Software\Microsoft\Windows\CurrentVersion\Runon
ce
C:\> reg query
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOn
ceEx
C:\> reg query
HKCU\Software\Microsoft\Windows\CurrentVersion\RunSe
rvices
C:\> reg query
HKCU\Software\Microsoft\Windows\CurrentVersion\RunSe
rv ices Once
C:\> reg query
HKCU\Software\Microsoft\Windows\CurrentVersion\Windo
ws\Run
C:\> reg query
HKCU\Software\Microsoft\Windows\CurrentVersion\Windo
ws\Load
C:\> reg query
HKCU\Software\Microsoft\Windows\CurrentVersion\Windo
ws\Scripts
C:\> reg query «HKCU\Software\Microsoft\Windows
NT\CurrentVersion\Windows « /f run
C:\> reg query «HKCU\Software\Microsoft\Windows
NT\CurrentVersion\Windows « /f load
C:\> reg query
HKCU\Software\Microsoft\Windows\CurrentVersion\Polic
ies\Explorer\Run
C:\> reg query
HKCU\Software\Microsoft\Windows\CurrentVersion\Explo
rer\RecentDocs
C:\> reg query
HKCU\Software\Microsoft\Windows\CurrentVersion\Explo
rer\ComDlg32\LastVisitedMRU
C:\> reg query
HKCU\Software\Microsoft\Windows\CurrentVersion\Explo
rer\ComD1g32\0pen5aveMRU
C:\> reg query
HKCU\Software\Microsoft\Windows\CurrentVersion\Explo
rer\ComDlg32\LastVisitedPidlMRU
C:\> reg query
HKCU\Software\Microsoft\Windows\CurrentVersion\Explo
rer\ComD1g32\0pen5avePidlMRU /s
C:\> reg query
HKCU\Software\Microsoft\Windows\CurrentVersion\Explo
rer\RunMRU
C:\> reg query
«HKCU\Software\Microsoft\Windows\CurrentVersion\Expl
orer\Shell Folders"
C:\> reg query
uHKCU\Software\Microsoft\Windows\CurrentVersion\Expl
orer\User Shell Folders"
C:\> reg query
HKCU\Software\Microsoft\Windows\CurrentVersion\Apple
ts\RegEdit /v LastKey
C:\> reg query "HKCU\Software\Microsoft\Internet
Exp lo re r\ TypedURLs"
C:\> reg query
uHKCU\Software\Policies\Microsoft\Windows\Control
Panel \Desktop"
```

#### HKEY\_LOCAL\_MACHINE:

```text
C: \> reg query uHKLM\SOFTWARE\Mic rosoft\Act ive
Setup\Installed Components" /s
C:\> reg query
"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\expl
orer\User Shell Folders"
C:\> reg query
"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\expl
orer\Shell Folders"
C:\> reg query
HKLM\Software\Microsoft\Windows\CurrentVersion\explo
rer\ShellExecuteHooks
C:\> reg query
"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Expl
orer\Browser Helper Objects" /s
C:\> reg query
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Polic
ies\Explorer\Run
C:\> reg query
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
C:\> reg query
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Runon
ce
C:\> reg query
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOn
ceEx
C:\> reg query
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunSe
rvices
C:\> reg query
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunSe
rvicesOnce
C:\> reg query
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Winlo
gon\Userinit
C:\> reg query
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\shell
ServiceObjectDelayLoad
C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows
NT\CurrentVersion\Schedule\TaskCache\Tasks" /s
C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows
NT\CurrentVersion\Windows"
C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows
NT\CurrentVersion\Windows" /f Appinit_DLLs
C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows
NT\CurrentVersion\Winlogon" /f Shell
C: \> reg query "HKLM\SOFTWARE\Mic rosoft\Windows
NT\CurrentVersion\Winlogon" /f Userinit
C:\> reg query
HKLM\SOFTWARE\Policies\Microsoft\Windows\Systern\Scri
pts
C:\> reg query
HKLM\SOFTWARE\Classes\batfile\shell\open\cornrnand
C:\> reg query
HKLM\SOFTWARE\Classes\cornfile\shell\open\cornrnand
C:\> reg query
HKLM\SOFTWARE\Classes\exefile\shell\open\command
C:\> reg query
HKLM\SOFTWARE\Classes\htafile\Shell\Open\Command
C:\> reg query
HKLM\SOFTWARE\Classes\piffile\shell\open\command
C:\> reg query
"HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\Current
Version\Explorer\Browser Helper Objects" /s
C:\> reg query
"HKLM\SYSTEM\CurrentControlSet\Control\Session
Manager"
C:\> reg query
"HKLM\SYSTEM\CurrentControlSet\Control\Session
Manager\KnownDLLs"
C:\> reg query
"HKLM\SYSTEM\ControlSet001\Control\Session
Manager\KnownDLLs"
```

### LOGS

#### Copy event logs:

```text
C:\> wevtutil epl Security C:\<BACK UP
PATH>\mylogs.evtx
C:\> wevtutil epl System C:\<BACK UP
PATH>\mylogs.evtx
C:\> wevtutil epl Application C:\<BACK UP
PATH>\mylogs.evtx
```

#### Get list of logs remotely:

Ref. [https://technet.microsoft.com/en­](https://technet.microsoft.com/en­) us/sysinternals/psloglist.aspx

```text
C:\> psloglist \\<REMOTE COMPUTER> -accepteula -h 12
-x
```

#### Clear all logs and start a baseline log to monitor:

```text
PS C:\> wevtutil el I Foreach-Object {wevtutil cl
"$_"}
```

#### List log filenames and path location:

```text
C:\> wmic nteventlog get path,filename,writeable
```

#### Take pre breach log export:

```text
PS C:\> wevtutil el I ForEach-Object{Get-Eventlog -
Log "$_" I Export-Csv -Path (:\<BASELINE LOG>,csv -
Append}
```

#### Take post breach log export:

```text
PS C:\> wevtutil el I ForEach-Object{Get-EventLog -
Log"$_" I Export-Csv -Path C:\<POST BASELINE
LOG>,CSV -Append}
```

#### Compare two files baseline and post breach logs:

```text
PS C:\> Compare-Object -ReferenceObject $(Get­
Content "C:\<PATH TO FILE>\<ORIGINAL BASELINE
LOGS>.txt") -DifferenceObject $(Get-Content
"C:\<PATH TO FILE>\<POST BASELINE LOGS>.txt") >>
<DIFFERENCES LOG>.txt
```

#### This deletes all logs:

```text
PS C:\> wevtutil el I Foreach-Object {wevtutil cl
"$_"}
```

### FILES, DRIVES AND SHARES INFORMATION

```text
C:\> net use \\<TARGET IP ADDRESS>
C:\> net share
C:\> net session
C:\> wmic volume list brief
C:\> wmic logicaldisk get
description,filesystem,name,size
C:\> wmic share get name,path
```

#### Find multiple file types or a file:

```text
C:\> dir /A /5 /T:A *,exe *,dll *,bat *·PS1 *,zip
C:\> dir /A /5 /T:A <BAD FILE NAME>,exe
```

#### Find executable \(.exe\) files newer than Jan 1, 2017:

```text
C:\> forfiles /p C:\ /M *,exe /5 /0 +1/1/2017 /C
"cmd /c echo @fdate @ftime @path"
```

#### Find multiple files types using loop:

```text
C:\> for %G in (.exe, .dll, .bat, .ps) do forfiles -
p "C:" -m *%G -s -d +1/1/2017 -c "cmd /c echo @fdate
@ftime @path"
```

#### Search for files newer than date:

```text
C:\> forfiles /PC:\ /5 /0 +1/01/2017 /C "cmd /c
echo @path @fdate"
```

#### Find large files: \(example &lt;20 MB\)

```text
C:\> forfiles /5 /M * /C "cmd /c if @fsize GEO
2097152 echo @path @fsize"
```

#### Find files with Alternate Data Streams:

Ref. [https://technet.microsoft.com/en­](https://technet.microsoft.com/en­) us/sysinternals/streams.aspx

```text
C:\> streams -s <FILE OR DIRECTORY>
```

#### Find files with bad signature into csv:

Ref. [https://technet.microsoft.com/en­](https://technet.microsoft.com/en­) us/sysinternals/bb897441.aspx

```text
C:\> sigcheck -c -h -s -u -nobanner <FILE OR
DIRECTORY> > <OUTPUT FILENAME>,csv
```

#### Find and show only unsigned files with bad signature in C:

```text
C:\> sigcheck -e -u -vr -s C:\
```

#### List loaded unsigned Dlls:

Ref. [https://technet.microsoft.com/en­](https://technet.microsoft.com/en­) us/sysinternals/bb896656.aspx

```text
C:\> listdlls.exe -u
C:\> listdlls.exe -u <PROCESS NAME OR PID>
```

#### Run Malware scan \(Windows Defender\) offline:

Ref. [http://windows.microsoft.com/en­](http://windows.microsoft.com/en­) us/windows/what-is-windows-defender-offline

```text
C:\> MpCmdRun.exe -SignatureUpdate
C:\> MpCmdRun.exe -Scan
```

## LIVE TRIAGE - LINUX

### SYSTEM INFORMATION

```text
# uname -a
# up time
# t imedatec t
# mount
```

### USER INFORMATION

#### View logged in users:

```text
# w
```

#### Show if a user has ever logged in remotely:

```text
# lastl og
# last
```

#### View failed logins:

```text
# fail o
g -a
```

#### View local user accounts:

```text
# cat /etc/passwd
# cat /etc/shadow
```

#### View local groups:

```text
# cat/etc/group
```

#### View sudo access:

```text
# cat /etc/sudoers
```

#### View accounts with UID 0:

```text
# awk -F: '($3 == "0") {p rint}' /etc/passw
# egrep ':0+' /etc/passw
```

#### View root authorized SSH key authentications:

```text
# cat /root/.ssh/authorized_keys
```

#### List of files opened by user:

```text
# lsof -u <USER NAME>
```

#### View the root user bash history:

```text
# cat /root/,bash_history
```

### NETWORK INFORMATION

#### View network interfaces:

```text
# ifconfig
```

#### View network connections:

```text
# netstat -antup
# netstat -plantux
```

#### View listening ports:

```text
# netstat -nap
```

#### View routes:

```text
# route
```

#### View arp table:

```text
# arp -a
```

#### List of processes listening on ports:

```text
# lsof -i
```

### SERVICE INFORMATION

#### View processes:

```text
# ps -aux
```

#### List of load modules:

```text
# lsmod
```

#### List of open files:

```text
# lsof
```

#### List of open files, using the network:

```text
# lsof -nPi I cut -f 1 -d " "I uniq I tail -n +2
```

#### List of open files on specific process:

```text
# lsof -c <SERVICE NAME>
```

#### Get all open files of a specific process ID:

```text
# lsof -p <PID>
```

#### List of unlinked processes running:

```text
# lsof +Ll
```

#### Get path of suspicious process PID:

```text
#ls -al /proc/<PID>/exe
```

#### Save file for further malware binary analysis:

```text
# cp /proc/<PID>/exe >/<SUSPICIOUS FILE NAME TO
SAVE>,elf
```

#### Monitor logs in real-time:

```text
# less +F /var/log/messages
```

#### List services:

```text
# chkconfig --list
```

### POLICY, PATCH AND SETTINGS INFORMATION

#### View pam.d files:

```text
# cat /etc/pam.d/common*
```

### AUTORUN AND AUTOLOAD INFORMATION:

#### List cron jobs:

```text
# crontab -l
```

#### List cron jobs by root and other UID 0 accounts:

```text
# crontab -u root -l
```

#### Review for unusual cron jobs:

```text
# cat /etc/crontab
# ls /etc/cron,*
```

### LOGS

#### View root user command history:

```text
# cat /root/,*history
```

#### View last logins:

```text
# last
```

### FILES, DRIVES AND SHARES INFORMATION

#### View disk space:

```text
# df -ah
```

#### View directory listing for /etc/init.d:

```text
#ls -la /etc/init.d
```

#### Get more info for a file:

```text
# stat -x <FILE NAME>
```

#### Identify file type:

```text
# file <FILE NAME>
```

#### Look for immutable files:

```text
# lsatt r -R / I g rep \-i-"
```

#### View directory listing for /root:

```text
#ls -la /root
```

#### Look for files recently modified in current directory:

```text
# ls -alt I head
```

#### Look for world writable files:

```text
#find/ -xdev -type d\( -perm -0002 -a ! -perm -
1000 \) -print
```

#### Look for recent created files, in this case newer than Jan 02, 2017:

```text
#find/ -n ewermt 2017-01-02q
```

#### List all files and attributes:

```text
#find/ -printf
%m;%Ax;%AT;%Tx;%TT;%Cx;%CT;%U;%G;%s;%p\n"
```

#### Look at files in directory by most recent timestamp:\(Could be tampered\)

```text
#ls -alt /<DIRECTORY>! head
```

#### Get full file information:

```text
# stat /<FILE PATH>/<SUSPICIOUS FILE NAME>
```

#### Review file type:

```text
# file /<FILE PATH>/<SUSPICIOUS FILE NAME>
```

#### Check for rootkits or signs of compromise:

#### Run unix-privsec-check tool:

```text
# wget
https://raw.githubusercontent.com/pentestmonkey/unix
-privesc-check/l_x/unix-privesc-check
# ./unix-privesc-check > output.txt
```

#### Run chkrootkit:

```text
# apt-get install chkrootkit
# chkrootkit
```

#### Run rkhunter:

```text
# apt-get install rkhunter
# rkhunter --update
# rkhunter -check
```

#### Run tiger:

```text
# apt-get install tiger
# tiger
#less /var/log/tiger/security.report,*
```

#### Run lynis:

```text
# apt-get install lynis
# lynis audit system
# more /var/logs/lynis. log
```

#### Run Linux Malware Detect \(LMD\):

```text
# wget http://www.rfxn.com/downloads/maldetect­
current.tar.gz
# tar xfz maldetect-current.tar.gz
# cd maldetect-*
# ./install.sh
```

#### Get LMD updates:

```text
# maldet -u
```

#### Run LMD scan on directory:

```text
# maldet -a /<DIRECTORY>
```

## MALWARE ANALYSIS

### STATIC ANALYSIS BASICS

#### Mount live Sysinternats toots drive:

```text
\\live.sysinternals.com\tools
```

#### Signature check of dlt, exe files:

Ref. [http://technet.microsoft.com/en­](http://technet.microsoft.com/en­) us/sysinternals/bb897441.aspx

```text
C:\> sigcheck.exe -u -e (:\<DIRECTORY>
```

#### Send to VirusTotat:

```text
C:\> sigcheck.exe -vt <SUSPICIOUS FILE NAME>
```

#### Windows PE Analysis:

#### View Hex and ASCI of PE{exe or any file\), with optional -n first 500 bytes:

```text
# hexdump -C -n 500 <SUSPICIOUS FILE NAME>
# od -x somefile.exe
# xxd somefile.exe
```

#### In Windows using debug toot {works for .java files too\):

```text
C:\> debug <SUSPICIOUS FILE NAME>
> -d (just type d and get a page at a time of hex)
> -q (quit debugger)
```

#### Windows PE analysis: 

#### PE Fite Compile Date/Time pert script below \(Windows PE only script\).

Ref. [https://www.perl.org/get.html](https://www.perl.org/get.html) 

Ref. [http://www.perlmonks.org/bare/?node\_id=484287](http://www.perlmonks.org/bare/?node_id=484287)

```text
C:\> perl.exe <SCRIPT NAME>.pl <SUSPICIOUS FILE
NAME>
#! perl -slw
use strict;
$1 . " •
open EXE, '<:raw', $ARGV[0] or die "$ARGV[0] : $!";
my $dos = do{ local$/ = \65536; <EXE>};
die "$ARGV[0] is not a .exe or .dll (sig='${ \substr
$dos, 0, 2 } ')" unless substr( $dos, 0, 2 ) eq 'MZ';
my $coffoff = 8+ unpack 'x60 V', $dos;
read( EXE, $dos, $coffoff - 65536 + 4, 65536 ) or
die$! if $coffoff > 65536;
my $ts = unpack "x$coffoff V", $dos;
print "$ARGV [0] : ", defined $ts
? ( scalar( localtime $ts) "has unfathomable
timestamp value $ts" )
: 'has no timestamp';
_END_
```

#### View strings within PE and optional string length -n option: 

#### Using stings in Linux:

```text
# strings -n 10 <SUSPICIOUS FILE NAME>
```

Ref. [https://technet.microsoft.com/en­](https://technet.microsoft.com/en­) us/sysinternals/strings.aspx

#### Using strings in Windows:

```text
C:\> strings <SUSPICIOUS FILE NAME>
```

#### Find Malware in memory dump using Volatility and Windows7SPFix64 profile:

Ref, [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)

```text
# python vol.py -f <MEMORY DUMP FILE NAME>.raw -
profile=Win7SPFix64 malfind -D /<OUTPUT DUMP
DIRECTORY>
```

#### Find Malware with PID in memory dump using Volatility:

```text
# python vol.py -f <MEMORY DUMP FILE NAME>.raw -
profile=Win7SPFix64 malfind -p <PID #> -D /<OUTPUT
DUMP DIRECTORY>
```

#### Find suspicious processes using Volatility:

```text
# python vol.py -f <MEMORY DUMP FILE NAME>.raw -
profile=Win7SPFix64 pslist
# python vol.py -f <MEMORY DUMP FILE NAME>,raw -
profile=Win7SPFix64 pstree
```

#### Find suspicious dlls using Volatility:

```text
# python vol.py -f <MEMORY DUMP FILE NAME>.raw -
profile=Win7SPFix64 dlllist
# python vol.py -f <MEMORY DUMP FILE NAME>.raw -
profile=Win7SPFix64 dlldump -D /<OUTPUT DUMP
DIRECTORY>
```

#### Malware analysis parsing Tool:

Ref. [https://github.com/Defense-Cyber-Crime­](https://github.com/Defense-Cyber-Crime­) Center/DC3-MWCP

#### Install dc3-mwcp tool:

```text
# setup.py install
```

#### Use dc3-mwcp tool to parse suspicious file:

```text
# mwcp-tool.py -p <SUSPICIOUS FILE NAME>
```

## IDENTIFY MALWARE

### PROCESS EXPLORER

Ref. [https://youtu.be/80vfTA9LrBM](https://youtu.be/80vfTA9LrBM)

**Step 1:** Look at running processes by running Process Explorer \(GUI\) and identify potential indicators of compromise:

* Items with no icon
* Items with no description or company name
* Unsigned Microsoft images \(First add Verified Signer column under View tab-&gt;Select Columns, then go to Options tab and choose Verify Image Signatures\)
* Check all running process hashes in Virus Total \(Go to Options tab and select Check VirusTota l. com\)
* Suspicious files are in Windows directories or user profile
* Purple items that are packed or compressed • Items with open TCP/IP endpoints

**Step 2:** Signature File Check:

\( See Sigcheck\)

**Step 3:** Strings Check:

* Right click on suspicious process in Process Explorer and on pop up window choose Strings tab and review for suspicious URLs. Repeat for Image and Memory radio buttons.
* Look for strange URLs in strings

**Step 4:** DLL View:

* Pop open with Ct rl+D
* Look for suspicious DLLs or services
* Look for no description or no company name
* Look at VirusTotal Results column

**Step 5:** Stop and Remove Malware:

* Right click and select Suspend for any identified suspicious processes
* Right click and select Terminate Previous Suspended processes

**Step 6:** Clean up where malicious files Auto start on reboot.

* Launch Autoruns
* Under Options, Check the boxes Verify Code Signatures and Hide Microsoft entries
* Look for suspicious process file from earlier steps on the everything tab and uncheck. Safer to uncheck than delete, in case of error.
* Press FS, to refresh Autoruns, and confirm malicious file has not recreated the malicious entry into the previous unchecked auto start location.

**Step 7:** Process Monitor

Ref. [https://technet.microsoft.com/en­](https://technet.microsoft.com/en­) us/sysinternals/processmonitor.aspx

* If malicious activity is still persistent, run Process Monitor.
* Look for newly started process that start soon after terminated from previous steps.

**Step 8:** Repeat as needed to find all malicious files and process and/or combine with other tools and suites.

## FILE HASH ANALYSIS

### HASH QUERY

#### VirusTotal online API query:

Ref. [https://www.virustotal.com/en/documentation/public­](https://www.virustotal.com/en/documentation/public­) api/ \(Prerequisite: Need a VT API Key\)

#### Send a suspicious hash to VirtusTotal using cURL:

```text
# curl -v --request POST --url
https://www.virustotal.com/vtapi/v2/file/report' -d
apikey=<VT API KEY> -d 'resource=<SUSPICIOUS FILE
HASH>'
```

#### Send a suspicious file to VirusTotal using cURL:

```text
# curl -v -F 'file=/<PATH TO FILE>/<SUSPICIOUS FILE
NAME>' -F apikey=<VT API KEY>
https://www.virustotal.com/vtapi/v2/file/scan
```

#### Team Cymru API:

Ref. [https://hash.cymru.com](https://hash.cymru.com), [http://totalhash.com](http://totalhash.com)

**Team Cymru malware hash lookup using whois:** \(Note: Output is timestamp of last seen and detection rate\)

```text
# whois -h hash,cymru.com <SUSPICIOUS FILE HASH>
```

## HARD DRIVE AND MEMORY ACQUISITION

### WINDOWS

#### Create memory dump remotely:

Ref. [http://kromer.pl/malware-analysis/memory­](http://kromer.pl/malware-analysis/memory­) forensics-using-volatility-toolkit-to-extract­ malware-samples-from-memory-dump/   
Ref. [http://sourceforge.net/projects/mdd/](http://sourceforge.net/projects/mdd/)  
Ref. [https://technet.microsoft.com/en­](https://technet.microsoft.com/en­) us/sysinternals/psexec.aspx

```text
C: \> psexec. exe \\<HOST NAME OR IP ADDRESS> -u
<DOMAIN>\<PRIVILEGED ACCOUNT> -p <PASSWORD> -c
mdd_l,3.exe --o C:\memory.dmp
```

Ref. [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)

#### Extract exe/dll from memory dump:

```text
C:\> volatility dlldump -f memory.dmp -0 dumps/
C:\> volatility procmemdump -f memory.dmp -0 dumps/
```

Ref. [https://sourceforge.net/projects/dc3dd/files/dc3dd/7](https://sourceforge.net/projects/dc3dd/files/dc3dd/7) .2%20-%20Windows/

```text
C:\> dc3dd,exe if=\\,\c: of=d:\<ATTACHED OR TARGET
DRIVE>\<IMAGE NAME>,dd hash=md5 log=d:\<MOUNTED
LOCATION>\<LOG NAME>, log
```

### LINUX

#### Create memory dump:

```text
dd if=/dev/fmem of=/tmp/<MEMORY FILE NAME>.dd
```

#### Create memory dump using LiME:

Ref. [https://github.com/504ensicslabs/lime](https://github.com/504ensicslabs/lime)

```text
# wget
https://github.com/504ensicslabs/LiME/archive/master
.zip
unzip master.zip
# cd LiME-master/src
# make
# cp lime-*,ko /media/=/media/ExternalUSBDriveName/
# insmod lime-3.13.0-79-generic.ko
"path=/media/Exte rna lUSBDriveName/<MEMORY DUMP>, lime
format= raw"
```

#### Make copy of suspicious process using process ID:

```text
# cp /proc/<SUSPICIOUS PROCESS ID>/exe /<NEW SAVED
LOCATION>
```

#### Grab memory core dump of suspicious process:

```text
# gcore <PIO>
```

#### Strings on gcore file:

```text
# strings gcore.*
```

#### Create a hard drive/partition copy with tog and hash options:

```text
# dd if=<INPUT DEVICE> of=<IMAGE FILE NAME>
# dc3dd if=/dev/<TARGET DRIVE EXAMPLE SDA OR SDAl>
of=/dev/<MOUNTED LOCATION>\<FILE NAME>.img hash=md5
log=/<MOUNTED LOCATION>/<LOG NAME>.log
```

#### Create a remote hard drive/partition over SSH:

```text
# dd if=/dev/<INPUT DEVICE> I ssh <USER
NAME>@<DESTINATION IP ADDRESS> "dd of=<DESTINATION
PATH>"
```

#### Send hard drive image zipped over netcat:

#### Sending host:

```text
# bzip2 -c /dev/<INPUT DEVICE> I nc <DESTINATION IP
ADDRESS> <PICK A PORT>
```

#### Receiving host:

```text
# nc -p <PICK SAME PORT> -l lbzip2 -d I dd
of=/dev/sdb
```

#### Sending host:

```text
# dd if=/dev/<INPUT DEVICE> bs=16M I nc <PORT>
```

#### Receiving host with Pipe Viewer meter:

```text
# nc -p <SAME PORT> -l -vv I pv -r I dd
of=/dev/<INPUT DEVICE> bs=16M
```

