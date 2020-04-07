# تحلیل

## LIVE TRIAGE - ویندوز

### اطلاعات سیستم

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

منبع. [https://technet.microsoft.com/en­](https://technet.microsoft.com/en­) us/sysinternals/psinfo.aspx

```text
C:\> psinfo -accepteula -s -h -d
```

### اطلاعات کاربر

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

### اطلاعات شبکه

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

### اطلاعات سرویس ها

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

#### لیست تمام سرویس و ماژول ها:

```text
PS C:\> Get-Process !select modules!Foreach­
Object{$_.modules}
```

### اطلاعات POLICY, PATCH و تنظیمات

```text
C:\> set
C:\> gpresult /r
C:\> gpresult /z > <OUTPUT FILE NAME>.txt
C:\> gpresult /H report.html /F
C:\> wmic qfe
```

#### لیست نرم افزار های GPO نصب شده:

```text
C:\> reg query
uHKLM\Software\Microsoft\Windows\Current
Version\Group Policy\AppMgmt"
```

### اطلاعات AUTORUN و AUTOLOAD

```text
Startup information:
C:\> wmic startup list full
C:\> wmic ntdomain list brief
```

#### نمایش محتوای مسیر سرویس های راه انداز:

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

#### نمایش autorun ها و فایل های مخفی ماکروسافت:

منبع. [https://technet.microsoft.com/en­](https://technet.microsoft.com/en­) us/sysinternals/bb963902.aspx

```text
C:\> autorunsc -accepteula -m
C:\> type C:\Autoexec.bat"
```

#### نمایش تمامی فایل های autorun و ذخیره سازی آن ها در csv و بررسی آن توسط virustotal:

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

#### لیست گزارشات از راه دور:

منبع. [https://technet.microsoft.com/en­](https://technet.microsoft.com/en­) us/sysinternals/psloglist.aspx

```text
C:\> psloglist \\<REMOTE COMPUTER> -accepteula -h 12
-x
```

#### پاک نمودن تمامی گزارشات تا نقطه baseline:

```text
PS C:\> wevtutil el I Foreach-Object {wevtutil cl
"$_"}
```

#### لیست نام و مسیر فایل های گزارشات:

```text
C:\> wmic nteventlog get path,filename,writeable
```

#### عملیات pre breach log export:

```text
PS C:\> wevtutil el I ForEach-Object{Get-Eventlog -
Log "$_" I Export-Csv -Path (:\<BASELINE LOG>,csv -
Append}
```

#### عملیات post breach log export:

```text
PS C:\> wevtutil el I ForEach-Object{Get-EventLog -
Log"$_" I Export-Csv -Path C:\<POST BASELINE
LOG>,CSV -Append}
```

#### مقایسه baseline دو فایل و post breach logs:

```text
PS C:\> Compare-Object -ReferenceObject $(Get­
Content "C:\<PATH TO FILE>\<ORIGINAL BASELINE
LOGS>.txt") -DifferenceObject $(Get-Content
"C:\<PATH TO FILE>\<POST BASELINE LOGS>.txt") >>
<DIFFERENCES LOG>.txt
```

#### تمام گزارشات حذف شده:

```text
PS C:\> wevtutil el I Foreach-Object {wevtutil cl
"$_"}
```

### اطلاعات پرونده ها و درایور ها و محیط های اشتراکی

```text
C:\> net use \\<TARGET IP ADDRESS>
C:\> net share
C:\> net session
C:\> wmic volume list brief
C:\> wmic logicaldisk get
description,filesystem,name,size
C:\> wmic share get name,path
```

#### جست و جو فایل های پسوند های مختلف و یا یک فایل:

```text
C:\> dir /A /5 /T:A *,exe *,dll *,bat *·PS1 *,zip
C:\> dir /A /5 /T:A <BAD FILE NAME>,exe
```

#### جست و جو فایل های اجرایی \(.exe\) که از تاریخ Jan 1, 2017 به بعد هستند:

```text
C:\> forfiles /p C:\ /M *,exe /5 /0 +1/1/2017 /C
"cmd /c echo @fdate @ftime @path"
```

#### جست و جو فایل های با پسوند های مختلف به صورت همیشگی:

```text
C:\> for %G in (.exe, .dll, .bat, .ps) do forfiles -
p "C:" -m *%G -s -d +1/1/2017 -c "cmd /c echo @fdate
@ftime @path"
```

#### جست و جو فایل های بر اساس تاریخ:

```text
C:\> forfiles /PC:\ /5 /0 +1/01/2017 /C "cmd /c
echo @path @fdate"
```

#### جست و جو فایل ها بر اساس اندازه: \(برای مثال 20 مگابایت\)

```text
C:\> forfiles /5 /M * /C "cmd /c if @fsize GEO
2097152 echo @path @fsize"
```

#### جست و جو فایل های Alternate Data Streams:

منبع. [https://technet.microsoft.com/en­](https://technet.microsoft.com/en­) us/sysinternals/streams.aspx

```text
C:\> streams -s <FILE OR DIRECTORY>
```

#### جست و جو فایل های دارای امضا مشکوک و ذخیره آن در csv:

منبع. [https://technet.microsoft.com/en­](https://technet.microsoft.com/en­) us/sysinternals/bb897441.aspx

```text
C:\> sigcheck -c -h -s -u -nobanner <FILE OR
DIRECTORY> > <OUTPUT FILENAME>,csv
```

#### جست و جو و نمایش فایل های دارای امضا مشکوک در درایو C:\:

```text
C:\> sigcheck -e -u -vr -s C:\
```

#### لیست Dll های unsigned که load شده اند:

منبع. [https://technet.microsoft.com/en­](https://technet.microsoft.com/en­) us/sysinternals/bb896656.aspx

```text
C:\> listdlls.exe -u
C:\> listdlls.exe -u <PROCESS NAME OR PID>
```

#### اسکن Malware \(با استفاده از Windows Defender\) به صورت آفلاین:

منبع. [http://windows.microsoft.com/en­](http://windows.microsoft.com/en­) us/windows/what-is-windows-defender-offline

```text
C:\> MpCmdRun.exe -SignatureUpdate
C:\> MpCmdRun.exe -Scan
```

## LIVE TRIAGE - لینوکس

### اطلاعات سیستم

```text
# uname -a
# up time
# t imedatec t
# mount
```

### اطلاعات کاربر

#### لیست کاربرانی که ورود کرده اند:

```text
# w
```

#### لیست کاربرانی که از راه دور ورود کرده اند:

```text
# lastl og
# last
```

#### نمایش ورود های ناموفق:

```text
# fail o
g -a
```

#### نمایش کاربران محلی:

```text
# cat /etc/passwd
# cat /etc/shadow
```

#### نمایش گروه های محلی:

```text
# cat/etc/group
```

#### نمایش دسترسی sudo:

```text
# cat /etc/sudoers
```

#### نمایش کاربران با UID 0:

```text
# awk -F: '($3 == "0") {p rint}' /etc/passw
# egrep ':0+' /etc/passw
```

#### لیست کلید های احراز هویت معتبر ssh:

```text
# cat /root/.ssh/authorized_keys
```

#### لیست فایل هایی که توسط کاربر باز شده است:

```text
# lsof -u <USER NAME>
```

#### نمایش تاریخچه bash:

```text
# cat /root/,bash_history
```

### اطلاعات شبکه

#### نمایش interface های شبکه:

```text
# ifconfig
```

#### نمایش ارتباطات شبکه:

```text
# netstat -antup
# netstat -plantux
```

#### نمایش پورت های listening:

```text
# netstat -nap
```

#### نمایش route ها:

```text
# route
```

#### نمایش جدول arp:

```text
# arp -a
```

#### نمایش لیست فرآیند ها و پورت های مورد استفاده:

```text
# lsof -i
```

### اطلاعات سرویس ها

#### لیست فرآیند ها:

```text
# ps -aux
```

#### لیست ماژول های بارگذاری شده:

```text
# lsmod
```

#### لیست فایل های باز شده:

```text
# lsof
```

#### لیست فایل های باز شده تحت شبکه:

```text
# lsof -nPi I cut -f 1 -d " "I uniq I tail -n +2
```

#### لیست فایل های باز شده توسط یک فرآیند خاص:

```text
# lsof -c <SERVICE NAME>
```

#### لیست کلیه فایل های باز شده توسط یک فرآیند خاص:

```text
# lsof -p <PID>
```

#### لیست کلید فرآیند های unlinked در حال اجرا:

```text
# lsof +Ll
```

#### لیست فرآیند های یک PID:

```text
#ls -al /proc/<PID>/exe
```

#### ذخیره سازی تحلیل های فایل های اجرایی malware ها:

```text
# cp /proc/<PID>/exe >/<SUSPICIOUS FILE NAME TO
SAVE>,elf
```

#### نمایش گزارشات به صورت زنده:

```text
# less +F /var/log/messages
```

#### لیست سرویس ها:

```text
# chkconfig --list
```

### اطلاعات POLICY, PATCH و تنظیمات

#### نمایش فایل های درون مسیر pam.d:

```text
# cat /etc/pam.d/common*
```

### اطلاعات AUTORUN و AUTOLOAD:

#### لیست cron job ها:

```text
# crontab -l
```

#### لیست cron job ها که توسط کاربر root و UID صفر است:

```text
# crontab -u root -l
```

#### بررسی cron job ها غیر معمول:

```text
# cat /etc/crontab
# ls /etc/cron,*
```

### گزارشات

#### بررسی تاریخچه دستور های اجرا شده کاربر root:

```text
# cat /root/,*history
```

#### بررسی آخرین کاربر وارد شده به سیستم:

```text
# last
```

### اطلاعات فایل ها و درایور ها و محیط های اشتراکی

#### نمایش میزان استفاده از دیسک:

```text
# df -ah
```

#### نمایش فایل های مسیر /etc/init.d:

```text
#ls -la /etc/init.d
```

#### اطلاعات بیشتر درباره فایل:

```text
# stat -x <FILE NAME>
```

#### تشخیص نوع فایل:

```text
# file <FILE NAME>
```

#### نمایش فایل های immutable:

```text
# lsatt r -R / I g rep \-i-"
```

#### لیست فایل های مسیر /root:

```text
#ls -la /root
```

#### نمایش لیست آخرین فایل های ویرایش شده:

```text
# ls -alt I head
```

#### لیست فایل های قابل نوشتن:

```text
#find/ -xdev -type d\( -perm -0002 -a ! -perm -
1000 \) -print
```

#### لیست فایل هایی که به تازگی از تاریخ Jan 02, 2017 ایجاد شده اند:

```text
#find/ -n ewermt 2017-01-02q
```

#### لیست کلیه فایل ها و ویژگی های آن:

```text
#find/ -printf
%m;%Ax;%AT;%Tx;%TT;%Cx;%CT;%U;%G;%s;%p\n"
```

#### لیست فایل های مسیری خاص که timestamp جدید تری دارند:\(ممکن است دستکاری شود\)

```text
#ls -alt /<DIRECTORY>! head
```

#### نمایش جزییات فایل:

```text
# stat /<FILE PATH>/<SUSPICIOUS FILE NAME>
```

#### بررسی نوع فایل:

```text
# file /<FILE PATH>/<SUSPICIOUS FILE NAME>
```

#### بررسی sign فایل ها برای شناسایی rootkit ها:

#### Run unix-privsec-check tool:

```text
# wget
https://raw.githubusercontent.com/pentestmonkey/unix
-privesc-check/l_x/unix-privesc-check
# ./unix-privesc-check > output.txt
```

#### اجرا chkrootkit:

```text
# apt-get install chkrootkit
# chkrootkit
```

#### اجرا rkhunter:

```text
# apt-get install rkhunter
# rkhunter --update
# rkhunter -check
```

#### اجرا tiger:

```text
# apt-get install tiger
# tiger
#less /var/log/tiger/security.report,*
```

#### اجرا lynis:

```text
# apt-get install lynis
# lynis audit system
# more /var/logs/lynis. log
```

#### اجرا Linux Malware Detect \(LMD\):

```text
# wget http://www.rfxn.com/downloads/maldetect­
current.tar.gz
# tar xfz maldetect-current.tar.gz
# cd maldetect-*
# ./install.sh
```

#### دریافت LMD updates:

```text
# maldet -u
```

#### اجرا و اسکن LMD برروی مسیری خاص:

```text
# maldet -a /<DIRECTORY>
```

## بررسی و تحلیل MALWARE

### بررسی و تحلیل STATIC ANALYSIS

#### ایجاد Mount live Sysinternals tools drive:

```text
\\live.sysinternals.com\tools
```

#### بررسی Signature مربوط به فایل های dlt و exe :

منبع. [http://technet.microsoft.com/en­](http://technet.microsoft.com/en­) us/sysinternals/bb897441.aspx

```text
C:\> sigcheck.exe -u -e (:\<DIRECTORY>
```

#### ارسال به VirusTotat:

```text
C:\> sigcheck.exe -vt <SUSPICIOUS FILE NAME>
```

#### بررسی و تحلیل Windows PE:

#### نمایش Hex و ASCI فایل های PE{exe یا هر فایلی\), با سوییچ و 500 بایت اول -n:

```text
# hexdump -C -n 500 <SUSPICIOUS FILE NAME>
# od -x somefile.exe
# xxd somefile.exe
```

#### استفاده از ابزار debug در ویندوز {برای فایل های .java \):

```text
C:\> debug <SUSPICIOUS FILE NAME>
> -d (just type d and get a page at a time of hex)
> -q (quit debugger)
```

#### بررسی و تحلیل Windows PE: 

#### اسکریپت زمان و تاریخ کامپایل فایل های PE \(فقط برای ویندوز\).

منبع. [https://www.perl.org/get.html](https://www.perl.org/get.html) 

منبع. [http://www.perlmonks.org/bare/?node\_id=484287](http://www.perlmonks.org/bare/?node_id=484287)

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

#### نمایش رشته های داخل PE و طول رشته ها با سوییچ -n: 

#### استفاده از strings در لینوکس:

```text
# strings -n 10 <SUSPICIOUS FILE NAME>
```

منبع. [https://technet.microsoft.com/en­](https://technet.microsoft.com/en­) us/sysinternals/strings.aspx

#### استفاده از strings در ویندوز:

```text
C:\> strings <SUSPICIOUS FILE NAME>
```

#### شناسایی Malware در memory، dump شده با استفاده از Volatility و پروفایل Windows7SPFix64:

منبع, [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)

```text
# python vol.py -f <MEMORY DUMP FILE NAME>.raw -
profile=Win7SPFix64 malfind -D /<OUTPUT DUMP
DIRECTORY>
```

#### شناسایی Malware با PID در memory، dump شده با استفاده از Volatility:

```text
# python vol.py -f <MEMORY DUMP FILE NAME>.raw -
profile=Win7SPFix64 malfind -p <PID #> -D /<OUTPUT
DUMP DIRECTORY>
```

#### لیست فرآیند ها با استفاده از Volatility:

```text
# python vol.py -f <MEMORY DUMP FILE NAME>.raw -
profile=Win7SPFix64 pslist
# python vol.py -f <MEMORY DUMP FILE NAME>,raw -
profile=Win7SPFix64 pstree
```

#### لیست dll ها با استفاده از Volatility:

```text
# python vol.py -f <MEMORY DUMP FILE NAME>.raw -
profile=Win7SPFix64 dlllist
# python vol.py -f <MEMORY DUMP FILE NAME>.raw -
profile=Win7SPFix64 dlldump -D /<OUTPUT DUMP
DIRECTORY>
```

#### ابزار بررسی و شناسایی Malware:

منبع. [https://github.com/Defense-Cyber-Crime­](https://github.com/Defense-Cyber-Crime­) Center/DC3-MWCP

#### نصب ابزار dc3-mwcp:

```text
# setup.py install
```

#### استفاده از ابزار dc3-mwcp برای بررسی فایل های مشکوک:

```text
# mwcp-tool.py -p <SUSPICIOUS FILE NAME>
```

## شناسایی MALWARE

### ابزار PROCESS EXPLORER

منبع. [https://youtu.be/80vfTA9LrBM](https://youtu.be/80vfTA9LrBM)

**مرحله 1:** لیست فرآیند ها و بررسی موارد مشکوک :

* Items with no icon
* Items with no description or company name
* Unsigned Microsoft images \(First add Verified Signer column under View tab-&gt;Select Columns, then go to Options tab and choose Verify Image Signatures\)
* Check all running process hashes in Virus Total \(Go to Options tab and select Check VirusTota l. com\)
* Suspicious files are in Windows directories or user profile
* Purple items that are packed or compressed • Items with open TCP/IP endpoints

**مرحله 2:** بررسی Signature فایل ها :

\( نمایش Sigcheck\)

**مرحله 3:** بررسی Strings:

* Right click on suspicious process in Process Explorer and on pop up window choose Strings tab and review for suspicious URLs. Repeat for Image and Memory radio buttons.
* Look for strange URLs in strings

**مرحله 4:** نمایش DLL:

* Pop open with Ct rl+D
* Look for suspicious DLLs or services
* Look for no description or no company name
* Look at VirusTotal Results column

**مرحله 5:** توقف و حذف Malware:

* Right click and select Suspend for any identified suspicious processes
* Right click and select Terminate Previous Suspended processes

**مرحله 6:** حذف فایل های مشکوکی که در راه اندازی سیستم اجرا می شوند.

* Launch Autoruns
* Under Options, Check the boxes Verify Code Signatures and Hide Microsoft entries
* Look for suspicious process file from earlier steps on the everything tab and uncheck. Safer to uncheck than delete, in case of error.
* Press FS, to refresh Autoruns, and confirm malicious file has not recreated the malicious entry into the previous unchecked auto start location.

**مرحله 7:** نظارت بر فرآیند ها

منبع. [https://technet.microsoft.com/en­](https://technet.microsoft.com/en­) us/sysinternals/processmonitor.aspx

* If malicious activity is still persistent, run Process Monitor.
* Look for newly started process that start soon after terminated from previous steps.

**مرحله 8:** تکرار مراحل بالا برای شناسایی فایل های مشکوک.

## بررسی هش فایل ها

### با استفاده از HASH QUERY

#### استفاده از Api های VirusTotal:

Ref. [https://www.virustotal.com/en/documentation/public­](https://www.virustotal.com/en/documentation/public­) api/ \(Prerequisite: Need a VT API Key\)

#### ارسال هش فایل های مشکوک به virustotal با استفاده از ابزار curl:

```text
# curl -v --request POST --url
https://www.virustotal.com/vtapi/v2/file/report' -d
apikey=<VT API KEY> -d 'resource=<SUSPICIOUS FILE
HASH>'
```

#### ارسال فایل های مشکوک به virustotal با استفاده از ابزار curl:

```text
# curl -v -F 'file=/<PATH TO FILE>/<SUSPICIOUS FILE
NAME>' -F apikey=<VT API KEY>
https://www.virustotal.com/vtapi/v2/file/scan
```

#### استفاده از API های Team Cymru:

منبع. [https://hash.cymru.com](https://hash.cymru.com), [http://totalhash.com](http://totalhash.com)

**نمایش هش های malware ها با استفاده از Team Cymru و ابزار whois:** \(Note: Output is timestamp of last seen and detection rate\)

```text
# whois -h hash,cymru.com <SUSPICIOUS FILE HASH>
```

## HARD DRIVE و MEMORY ACQUISITION

### ویندوز

#### ایحاد memory، dump شده از راه دور:

منبع. [http://kromer.pl/malware-analysis/memory­](http://kromer.pl/malware-analysis/memory­) forensics-using-volatility-toolkit-to-extract­ malware-samples-from-memory-dump/   
منبع. [http://sourceforge.net/projects/mdd/](http://sourceforge.net/projects/mdd/)  
منبع. [https://technet.microsoft.com/en­](https://technet.microsoft.com/en­) us/sysinternals/psexec.aspx

```text
C: \> psexec. exe \\<HOST NAME OR IP ADDRESS> -u
<DOMAIN>\<PRIVILEGED ACCOUNT> -p <PASSWORD> -c
mdd_l,3.exe --o C:\memory.dmp
```

منبع. [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)

#### استخراج فایل های exe و dll از memory، dump شده:

```text
C:\> volatility dlldump -f memory.dmp -0 dumps/
C:\> volatility procmemdump -f memory.dmp -0 dumps/
```

منبع. [https://sourceforge.net/projects/dc3dd/files/dc3dd/7](https://sourceforge.net/projects/dc3dd/files/dc3dd/7) .2%20-%20Windows/

```text
C:\> dc3dd,exe if=\\,\c: of=d:\<ATTACHED OR TARGET
DRIVE>\<IMAGE NAME>,dd hash=md5 log=d:\<MOUNTED
LOCATION>\<LOG NAME>, log
```

### لینوکس

#### ایجاد memory dump:

```text
dd if=/dev/fmem of=/tmp/<MEMORY FILE NAME>.dd
```

#### ایجاد memory dump با استفاده از ابزار LiME:

منبع. [https://github.com/504ensicslabs/lime](https://github.com/504ensicslabs/lime)

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

#### ایجاد کپی از فرآیند مشکوک با استفاده از  process ID:

```text
# cp /proc/<SUSPICIOUS PROCESS ID>/exe /<NEW SAVED
LOCATION>
```

#### اطلاعات بیشتر درباره فرآیند مشکوک در memory، dump شده:

```text
# gcore <PIO>
```

#### استفاده از Strings بر روی فایل:

```text
# strings gcore.*
```

#### ایجاد یک کپی از hard drive و partition شامل tog و hash ها:

```text
# dd if=<INPUT DEVICE> of=<IMAGE FILE NAME>
# dc3dd if=/dev/<TARGET DRIVE EXAMPLE SDA OR SDAl>
of=/dev/<MOUNTED LOCATION>\<FILE NAME>.img hash=md5
log=/<MOUNTED LOCATION>/<LOG NAME>.log
```

#### ایجاد hard drive و partition بر روی SSH:

```text
# dd if=/dev/<INPUT DEVICE> I ssh <USER
NAME>@<DESTINATION IP ADDRESS> "dd of=<DESTINATION
PATH>"
```

#### ارسال hard drive image، zip شده بر روی netcat:

#### ارسال به میزبان:

```text
# bzip2 -c /dev/<INPUT DEVICE> I nc <DESTINATION IP
ADDRESS> <PICK A PORT>
```

#### دریافت توسط میزبان:

```text
# nc -p <PICK SAME PORT> -l lbzip2 -d I dd
of=/dev/sdb
```

#### ارسال به میزبان host:

```text
# dd if=/dev/<INPUT DEVICE> bs=16M I nc <PORT>
```

#### دریافت توسط میزبان با استفاده از Pipe Viewer meter:

```text
# nc -p <SAME PORT> -l -vv I pv -r I dd
of=/dev/<INPUT DEVICE> bs=16M
```

#### وبسایت های رمزنگاری

```text
https://www.dcode.fr/
https://gchq.github.io/CyberChef/
https://crackstation.net/
```

### بررسی دادها های مخفی در فایل با StegCracker

```text
https://github.com/Paradoxis/StegCracker
For example: stegcracker image.jpg
```

### بررسی دادها های مخفی در عکس با StegSolve

```text
wget http://www.caesum.com/handbook/Stegsolve.jar -O stegsolve.jar
chmod +x stegsolve.jar
java -jar stegsolve.jar

```
