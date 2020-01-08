# روش های و نکات

## برگه رمز های سیستم عامل

### ویندوز

#### استفاده از Pipe برای خروجی ها و استفاده در clipboard:

```text
C:\> some_command.exe | clip
```

#### دریافت اطلاعات از clipboard در ذخیره آن در فایل: \(نیازمند PowerShell 5\)

```text
PS C:\> Get-Clipboard> clip.txt
```

#### اضافه نمودن timestamps در فایل گزارشات:

```text
C:\> echo %DATE% %TIME%>> <TXT LOG>,txt
```

#### اضافه/تغییر کلید های رجیستری از راه دور:

```text
C:\> reg add \\<REMOTE COMPUTER
NAME>\HKLM\Software\<REG KEY INFO>
```

#### دریافت مقدار های رجیستری به صورت از راه دور:

```text
C:\> reg query \\<REMOTE COMPUTER
NAME>\HKLM\Software\<REG KEY INFO>
```

#### بررسی و تست مسیر های رجیستری:

```text
PS C:\> Test-Path "HKCU:\Software\Microsoft\<HIVE>"
```

#### کپی از فایل ها از راه دور:

```text
C:\> robocopy C:\<SOURCE SHARED FOLDER>
\\<DESTINATION COMPUTER>\<DESTINATION FOLDER> /E
```

#### بررسی پسوند های مختلف فایل ها در مسیر:

```text
PS C:\> Test-Path C:\Scripts\Archive\* -include
*·PSl, *,VbS
```

#### نمایش محتوای فایل ها:

```text
C:\> type <FILE NAME>
```

#### ادغام محتوای چندین فایل:

```text
C:\> type <FILE NAME 1> <FILE NAME 2> <FILE NAME 3>
> <NEW FILE NAME>
```

#### Desktop ها, اجازه به ایجاد چند صفحه نمایش به Desktop:

منبع. [https://technet.microsoft.com/enus/](https://technet.microsoft.com/enus/) sysinternals/cc817881

#### اجرا به صورت live:

```text
C:\> "%ProgramFiles%\Internet Explorer\iexplore.exe
"https://live.sysinternals.com/desktops.exe
```

#### mounting از راه دور و اجازه به نوشتن و خواندن, Read and Read/Write:

```text
C:\> net share MyShare_R=c:\<READ ONLY FOLDER>
/GRANT:EVERYONE,READ
C:\> net share MyShare_RW=c:\<READ/WRITE FOLDER>
/GRANT:EVERYONE,FULL
```

#### اجرای task از راه دور با استفاده از PSEXEC:

منبع. [https://technet.microsoft.com/enus/](https://technet.microsoft.com/enus/) sysinternals/psexec.aspx

```text
C:\> psexec.exe \\<TARGET IP ADDRESS> -u <USER NAME>
-p <PASSWORD> /C C:\<PROGRAM>.exe
C:\> psexec @(:\<TARGET FILE LIST>.txt -u <ADMIN
LEVEL USER NAME> -p <PASSWORD> C:\<PROGRAM>,exe >>
C:\<OUTPUT FILE NAME>,txt
C:\> psexec.exe @(:\<TARGET FILE LIST>.csv -u
<DOMAIN NAME>\<USER NAME> -p <PASSWORD> /c
C:\<PROGRAM>.exe
```

#### اجرای task و ارسال نتیجه آن به محیط اشتراکی:

```text
C:\> wmic /node:ComputerName process call create
ucmd,exe /c netstat -an > \\<REMOTE SHARE>\<OUTPUT
FILE NAME>,txt"
```

#### مقایسه تغییرات دو فایل:

```text
PS C:\> Compare-Object (Get-Content ,<LOG FILE NAME
l>, log) -DifferenceObject (Get-Content .<LOG FILE
NAME 2>,log)
```

#### اجرای task از راه دور با استفاده از PowerShell:

```text
PS C:\> Invoke-Command -<COMPUTER NAME> {<PS
COMMAND>}
```

#### راهنمای دستورات PowerShell:

```text
PS C:\> Get-Help <PS COMMAND> -full
```

### لینوکس

#### بررسی و تحلیل ترافیک از راه دور بر روی ssh:

```text
# ssh root@<REMOTE IP ADDRESS OF HOST TO SNIFF>
tcpdump -i any -U -s 0 -w - 'not port 22'
```

#### ایجاد دستی یادداشت یا داده به syslog:

```text
# logger usomething important to note in Log"
# dmesg I grep <COMMENT>
```

#### ایجاد mounting به صورت فقط خواندنی:

```text
# mount -o ro /dev/<YOUR FOLDER OR DRIVE> /mnt
```

#### ایجاد Mounting از راه دور بر روی SSH:

```text
# apt-get install sshfs
# adduser <USER NAME> fuse
Log out and log back in.
mkdir 󰁝/<WHERE TO MOUNT LOCALLY>
# sshfs <REMOTE USER NAME>@<REMOTE HOST>:/<REMOTE
PATH> 󰁝/<WHERE TO MOUNT LOCALLY>
```

#### ایجاد محیط اشتراکی SMB در لینوکس:

```text
# useradd -m <NEW USER>
# passwd <NEW USER>
# smbpasswd -a <NEW USER>
# echo [Share] >> /etc/samba/smb.conf
# echo /<PATH OF FOLDER TO SHARE> >>
/etc/samba/smb.conf
# echo available = yes >> /etc/samba/smb.conf
# echo valid users = <NEW USER> >>
/etc/samba/smb.conf
# echo read only = no >> /etc/samba/smb.conf
# echo browsable = yes >> /etc/samba/smb.conf
# echo public = yes >> /etc/samba/smb.conf
# echo writable = yes >> /etc/samba/smb.conf
# service smbd restart
```

#### نمایش محیط اشتراکی سیستم از راه دور:

```text
> smb:\\<IP ADDRESS OF LINUX SMB SHARE>
```

#### کپی فایل از راه دور به سیستم دیگر:

```text
> scp <FILE NAME> <USER NAME>@<DESTINATION IP
ADDRESS>:/<REMOTE FOLDER>
```

#### ایجاد Mount و محیط اشتراکی SMB در سیستم دیگر از راه دور:

```text
# mount -t smbfs -o username=<USER NAME> //<SERVER
NAME OR IP ADDRESS>/<SHARE NAME> /mnt/<MOUNT POINT>/
```

#### نظارت بر وبسایت و فایل ها:

```text
#while :; do curl -sSr http://<URL> I head -n 1;
sleep 60; done
```

روش دوم\([reference](https://unix.stackexchange.com/questions/84814/health-check-of-web-page-using-curl)\):

```text
for i in `curl -s -L cnn.com |egrep --only-matching "http(s?):\/\/[^ \"\(\)\<\>]*" | uniq` ;
do curl -s -I $i 2>/dev/null |head -n 1 | cut -d$' ' -f2; sleep 60; done
```

## رمزگشایی

### ارتباط HEX

#### تبدیل از حالت hex به decimal در ویندوز:

```text
C:\> set /a 0xff
255
PS C:\> 0xff
255
```

#### دیگر عملیات های ریاضی در ویندوز:

```text
C:\> set /a 1+2
3
C:\> set /a 3*(9/4)
6
C:\> set /a (2*5)/2
5
C:\> set /a "32>>3"
4
```

#### رمزگشایی متن Base64 درون یک فایل:

```text
C:\> certutil -decode <BASE64
<DECODED FILE NAME>
```

#### رمزگشایی XOR جست و جو برای http:

منبع, [https://blog.didierstevens.com/programs/xorsearch/](https://blog.didierstevens.com/programs/xorsearch/)

```text
C:\> xorsearch,exe -i -s <INPUT FILE NAME> http
```

#### تبدیل hex به decimal در لینوکس:

```text
# echo u0xff"lwcalc -d
= 255
```

#### تبدیل decimal به hex در لینوکس:

```text
$ echo u25s"1wcalc -h
= 0xff
```

#### رمزگشایی رشته های HTML:

```text
PS C:\> Add-Type -AssemblyName System.Web
PS C:\>
[System.Uri] ::UnescapeDataString("HTTP%3a%2f%2fHello
%20World.com")
HTTP://Hello World.com
```

## ابزار SNORT

### قوانین SNORT

#### قوانین Snort برای شناسایی ترافیک Meterpreter:

منبع. [https://blog.didierstevens.com/2015/06/16/metasploit](https://blog.didierstevens.com/2015/06/16/metasploit) -meterpreter-reverse-https-snort-rule/

```text
alert tcp $HOME_NET any-> $EXTERNAL_NET $HTTP_PORTS
(msg:"Metasploit User Agent String";
flow:to_server,established; content:"User-Agentl3al
Mozilla/4,0 (compatible\; MSIE 6.0\; Windows NT
5.1) l0d 0al"; http_header; classtype:trojanactivity;
reference:url,blog,didierstevens.com/2015/03/16/quic
kpost-metasploit-user-agent-strings/; sid:1618000;
rev:1;)
alert tcp $HOME_NET any-> $EXTERNAL_NET $HTTP_PORTS
( msg: "Metasploit User Agent St ring";
flow:to_server,established; content:"User-Agentl3al
Mozilla/4.0 (compatible\; MSIE 6,1\; Windows NT) l0d
0al"; http_header; classtype:trojan-activity;
reference:url,blog,didierstevens.com/2015/03/16/quic
kpost-metasploit-user-agent-strings/; sid:1618001;
rev: 1;)
alert tcp $HOME_NET any-> $EXTERNAL_NET $HTTP_PORTS
(msg: "Metasploit User Agent String";
flow:to_server,established; content:"User-Agentl3al
Mozilla/4,0 (compatible\; MSIE 7,0\; Windows NT
6.0) l0d 0al"; http_header; classtype:trojanactivity;
reference:url,blog.didierstevens.com/2015/03/16/quic
kpost-metasploit-user-agent-strings/; sid:1618002;
rev: 1;)
alert tcp $HOME_NET any-> $EXTERNAL_NET $HTTP_PORTS
(msg:"Metasploit User Agent String";
flow:to_server,established; content:"User-Agentl3al
Mozilla/4,0 (compatible\; MSIE 7,0\; Windows NT
6,0\; Trident/4,0\; SIMBAR={7DB0F6DE-8DE7-4841-9084-
28FA914B0F2E}\; SLCCl\; ,Nl0d 0al"; http_header;
classtype:trojan-activity;
reference:url,blog.didierstevens.com/2015/03/16/quic
kpost-metasploit-user-agent-strings/; sid:1618003;
rev: 1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS
(msg:"Metasploit User Agent String";
flow:to_server,established; content:"User-Agentl3al
Mozilla/4.0 (compatible\; Metasploit RSPEC)l0d 0al";
http_header; classtype:trojan-activity;
reference:url,blog,didierstevens.com/2015/03/16/quic
kpost-metasploit-user-agent-strings/; sid:1618004;
rev: 1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS
(msg:"Metasploit User Agent String";
flow:to_server,established; content:"User-Agentl3al
Mozilla/5,0 (Windows\; U\; Windows NT 5,1\; en-US)
AppleWebKit/525,13 (KHTML, like Gecko)
Chrome/4.0.221.6 Safari/525,13l0d 0al"; http_header;
classtype:trojan-activity;
reference:url,blog.didierstevens.com/2015/03/16/quic
kpost-metasploit-user-agent-strings/; sid:1618005;
rev: 1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS
( msg: "Metasploit User Agent St ring";
flow:to_server,established; content:"User-Agentl3al
Mozilla/5.0 (compatible\; Googlebot/2.1\;
+http://www.google.com/bot.html) l0d 0al";
http_header; classtype:trojan-activity;
reference:url,blog,didierstevens.com/2015/03/16/quic
kpost-metasploit-user-agent-strings/; sid:1618006;
rev: 1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS
(msg: "Metasploit User Agent St ring";
flow:to_server,established; content:"User-Agentl3al
Mozilla/5,0 (compatible\; MSIE 10,0\; Windows NT
6,1\; Trident/6,0) l0d 0al"; http_header;
classtype:trojan-activity;
reference:url,blog.didierstevens.com/2015/03/16/quic
kpost-metasploit-user-agent-strings/; sid:1618007;
rev: 1;)
```

#### قوانین Snort برای شناسایی ترافیک PSEXEC:

منبع. [https://github.com/John-Lin/dockersnort/](https://github.com/John-Lin/dockersnort/) blob/master/snortrules-snapshot- 2972/rules/policy-other.rules

```text
alert tcp $HOME_NET any -> $HOME_NET [139,445]
(msg:"POLICY-OTHER use of psexec remote
admin ist rat ion tool"; flow: to_server, established;
content:" IFFISMB1A2I"; depth:5; offset:4;
content:"ISC
.00 I p I 00 Is I 00 I e I 00 Ix I 00 I e I 00 I c I 00 I s I 00 Iv I 00 I c" ;
nocase; metadata:service netbios-ssn;
reference:url,technet.microsoft.com/enus/
sysinternals/bb897553.aspx; classtype:policyviolation;
sid:24008; rev:1;)
alert tcp $HOME_NET any -> $HOME_NET [139,445]
(msg:"POLICY-OTHER use of psexec remote
administration tool SMBv2";
flow:to_server,established; content:"IFEISMB";
depth:8; nocase; content:"105 001"; within:2;
distance:8;
content:"Pl001Sl00IEl00IXl00IEl00ISl00IVl00ICl00I";
fast_pattern:only; metadata:service netbios-ssn;
reference:url,technet.microsoft,com/enus/
sysinternals/bb897553.aspx[l]; classtype:policyviolation;
sid:30281; rev:1;)
```

## حملات DOS و DDOS

### امضای حملات DOS و DDOS

#### روش های حملات DoS و DDoS:

منبع. [https://www.trustwave.com/Resources/SpiderLabsBlog/](https://www.trustwave.com/Resources/SpiderLabsBlog/) PCAP-Files-Are-Great-Arn-t-They--/ 

** بر اساس حجم:** به عنوان مثال مصرف پهنای باند از 1 گیگابایت به 10 گیگابایت برسد 

منبع. [http://freecode.com/projects/iftop](http://freecode.com/projects/iftop)

```text
# iftop -n
```

**بر اساس پروتکل های مختلف:** استفاده از پروتکل های مختلف 

برای مثال, SYN Flood, ICMP Flood, UDP flood

```text
# tshark -r <FILE NAME>,pcap -q -z io,phs
# tshark -c 1000 -q -z io,phs
# tcpdump -tn r $FILE I awk -F '. ' '{print
$1","$2"."$3","$4}' I sort I uniq -c I sort -n I
tail
# tcpdump -qnn "tcp[tcpflags] & (tcp-syn) != 0"
# netstat -s
```

برای مثال فقط یک پروتکل را هدف قرار میگیرد

```text
# tcpdump -nn not arp and not icmp and not udp
# tcpdump -nn tcp
```

**منبع:** وضیعت اتصال 

به عنوان مثال ، فایروال می تواند 10،000 اتصال همزمان را کنترل کند ، و مهاجم 20،000 ارسال می کند

```text
# netstat -n I awk '{print $6}' I sort I uniq -c
sort -nr I head
```

**برنامه ها:** حملات لایه 7

برای مثال, HTTP GET flood, برای فایل عکس های حجیم.

```text
# tshark -c 10000 -T fields -e http.host
uniq -c I sort -r I head -n 10
so rt I
# tshark -r capture6 -T fields -e
http.request.full\_uri I sort I uniq -c I sort -r I
head -n 10c
# tcpdump -n 'tcp[32:4] = 0x47455420' I cut -f 7- -d
":"
```

#### برای مثال , درخواست برای فایل های پرونده های, GIF, ZIP, JPEG, PDF, PNG غیر معمول نباشد.

```text
# tshark -Y "http contains "ff:d8"" | "http
contains "GIF89a"" || "http contains
" \x50\x4B\x03\x04"" || "http contains\xff\xd8" " ||
"http contains "%PDF"" || "http contains
"\x89\x50\x4E\x47""
```

#### به عنوان مثال به مقدار 'user-agent' در درخواست وب توجه و بررسی شود.

```text
# tcpdump -c 1000 -Ann I grep -Ei 'user-agent'
sort I uniq -c I sort -nr I head -10
```

#### به عنوان مثال, Header منابع درخواستی بررسی شود.

```text
# tcpdump -i en0 -A -s 500 I grep -i refer
```

#### بررسی درخواست های HTTP برای شناسایی الگو های مشکوک و یا خطرناک:

```text
# tcpdump -s 1024 -l -A dst <EXAMPLE.COM>
```

**مسموم نمودن یا Poison:** حملات لایه 2

برای مثال , ARP poison, race condition DNS, DHCP

```text
# tcpdump 'arp or icmp'
# tcpdump -tnr <SAMPLE TRAFFIC FILE>.pcap ARP lawk -
F ',' '{print $1"."$2","$3","$4}' I sort I uniq -c
sort -n I tail
# tshark -r <SAMPLE TRAFFIC FILE>.pcap -q -z io,phsl
grep arp.duplicate-address-detected
```

## مجموعه ابزار ها

### ماشین ها و سیستم عامل های از پیش تهیه شده

#### KALI - Open Source Pentesting Distribution

منبع. [https://www.kali.org](https://www.kali.org)

#### SIFT - SANS Investigative Forensics Toolkit

منبع. [http://sift.readthedocs.org/](http://sift.readthedocs.org/)

#### REMNUX - A Linux Toolkit for Reverse-Engineering and Analyzing Malware

منبع. [https://remnux.org](https://remnux.org)

#### OPEN VAS - Open Source vulnerability scanner and manager

منبع. [http://www.openvas.org](http://www.openvas.org)

#### MOLOCH - Large scale IPv4 packet capturing \(PCAP\), indexing and database system

منبع. [https://github.com/aol/moloch/wiki](https://github.com/aol/moloch/wiki)

#### SECURITY ONION - Linux distro for intrusion detection, network security monitoring, and log management

منبع. [https://security-onionsolutions](https://security-onionsolutions). github.io/security-onion/

#### NAGIOS - Network Monitoring, Alerting, Response, and Reporting Tool

منبع. [https://www.nagios.org](https://www.nagios.org)

#### OSSEC - Scalable, multi-platform, open source Hostbased Intrusion Detection System

منبع. [http://ossec.github.io](http://ossec.github.io)

#### SAMURAI WTF - Pre-configured web pen-testing environment

منبع. [http://samurai.inguardians.com](http://samurai.inguardians.com)

#### RTIR - Request Tracker for Incident Response

منبع. [https://www.bestpractical.com/rtir/](https://www.bestpractical.com/rtir/)

#### HONEYDRIVE - Pre-configured honeypot software packages

منبع. [http://sourceforge.net/projects/honeydrive/](http://sourceforge.net/projects/honeydrive/)

#### ابزار های جلوگیری از اجرای موفقیت آمیز اکسپلویت

منبع. [https://support.microsoft.com/en-us/kb/2458544](https://support.microsoft.com/en-us/kb/2458544)

#### ATTACK SURFACE ANALYZER BY MICROSOFT - Baseline Tool

منبع. [https://www.microsoft.com/enus/](https://www.microsoft.com/enus/) download/confirmation.aspx?id=24487

#### WINDOWS TO GO - USB Portable Windows 8

منبع. [https://technet.microsoft.com/enus/](https://technet.microsoft.com/enus/) library/hh831833.aspx

#### WINFE - Windows Forensic Environment on CD/USB

منبع. [http://winfe.wordpress.com/](http://winfe.wordpress.com/)

#### DCEPT - Deploying and detecting use of Active Directory honeytokens

منبع. [https://www.secureworks.com/blog/dcept](https://www.secureworks.com/blog/dcept)

#### TAILS - The Amnesic Incognito Live System

منبع. [https://tails.boum.org](https://tails.boum.org)
