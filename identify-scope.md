# شناسایی\(دامنه\)

## اسکن و آسیب پذیری ها

### دستور NMAP

#### استفاده از Ping sweep برای شبکه:

```text
# nmap -sn -PE <IP ADDRESS OR RANGE>
```

#### اسکن و نمایش پورت های باز:

```text
# nmap --open <IP ADDRESS OF RANGE>
```

#### تعیین سرویس های باز:

```text
# nmap -sV <IP ADDRESS>
```

#### اسکن پورت http و https(tcp):

```text
# nmap -p 80,443 <IP ADDRESS OR RANGE>
```

#### اسکن dns(udp):

```text
# nmap -sU -p 53 <IP ADDRESS OR RANGE>
```

#### Scan UDP and TCP together, be verbose on a single host and include optional skip ping:

```text
# nmap -v -Pn -SU -ST -p U:53,111,137,T:21-
25,80,139,8080 <IP ADDRESS>
```

### دستور NESSUS

#### اسکن پایه ای Nessus:

```text
# nessus -q -x -T html <NESSUS SERVER IP ADDRESS>
<NESSUS SERVER PORT 1241> <ADMIN ACCOUNT> <ADMIN
PASSWORD> <FILE WITH TARGETS>,txt <RESULTS FILE
NAME>.html
# nessus [-vnh] [-c .refile] [-VJ [-T <format>]
```

#### اسکن Batch-mode:

```text
# nessus -q [-pPS] <HOST> <PORT> <USER NAME>
<PASSWORD> <targets-file> <result-file>
```

#### دریافت گزارش:

```text
# nessus -i in. [nsrlnbe] -o
out. [xmllnsrlnbelhtmlltxt]
```

### دستور OPENVAS

**مرحله 1:** نصب سرور و کلاینت و افزونه ها:

```text
# apt-get install openvas-server openvas-client
openvas-plugins-base openvas-plugins-dfsg
```

**مرحله 2:** بروزرسانی پایگاه داده آسیب پذیری ها

```text
# openvas-nvt-sync
```

**مرحله 3:** اضافه نموده کاربر به کلاینت:

```text
# openvas-adduser
```

**مرحله 4:** ورود: sysadm

**مرحله 5:** احراز هویت \(pass/cert\) \[pass\]: \[HIT ENTER\]

**مرحله 6:** کلمه عبور ورود: 

بر اساس سیسات های اضافه نموده کاربر

**مرحله 7:** اجازه به کاربر برای اسکن شبکه های نیاز مند احراز هویت:

```text
accept <YOUR IP ADDRESS OR RANGE>
default deny
```

**مرحله 8**: کلید های ترکیبی ctrl-D برای خروج.

**Step 9:** Start the server:

```text
# service openvas-server start
```

**مرحله 10:** انتخاب هدف برای اسکن:

ایجاد فایلی شامل هدف ها.

```text
# vi scanme.txt
```

**مرحله 11:** اضافه نموده هاست های مختلف در هر خط:

```text
<IP ADDRESS OR RANGE>
```

**مرحله 12:** شروع اسکن:

```text
# openvas-client -q 127.0.0.1 9390 sysadm nsrc+ws
scanme.txt openvas-output-.html -T txt -V -x
```

**مرحله 13:** \(دلخواه\)شروع اسکن با فرمت html:

```text
# openvas-client -q 127.0.0.1 9390 sysadm nsrc+ws
scanme.txt openvas-output.txt -T html -V -x
```

## ویندوز

### شناسایی شبکه

#### شناسایی پایه ای شبکه:

```text
C:> net view /all
C:> net view \\<HOST NAME>
```

#### استفاده از ping برای اسکن و ذخیره حاصل درون فایل:

```text
C:\> for /L %I in (1,1,254) do ping -w 30 -n 1
192.168. l.%I I find "Reply" >> <OUTPUT FILE
NAME>.txt
```

### DHCP

#### فعال سازی گزارشات DHCP:

```text
C:\> reg add
HKLM\System\CurrentControlSet\Services\DhcpServer\Pa
rameters /v ActivityLogFlag /t REG_DWORD /d 1
```

#### **مسیر پیش فرض ویندوز های 2003/2008/2012:**

```text
C:> %windir%\System32\Dhcp
```

### DNS

#### مسیر پیش فرض ویندوز 2003:

```text
C:\> %SystemRoot%\System32\Dns
```

#### مسیر پیشفرض Windows 2008:

```text
C:\> %SystemRoot%\System32\Winevt\Logs\DNS
Server. evtx
```

#### مسیر پیش فرض dns در ویندوز 2012 R2:

```text
C:\> %SystemRoot%\System32\Winevt\Logs\Microsoft­
Windows-DNSServer%4Analytical.etl
```

منبع. [https://technet.microsoft.com/en­](https://technet.microsoft.com/en­) us/library/cc940779.aspx

#### فعال سازی گزارش دهی DNS:

```text
C:\> DNSCmd <DNS SERVER NAME> /config /logLevel
0x8100F331
```

#### تنظیم مسیر log:

```text
C:\> DNSCmd <DNS SERVER NAME> /config /LogFilePath
<PATH TO LOG FILE>
```

#### تظیم اندازه فایل های گزارشات:

```text
C:\> DNSCmd <DNS SERVER NAME> /config
/logfilemaxsize 0xffffffff
```

### هش

#### نرم افزار File Checksum Integrity Verifier \(FCIV\):

منبع. [http://support2.microsoft.com/kb/841290](http://support2.microsoft.com/kb/841290)

#### هش یک فایل:

```text
C:\> fciv.exe <FILE TO HASH>
```

#### هش کلیه فایل های درایور C: و فایل آن در دیتابیس xml:

```text
C:\> fciv.exe c:\ -r -mdS -xml <FILE NAME>.xml
```

#### لیست کلیه هش های فایل ها:

```text
C:\> fciv.exe -list -shal -xml <FILE NAME>.xml
```

#### هش های قبلی را با سیستم فایل بررسی می کند:

```text
C:\> fciv.exe -v -shal -xml <FILE NAME>.xml
```

#### ممکن است ایجاد یک db master و مقایسه با همه سیستم ها از یک خط cmd امکان پذیر باشد..

منبع. [https://technet.microsoft.com/en­](https://technet.microsoft.com/en­) us/library/dn520872.aspx

```text
PS C:\> Get-FileHash <FILE TO HASH> I Format-List
PS C:\> Get-FileHash -algorithm md5 <FILE TO HASH>
C:\> certutil -hashfile <FILE TO HASH> SHAl
C:\> certutil -hashfile <FILE TO HASH> MD5
```

### NETBIOS

#### اسکن پایه ای nbtstat:

```text
C:\> nbtstat -A <IP ADDRESS>
```

#### ذخیره اطلاعات NetBIOS در localhost:

```text
C:> nbtstat -c
```

#### اسکریپت اسکن حلقه ای:

```text
C:\> for /L %I in (1,1,254) do nbstat -An
192.168.l.%I
```

### فعالیت های کاربر

منبع. [https://technet.microsoft.com/en­](https://technet.microsoft.com/en­) us/sysinternals/psloggedon.aspx

#### نمایش کاربر وارد شده:

```text
C:\> psloggedon \\computername
```

#### اسکریپت اسکن حلقه ای :

```text
C:&gt; for /L %i in \(1,1,254\) do psloggedon \192.168.l.%i &gt;&gt; C:\users\_output.txt
```

### کلمه عبور ها

#### حدس یا بررسی کلمه عبور:

```text
# for /f %i in (<PASSWORD FILE NAME>.txt) do
@echo %i & net use \\<TARGET IP ADDRESS> %i /u:<USER
NAME> 2>nul && pause

# for /f %i in (<USER NAME FILE>.txt) do @(for /f %j
in (<PASSWORD FILE NAME>.txt) do @echo %i:%j & @net
use \\<TARGET IP ADDRESS> %j /u:%i 2>nul &&
echo %i:%j >> success.txt && net use \\<IP ADDRESS>
/del)
```

### بررسی MICROSOFT BASELINE SECURITY ANALYZER \(MBSA\)

#### اسکن پایه ای ip هدف:

```text
C:\> mbsacli.exe /target <TARGET IP ADDRESS> /n
os+iis+sql+password
```

#### اسکن پایه ای محدوده ip هدف:

```text
C:\> mbsacli.exe /r <IP ADDRESS RANGE> /n
os+iis+sql+password
```

#### اسکن پایه ای دامین هدف:

```text
C:\> mbsacli.exe /d <TARGET DOMAIN> /n
os+iis+sql+password
```

#### اسکن پایه ای برای نام های درون فایل txt:

```text
C:\> mbsacli.exe /listfile <LISTNAME OF COMPUTER
NAMES>.txt /n os+iis+sql+password
```

### ACTIVE DIRECTORY INVENTORY

#### لیست کل OU ها:

```text
C:\> dsquery ou DC=<DOMAIN>,DC=<DOMAIN EXTENSION>
```

#### لیست کلیه ایستگاه های کاری دامین:

```text
C:\> netdom query WORKSTATION
```

#### لیست کلیه سرور های دامین:

```text
C:\> netdom query SERVER
```

#### لیست کلیه domain controllers:

```text
C:\> netdom query DC
```

#### لیست کلیه ou که کاربر حق ایجاد object را دارد:

```text
C:\> netdom query OU
```

#### لیست domain controller ثانویه:

```text
C:\> netdom query PDC
```

#### لیست کلیه دامین های مورد اعتماد:

```text
C:\> netdom query TRUST
```

#### لیست فعلی صاحبان FSMO را مشخص می کند

```text
C:\> netdom query FSMO
```

#### لیست کلیه رایانه های  Active Directory:

```text
C:\> dsquery COMPUTER "OU=servers,DC=<DOMAIN
NAME>,DC=<DOMAIN EXTENSION>" -o rdn -limit 0 >
C:\machines.txt
```

#### لیست کلیه کاربران غیر فعال در 3 هفته اخیر

```text
C:\> dsquery user domainroot -inactive 3
```

#### جست و جو هر چیز \(یا هر کاربر\) که timestamp آن به شکل YYYYMMDDHHMMSS.sZ است:

```text
C:\> dsquery * -filter
"(whenCreated>=20101022083730,0Z)"
C:\> dsquery * -filter
"((whenCreated>=20101022083730.0Z)&(objectClass=user
) ) II
```

#### **راه مشابه:**

```text
C:\> ldifde -d ou=<OU NAME>,dC=<DOMAIN
NAME>,dc=<DOMAIN EXTENSION> -l whencreated,
whenchanged -p onelevel -r "(ObjectCategory=user)" -
f <OUTPUT FILENAME>
```

**timestamp آخرین ورود UTC: YYYYMMDDHHMMSS**

**راه مشابه:**

```text
C:\> dsquery * dc=<DOMAIN NAME>,dc=<DOMAIN
EXTENSION> -filter "(&(objectCategory=Person)
(objectClass=User)(whenCreated>=20151001000000.0Z))"
```

**راه مشابه:**

```text
C:\> adfind -csv -b dc=<DOMAIN NAME>,dc=<DOMAIN
EXTENSION> -f "(&(objectCategory=Person)
(objectClass=User)(whenCreated>=20151001000000.0Z))"
```

#### با استفاده از powershell لیست کلیه کاربرانی که در 90 روز اخیر در active directory ایجاد شده اند:

```text
PS C:\> import-module activedirectory
PS C:\> Get-QADUser -CreatedAfter (Get­
Date).AddDays(-90)
PS C:\> Get-ADUser -Filter * -Properties whenCreated
I Where-Object {$_.whenCreated -ge ((Get­
Date).AddDays(-90)).Date}
```

## لینوکس

### شناسایی شبکه

#### اسکن نمای شبکه:

```text
# smbtree -b
# smbtree -D
# smbtree -5
```

#### نمایش محیط های به اشتراک گذاشته شده به اندازه 5 مگابایت:

```text
# smbclient -L <HOST NAME>
# smbstatus
```

#### اسکن پایه ای با ping:

```text
# for ip in $(seq 1 254); do ping -c 1
192.168.1.$ip>/dev/null; [ $? -eq 0 ] && echo
"192.168.1. $ip UP" || : ; done
```

### DHCP

#### مشاهده گزاراشت:

#### **در Red Hat 3:**

```text
# cat /var/lib/dhcpd/dhcpd. leases
```

**در Ubuntu:**

```text
# grep -Ei 'dhcp' /var/log/syslog.1
```

## نمایش آن در Ubuntu:

```text
# tail -f dhcpd. log
```

### DNS

#### شروع گزاراش دهی DNS:

```text
rndc querylog
```

#### نمیش گزاراشات DNS:

```text
# tail -f /var/log/messages I grep named
```

### هش

#### هش کلیه فایل های اجرایی در مسیر خاص:

```text
# find /<PATHNAME TO ENUMERATE> -type f -exec mdSsum
{} >> mdSsums.txt \;
# mdSdeep -rs /> mdSsums.txt
```

### NETBIOS

#### اسکن پایه ای nbtstat:

```text
nbtscan <IP ADDRESS OR RANGE>
```

### کلمه عبور ها

#### بررسی و حدس نام کاربری و کلمه عبور:

```text
while read line; do username=$line; while read
line; do smbclient -L <TARGET IP ADDRESS> -U
$username%$line -g -d 0; echo $username:$line;
done<<PASSWORDS>.txt;done<<USER NAMES>.txt
```
