# نظارت

## نظارت بر شبکه

### دستور TCPDUMP

#### نمایش ترافیک به ASCII \(-A\) یا HEX \(-X\):

```text
# tcpdump -A
#tcpdump -X
```

#### نمایش timestamps ترافیک ها و عدم تبدیل آدرس ها و کم صدا:

```text
# tcpdump -tttt -n -vv
```

#### شناسایی ارسال کننده ها بعد از دریافت 1000 بسته \(مشکوک حمله DDoS\):

```text
# tcpdump -nn -c 1000 jawk '{print $3}' I cut -d. 
-fl-4 I sort -n I uniq -c I sort -nr
```

#### ضبط کلیه بسته های در و بدل شده در همه interface میزبان ها و پورت 80 و ذخیره آن ها در فایل:

```text
# tcpdump -w <FILENAME>,pcap -i any dst <TARGET IP
ADDRESS> and port 80
```

#### نمایش ترافیک بین دو میزبان:

```text
# tcpdump host 10.0.0.1 && host 10.0.0.2
```

#### نمایش تمام ترافیک به غیر از محدوده شبکه و میزبان مشخص:

```text
# tcpdump not net 10.10 && not host 192.168.1,2
```

#### نمایش ترافیک بین میزبان 1 و میزبان های دیگر:

```text
#tcpdump host 10,10,10.10 && \(10,10.10.20 or
10,10,10,30\)
```

#### ذیخره فایل pcap در اندازه مشخص:

```text
# tcpdump -n -s65535 -C 1000 -w '%host_%Y-%m­%d_%H:%M:%S.pcap'
```

#### ذخیره فایل pcap file در سیستم دیگر:

```text
# tcpdump -w - I ssh <REMOTE HOST ADDRESS> -p 50005
"cat - > /tmp/remotecapture.pcap"
```

#### بررسی و جست و جو ترافیک ها برای کلمه pass:

```text
# tcpdump -n -A -s0 I grep pass
```

#### بررسی و جست و جو ترافیک ها برای پروتکل های clear text:

```text
# tcpdump -n -A -s0 port http or port ftp or port
smtp or port imap or port pop3 I egrep -i
'pass=lpwd=llog=llogin=luser=lusername=lpw=lpassw=IP
asswd=lpassword=lpass: I user: lusername: I password: I log
in: I pass I user ' --color=auto --line-buffered -B20
```

#### بررسی توان یا throughput:

```text
# tcpdump -w - lpv -bert >/dev/null
```

#### فیلتر ترافیک ipv6:

```text
# tcpdump not ip6
```

#### فیلتر ترافیک ipv4:

```text
# tcpdump ip6
```

#### اسکریپت ذخیره سازی ترافیک چندین interface در فایل به صورت زمان دار:

```text
#!/bin/bash
tcpdump -pni any -s65535 -G 3600 -w any%Y-%m­
%d_%H:%M:%S.pcap
```

#### اسکریپت انتقال فایل های ترافیک tcpdump به محل های دیگر:

```text
#!/bin/bash
while true; do
sleep 1;
rsync -azvr -progress <USER NAME>@<IP
ADDRESS>:<TRAFFIC DIRECTORY>/, <DESTINATION
DIRECTORY/.
done
```

#### جست و جو گراهینامه self-signed و مشکوک:

```text
# tcpdump -s 1500 -A '(tcp[((tcp[12:1] & 0xf0) >>
2)+5:1] = 0x01) and (tcp[((tcp[12:1] & 0xf0) >>
2) : 1] : 0x16)'
```

#### نمایش گواهینامه SSL:

```text
# openssl s_client -connect <URL>:443
# openssl s_client -connect <SITE>:443 </dev/null
2>/dev/null I sed -ne '/-BEGIN CERTIFICATE-/,/-END
CERTIFICATE-Ip' > <CERT>.pem
```

#### بررسی گواهینامه های Self-Signed:

```text
# openssl x509 -text -in <CERT>.pem

#openssl x509 -in <CERT>,pem -noout -issuer -
subject -startdate -enddate -fingerprint

# openssl verify <CERT>.pem
```

#### اسختراج نام سرور در گواهینامه ها:

```text
# tshark -nr <PCAP FILE NAME> -Y "ssl. handshake. ciphersuites" -Vx I grep "Server Name:" I sort I uniq -c I sort -r
```

#### اسختراج اطلاعات درباره گواهینامه:

```text
# ssldump -Nr <FILE NAME>.pcap I awk 'BEGIN {c=0;}
{ if ($0 � / A [ ]+Certificate$/) {c=l; print
"========================================";} if
($0 !�/ A +/) {c=0;} if (c==l) print $0; }'
```

#### بررسی وضیعت برنامه های و استفاده هر کدام از پورت ها :

```text
netstat -aon | findstr '[port_number]'
tasklist | findstr '[PID]'
tasklist | findstr '[application_name]'
netstat -aon | findstr '[PID]'
```

### دستور TSHARK

#### دریافت interface های شبکه:

```text
> tshark -D
```

#### بررسی چندین interface شبکه:

```text
> tshark -i ethl -i eth2 -i eth3
```

#### ذخیره pcap و غیرفعال سازی name resolution:

```text
> tshark -nn -w <FILE NAME>,pcap
```

#### نمایش تاریخ و  timestamp:

```text
> tshark -t a
```

#### دریافت ترافیک arp یا icmp:

```text
> tshark arp or icmp
```

#### ذخیره ترافیک بین \[میزبان ها\]  و یا \[شبکه ها\]:

```text
> tshark "host <HOST l> && host <HOST 2>"
> tshark -n "net <NET 1> && net <NET 2>"
```

#### فیلتر هاست ها و ip ها \(یا به غیر از ip شما\):

```text
> tshark -r <FILE NAME>,pcap -q -z hosts,ipv4
> tshark not host <YOUR IP ADDRESS>
```

#### به غیر از ARP و UDP:

```text
> tshark not arp and not (udp.port -- 53)
```

#### Replay های یک فایل pcap:

```text
> tshark -r <FILE NAME>.pcap
```

#### Replay های یک فایل pcap و استخراج میزبان ها و ip ها:

```text
> tshark -r <FILE NAME>.pcap -q -z hosts
```

#### آماده سازی ذخیره ترافیک\(در مدت 60 ثانیه\):

```text
> tshark -n -a files:10 -a filesize:100 -a
duration:60 -w <FILE NAME>,pcap
```

#### دریفات ip های منبع و مقصد:

```text
> tshark -n -e ip.src -e ip.dst -T fields -E
separator=, -Rip
```

#### دریافت ip مربوط به منبع dns و query های آن:

```text
> tshark -n -e ip.src -e dns,qry.name -E
separator=';' -T fields port 53
```

#### دریافت url های و درخواست http میزبان:

```text
> tshark -R http.request -T fields -E separator=';'
-e http.host -e http.request.uri
```

#### دریافت های و درخواست http میزبان:

```text
> tshark -n -R http.request -T fields -e http.host
```

#### بیشترین ارسال های به ip مقصد:

```text
> tshark -n -c 150 I awk '{print $4}' I sort -n I
uniq -c I sort -nr
```

#### آمار مربوط به پروتکل ها:

```text
> tshark -q -z io,phs -r <FILE NAME>.pcap
> tshark -r <PCAP FILE>,cap -R http.request -T
fields -e http.host -e http.request.uri lsed -e
'sf?,*$//' I sed -e 's#"(,*)t(,*)$#http://l2#' I
sort I uniq -c I sort -rn I head
> tshark -n -c 100 -e ip.src -R "dns.flags.response
eq 1" -T fields po rt 53
> tshark -n -e http.request.uri -R http.request -T
fields I grep exe
> tshark -n -c 1000 -e http.host -R http.request -T
fields port 80 I sort I uniq -c I sort -r
```

#### استخراج مقادیر درخواست های POST

```text
tshark -Y "http.request.method==POST" -T fields -e http.file_data -r keeptryin.pcap
```

### دستور SNORT

#### اجرای تست بر روی فایل تنظیمات snort:

```text
# snort -T -c /<PATH TO SNORT>/snort/snort.conf
```

#### روش استفاده از snort\(v=جزییات,d=دریافت payload های بسته\):

```text
# snort -dv -r <LOG FILE NAME>, log
```

#### پاسخ به فایل گزارشات و بررسی با ترافیک icmp:

```text
# snort -dvr packet.log icmp
```

#### گزارشات به صورت ASCII:

```text
# snort -K ascii -l <LOG DIRECTORY>
```

#### گزارشات به صورت binary:

```text
snort -l <LOG DIRECTORY>
```

#### ارسال event به console:

```text
# snort -q -A console -i eth0 -c
/etc/snort/snort.conf
# snort -c snort.conf -l /tmp/so/console -A console
```

#### ایجاد یک rule برای snort و ذخیره سازی آن:

```text
# echo alert any any <SNORT RULE> > one.rule
```

#### بررسی و تست یک rule:

```text
# snort -T -c one.rule
```

#### بررسی و تست یک rule و نتیجه آن در console ور مسیر گزارشات:

```text
# mkdir ,/logs
# snort -vd -c one.rule -r <PCAP FILE NAME>,pcap -A
console -l logs
```

## ابزار های بررسی ترافیک های شبکه یا فایل های PCAP

### ابزار EDITCAP

#### ویرایش فایل های pcap \(جداسازی 1000 بسته\):

```text
> editcap -F pcap -c 1000 orignal.pcap
out_split,pcap
```

#### ویرایش فایل های pcap \(جداسازی بسته ها در هر ساعت\):

```text
> editcap -F pcap -t+3600 orignal.pcap
out_split.pcap
```

### ابزار MERGECAP

#### برای ادغام چندین فایل pcap:

```text
> mergecap -w merged_cap.pcap capl.pcap cap2.pcap
cap3.pcap
```

## تکنیک HONEY

### ویندوز

#### Honey Port ها در ویندوز:

منبع. [http://securityweekly.com/wp­](http://securityweekly.com/wp­) content/uploads/2013/06/howtogetabetterpentest.pdf

**Step 1:** ایجاد rule در فایروال برای شناسایی و عدم اجازه به کلیه ارتباطات پورت 3333

```text
C:\> echo @echo off for /L %%i in (1,1,1) do @for /f
"tokens=3" %%j in ('netstat -nao A l find "'":3333 A "')
do@for /f "tokens=l delims=:" %%k in ("%%j") do
netsh advfirewall firewall add rulename="HONEY TOKEN
RULE" dir=in remoteip=%%k localport=any protocol=TCP
action=block >> <BATCH FILE NAME>.bat
```

**Step 2:** اجرای اسکریپت batch

```text
C:\> <BATCH FILE NAME>,bat
```

#### Honey Ports اسکریپت در powershell

Ref. [https://github.com/Pwdrkeg/honeyport/blob/master/hon](https://github.com/Pwdrkeg/honeyport/blob/master/hon) eyport.psl

**Step 1:** دریافت اسکریپت powershell

```text
C: \> "%ProgramFiles%\Internet Exp lo rer\iexplo re. exe"
https://github.com/Pwdrkeg/honeyport/blob/master/hon
eyport.psl
```

**Step 2:** اجرای اسکریپت powershell

```text
C:\> honeyport.psl
```

#### Honey Hashe ها برای ویندوز \(همچنین روش شناسایی Mimikatz\) :

منبع. [https://isc.sans.edu/forums/diary/Detecting+Mimikatz](https://isc.sans.edu/forums/diary/Detecting+Mimikatz) +Use+On+Your+Network/19311/

**Step 1:** ایجاد یک Honey Hash تقلبی. از کلمه عبور تقلبی استفاده کنید و cmd را باز نگهدارید

```text
C:\> runas
/user:yourdomain.com\fakeadministratoraccount
/netonly cmd.exe
```

**Step 2:** جست و جو برای تلاش از راه دور

```text
C:\> wevtutil qe System /q:"*[System
[(EventID=20274)]]" /f:text /rd:true /c:1
/r:remotecomputername
```

**Step 3:** جست و جو برای تلاش های ورود

```text
C:\> wevtutil qe Security /q:"*[System[(EventID=4624
or EventID=4625)]]" /f:text /rd:true /c:5
/r:remotecomputername
```

**Step 4:** \(اختیاری\) با استفاده از مکث 30 ثانیه ای نمایش داده شود

```text
C:\> for /L %i in (1,0,2) do (Insert Step 2) &
(Insert Step 3) & timeout 30
```

### لینوکس

#### Honey Port ها در لینوکس:

منبع. [http://securityweekly.com/wp­](http://securityweekly.com/wp­) content/uploads/2013/06/howtogetabetterpentest.pdf

**Step 1:** ایجاد یک حلقه برای رد کلیه درخواست های به پورت 2222

```text
# while [ 1 ] ; echo "started" ; do IP='nc -v -l -p
2222 2>&1 l> /dev/null I grep from I cut -d[ -f 3 I
cut -d] -f 1'; iptables -A INPUT -p tcp -s ${IP} -j
DROP ; done
```

#### اسکریپت Honey Port در لینوکس :

منبع. [https://github.com/gchetrick/honeyports/blob/master/](https://github.com/gchetrick/honeyports/blob/master/) honeyports-0.5.py

**Step 1:** دریافت اسکریپت پایتون

```text
# wget
https://github.com/gchetrick/honeyports/blob/master/
honeyports-0.5.py
```

**Step 2:** اجرای اسکریپت پایتون

```text
# python honeyports-0.5.py -p <CHOOSE AN OPEN PORT>
-h <HOST IP ADDRESS>
```

#### شناسایی rogue scanning با استفاده از Labrea Tarpit:

```text
# apt-get install labrea
# labrea -z -s -o -b -v -i eth0 2>&1 | tee -a log.txt
```

### ابزار NETCAT

#### استفاده از netcat برای شناسایی اسکن های تهدید آمیز:

```text
> nc -v -k -l 80
> nc -v -k -l 443
> nc -v -k -l 3389
```

### نظارت بر PASSIVE DNS

#### استفاده از  dnstop برای نظارت بر درخواست های DNS در هر موقعیتی:

```text
# apt-get update
# apt-get install dnstop
# dnstop -l 3 <INTERFACE NAME>
```

**مرحله 1:** کلید 2 را فشار دهید تا نام ها نمایش داده شود

#### استفاده از dnstop  برای نظارت بر درخواست های dns داخل فایل pcap:

```text
# dnstop -l 3 <PCAP FILE NAME> I <OUTPUT FILE
NAME>,txt
```

## روش های LOG AUDITING

### ویندوز

#### افزایش اندازه Log به منظور ارتقا auditing:

```text
C:\> reg add
HKLM\Software\Policies\Microsoft\Windows\Eventlog\Ap
plication /v MaxSize /t REG_DWORD /d 0x19000
C:\> reg add
HKLM\Software\Policies\Microsoft\Windows\Eventlog\Se
curity /v MaxSize /t REG_DWORD /d 0x64000
C:\> reg add
HKLM\Software\Policies\Microsoft\Windows\EventLog\Sy
stem /v MaxSize /t REG_DWORD /d 0x19000
```

#### بررسی تنظیمات Security log:

```text
C:\> wevtutil gl Security
```

#### برای تنظیمات audit policies:

```text
C:\> auditpol /get /category:*
```

#### تنظیم Log Auditing موفق و یا ناموفق در تمامی دسته بندی ها:

```text
C:\> auditpol /set /category:* /success:enable
/failure:enable
```

#### تنظیم Log Auditing موفق و یا ناموفق در تمامی زیر دسته ها:

```text
C: \> auditpol /set /subcategory: "Detailed File
Share" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"File System"
/success:enable /failure:enable
C:\> auditpol /set /subcategory:"Security System
Extension" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"System Integrity"
/success:enable /failure:enable
C:\> auditpol /set /subcategory:"Security State
Change" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Other System
Events" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"System Integrity"
/success:enable /failure:enable
C:\> auditpol /set /subcategory:"Logon"
/success:enable /failure:enable
C:\> auditpol /set /subcategory:"Logoff"
/success:enable /failure:enable
C:\> auditpol /set /subcategory:"Account Lockout"
/success:enable /failure:enable
C:\> auditpol /set /subcategory:"Other Logon/Logoff
Events" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Network Policy
Server" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Registry"
/success:enable /failure:enable
C:\> auditpol /set /subcategory:"SAM"
/success:enable /failure:enable
C:\> auditpol /set /subcategory:"Certification
Services" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Application
Generated" /success:enable /failure:enable
C: \> auditpol / set /subcategory: "Handle
Manipulation" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"file Share"
/success:enable /failure:enable
C:\> auditpol /set /subcategory:"filtering Platform
Packet Drop" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Filtering Platform
Connection" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Other Object Access
Events" /success:enable /failure:enable
C: \> auditpol /set /subcategory: "Detailed File
Share" /success:enable /failure:enable
C: \> auditpol /set /subcategory: "Sensitive Privilege
Use" /success:enable /failure:enable
C: \> auditpol /set /subcategory: "Non Sensitive
Privilege Use" /success:enable /failure:enable
C: \> auditpol /set /subcategory: "Other Privilege Use
Events" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Process
Termination" /success:enable /failure:enable
C:\> auditpol /set /subcategory: "DPAPI Activity"
/success:enable /failure:enable
C: \> audit pol /set /subcategory: "RPC Events"
/success:enable /failure:enable
C:\> auditpol /set /subcategory:"Process Creation"
/success:enable /failure:enable
C:\> auditpol /set /subcategory:"Audit Policy
Change" /success:enable /failure:enable
C:\> auditpol /set /subcategory: "Authentication
Policy Change" /success:enable /failure:enable
C:\> auditpol /set /subcategory: "Authorization
Policy Change" /success:enable /failure:enable
C: \> audit pol /set /subcategory: "MPSSVC Rule-Level
Policy Change" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Filtering Platform
Policy Change" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Other Policy Change
Events" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"User Account
Management" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Computer Account
Management" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Security Group
Management" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Distribution Group
Management" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Application Group
Management" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Other Account
Management Events" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Directory Service
Changes" /success:enable /failure:enable
C: \> auditpol / set /subcategory: "Directory Service
Replication" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Detailed Directory
Service Replication" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Directory Service
Access" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Kerberos Service
Ticket Operations" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Other Account Logan
Events" /success:enable /failure:enable
C: \> audit pol /set /subcategory: "Kerberos
Authentication Service" /success:enable
/failure:enable
C:\> auditpol /set /subcategory:"Credential
Validation" /success:enable /failure:enable
```

#### لیست گزارشات موجود و اندازه و مجاز:

```text
PS C:\> Get-Eventlog -list
```

#### لیست جزئی از کلید های نظارت بر Security Log Auditing events :

```text
PS C:\> Get-Eventlog -newest 5 -logname application
I Format-List
```

#### نمایش گزارشات به صورت از راه دور:

```text
PS C:\> Show-Eventlog -computername <SERVER NAME>
```

#### نمایش لیست event ها بر اساس Event ID:

```text
PS C:\> Get-Eventlog Security I ? { $_.Eventid -eq
4800}
PS C:\> Get-WinEvent -FilterHashtable
@{LogName="Secu rity"; ID=4774}
```

#### ورود به حساب - Audit Credential Validation برای 14 روز اخیر:

```text
PS C:\> Get-Eventlog Security
4768,4771,4772,4769,4770,4649,4778,4779,4800,4801,48
02,4803,5378,5632,5633 -after ((get-date).addDays(-
14))
```

#### حساب - ورود و خروج:
ا
```text
PS C:\> Get-Eventlog Security
4625,4634,4647,4624,4625,4648,4675,6272,6273,6274,62
75,6276,6277,6278,6279,6280,4649,4778,4779,4800,4801
,4802,4803,5378,5632,5633,4964 -after ((get­
date).addDays(-1))
```

#### مدیریت حساب - مدیریت گروه برنامه های Audit:

```text
PS C:\> Get-Eventlog Security
4783,4784,4785,4786,4787,4788,4789,4790,4741,4742,47
43,4744,4745,4746,4747,4748,4749,4750,4751,4752,4753
,4759,4760,4761,4762,4782,4793,4727,4728,4729,4730,4
731,4732,4733,4734,4735,4737,4754,4755,4756,4757,475
8,4764,4720,4722,4723,4724,4725,4726,4738,4740,4765,
4766,4767,4780,4781,4794,5376,5377 -after ((get­
date).addDays(-1))
```

#### ردیابی دقیق - Audit DPAPI Activity, Process Termination, RPC Events:

```text
PS C:\> Get-EventLog Security
4692,4693,4694,4695,4689,5712 -after ((get­
date).addDays(-1))
```

#### دسترسی به سرویس دامین - Audit دسترسی به سرویس دایرکتوری:

```text
PS C:\> Get-EventLog Security
4662,5136,5137,5138,5139,5141 -after ((get­
date).addDays(-1))
```

#### دسترسی به object - Audit اشتراک فایل, فایل سیستم, SAM, رجیستری, گواهینامه ها:

```text
PS C:\> Get-EventLog Security
4671,4691,4698,4699,4700,4701,4702,5148,5149,5888,58
89,5890,4657,5039,4659,4660,4661,4663,4656,4658,4690
,4874,4875,4880,4881,4882,4884,4885,4888,4890,4891,4
892,4895,4896,4898,5145,5140,5142,5143,5144,5168,514
0,5142,5143,5144,5168,5140,5142,5143,5144,5168,4664,
4985,5152,5153,5031,5140,5150,5151,5154,5155,5156,51
57,5158,5159 -after ((get-date).addDays(-1))
```

#### Policy تغییر - Audit Policy تغییر, Microsoft Protection سرویس, Windows Filtering Platform:

```text
PS C:\> Get-EventLog Security
4715,4719,4817,4902,4904,4905,4906,4907,4908,4912,47
13,4716,4717,4718,4739,4864,4865,4866,4867,4704,4705
,4706,4707,4714,4944,4945,4946,4947,4948,4949,4950,4
951,4952,4953,4954,4956,4957,4958,5046,5047,5048,544
9,5450,4670 -after ((get-date).addDays(-1))
```

#### Privilege استفاده - Audit مربوط به privilage استفاده از سرویس های حساس و غیرحساس:

```text
PS C:\> Get-EventLog Security 4672,4673,4674 -after
((get-date),addDays(-1))
```

#### سیستم - Audit Security تغییر وضیعت, Security System پسوند, System تمامیت, System Events:

```text
PS C:\> Get-Eventlog Security
5024,5025,5027,5028,5029,5030,5032,5033,5034,5035,50
37,5058,5059,6400,6401,6402,6403,6404,6405,6406,6407
,4608,4609 ,4616, 4621, 4610, 4611, 4614,
4622,4697,4612,4615,4618,4816,5038,5056,5057,5060,50
61,5062,6281 -after ((get-date).addDays(-1))
```

#### اضافه نمودن ماژول Microsoft IIS:

```text
PS C:\> add-pssnapin WebAdministration
PS C:\> Import-Module WebAdministration
```

#### دریافت اطلاعات درباره IIS:

```text
PS C:\> Get-IISSite
```

#### دریافت اطلاعات مسیر IIS:

```text
PS C:\> (Get-WebConfigurationProperty
'/system.applicationHost/sites/siteDefaults' -Name
'logfile.directory').Value
```

#### تنظیم متغییر برای مسیر گزارش IIS \(مسیر پیشفرض\):

```text
PS C:\> $LogDirPath =
"C:\inetpub\logs\LogFiles\W3SVCl"
```

#### دریافت فایل گزارشات 7 روز اخیر IIS:

```text
PS C:\> Get-Child!tem -Path
C:\inetpub\logs\LogFiles\w3svcl -recurse I Where­
Object {$_. lastwritetime -lt (get-date).addDays(-7)}
```

#### نمایش فایل گزارشات IIS \(استفاده از متغیر $LogDirPath\):

```text
PS C:\> Get-Content $LogDirPath\*, log I%{$_ -replace
'#Fields: ', "} I?{$_ -notmatch ""#'} I
ConvertFrom-Csv -Delimiter ' '
```

#### نمایش گزاراشت IIS:

```text
PS C:\> Get-Content <!IS LOG FILE NAME>, log I%{$_ -
replace '#Fields: ', ''} 17{$_ -notmatch 'A#'} I
ConvertFrom-Csv -Delimiter ' '
```

#### جست و جو در فایل گزارشات IIS به شکل  IP address 192.168._·_:

```text
PS C:\> Select-String -Path $LogDirPath\*, log -
Pattern '192,168,*,*'
```

#### جست و جو در فایل گزارشات IIS برای پیدا نمودن حمله SQL injection:

```text
PS C:\> Select-String -Path $LogDirPath\*, log
'(@@version) I (sqlmap) I (Connect\(\)) I (cast\() I (char\(
) I ( bcha r\ () I ( sys
databases) I ( \ (select) I (convert\ () I ( Connect\ () I ( count
\() I (sys objects)'
```

### لینوکس

#### گزراشت احراز هویت در Ubuntu:

```text
# tail /var/log/auth. log
# grep -i "fail" /var/log/auth. log
```

#### نمایش گزارشات ورود در Ubuntu:

```text
# tail /var/
```

#### نمایش گزارشات samba:

```text
# grep -i samba /var/log/syslog
```

#### نمایش فعالیت های cron:

```text
# grep -i cron /var/log/syslog
```

#### نمایش فعالیت های sudo:

```text
# grep -i sudo /var/log/auth. log
```

#### نمایش گزارشات Apache برای خطاهای 404:

```text
# grep 404 <LOG FILE NAME> I grep -v -E
"favicon. ico I robots. txt"
```

#### نمایش گزارشات Apache برای درخواست فایل ها:

```text
# head access_log I awk '{print $7}'
```

#### نظارت بر فایل های ایجاد شده در هر 5 دقیقه:

```text
# watch -n 300 -d ls -lR /<WEB DIRECTORY>
```

#### نمایش ترافیک های از سمت:

```text
# cat <LOG FILE NAME> I fgrep -v <YOUR DOMAIN> I cut
-d\" -f4 I grep -v ""-
```

#### نظارت بر ارتباطات TCP هر 5 ثانیه:

```text
# netstat -ac 5 I grep tcp
```

#### نصب فریمورک audit و بررسی syscalls/events:

```text
# apt-get install auditd
# auditctl -a exit,always -5 execve
# ausearch -m execve
```

#### دریافت گزارشات audit:

```text
# aureport
```
