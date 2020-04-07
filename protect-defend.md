# محافظت و دفاع

## ویندوز

### غیر فعال سازی و یا توقف سرویس ها

#### لیست سرویس های متوقف و یا غیر فعال شده:

```text
C:\> sc query
C:\> sc config "<SERVICE NAME>" start= disabled
C:\> sc stop "<SERVICE NAME>"
C:\> wmic service where name='<SERVICE NAME>' call
ChangeStartmode Disabled
```

### فایروال میزبان

#### نمایش تمام rule ها:

```text
C:\> netsh advfirewall firewall show rule name=all
```

#### روشن و یا خاموش نمودن فایروال :

```text
C:\> netsh advfirewall set currentprofile state on
C:\> netsh advfirewall set currentprofile
firewallpolicy blockinboundalways,allowoutbound
C:\> netsh advfirewall set publicprofile state on
C:\> netsh advfirewall set privateprofile state on
C:\> netsh advfirewall set domainprofile state on
C:\> netsh advfirewall set allprofile state on
C:\> netsh advfirewall set allprof ile state off
```

#### تنظیم rule جدید برای فایروال:

```text
C:\> netsh advfirewall firewall add rule name="Open
Port 80" dir=in action=allow protocol=TCP
localport=80

C:\> netsh advfirewall firewall add rule name="My
Application" dir=in action=al low
program="C:\MyApp\MyApp.exe" enable=yes

C:\> netsh advfirewall firewall add rule name="My
Application" dir=in action=al low
program="C:\MyApp\MyApp.exe" enable=yes
remoteip=157.60.0.1,172.16.0.0/16,Local5ubnet
prof i le=doma in

C:\> netsh advfirewall firewall add rule name="My
Application" dir=in action=allow
program="C:\MyApp\MyApp.exe" enable=yes
remoteip=157.60.0.1,172.16.0.0/16,LocalSubnet
profile=domain

C:\> netsh advfirewall firewall add rule name="My
Application" dir=in action=al low
program="C:\MyApp\MyApp.exe" enable=yes
remoteip=157.60.0.1,172.16.0.0/16,Local5ubnet
profile=private

C:\> netsh advfirewall firewall delete rule
name=rule name program="C:\MyApp\MyApp.exe"

C:\> netsh advfirewall firewall delete rule
name=rule name protocol=udp localport=500

C:\> netsh advfirewall firewall set rule
group=" remote desktop" new enable=Yes prof ile=domain

C:\> netsh advfirewall firewall set rule
group="remote desktop" new enable=No profile=public
```

#### تنظیم موقعیت مکانی گزارشات:

```text
C:\> netsh advfirewall set currentprofile logging
C:\<LOCATION>\<FILE NAME>
```

#### تنظیم و تغییر موقعیت گزارشات فایروال:

```text
C:\>
more %systemroot%\system32\LogFiles\Firewall\pfirewa
ll.log

C:\> netsh advfirewall set allprofile logging
maxfilesize 4096

C:\> netsh advfirewall set allprofile logging
droppedconnections enable

C:\> netsh advfirewall set allprofile logging
allowedconnections enable
```

#### نمایش گزارشات فایروال:

```text
PS C:\> Get-Content
$env:systemroot\system32\LogFiles\Firewall\pfirewall
. log
```

### کلمه عبور ها

#### تغییر کلمه عبور:

```text
C:\> net user <USER NAME> * /domain
C:\> net user <USER NAME> <NEW PASSWORD>
```

### تغییر کلمه عبور از راه دور:

منبع. [https://technet.microsoft.com/en­](https://technet.microsoft.com/en­) us/sysinternals/bb897543 

```text
C:\> pspasswd.exe \\<IP ADDRESS or NAME OF REMOTE
COMPUTER> -u <REMOTE USER NAME> -p <NEW PASSWORD>
```

#### تغییر کلمه عبور از راه دور:

```text
PS C:\> pspasswd.exe \\<IP ADDRESS or NAME OF REMOTE
COMPUTER>
```

### فایل های میزبان

#### تنظیم دوباره DNS:

```text
C:\> ipconfig /flushdns
```

#### تنظیم دوباره حافظه نهان NetBios:

```text
C:\> nbtstat -R
```

#### اضافه نمودن دامنه مخرب و هدایت آن به localhost:

```text
C:\> echo 127.0.0.1 <MALICIOUS DOMAIN> >>
C:\Windows\System32\drivers\etc\hosts
```

#### بررسی فایل های میزبان با ارسال ping 127.0.0.1:

```text
C:\> ping <MALICIOUS DOMAIN> -n 1
```

### لیست سفید

#### ایجاد و استفاده از فایل Proxy Auto Config\(PAC\) برای url و ip های مشکوک:

```text
function FindProxyForURL(url, host) {
II Send bad DNS name to the proxy
if (dnsDomainis(host, ".badsite.com"))
return "PROXY http:11127.0.0.1:8080";
II Send bad IPs to the proxy
if (isinNet(myipAddress(), "222.222.222.222",
"255.255.255.0"))
return "PROXY http:11127.0.0.1:8080";
II All other traffic bypass proxy
return "DIRECT";
}
```

### محدودیت های برنامه ای

#### استفاده از Applocker - برای Server 2008 R2 یا Windows 7 یا بالا تر:

* rule هایی برای فایل های اجرایی \(. exe, . com\)
* rule های dll \( .dll, .ocx\)
* rule های اسکریپت ها \(.psl, .bat, .cmd, .vbs, .js\)
* rule های نصب برنامه \( .msi, .msp, .mst\)

#### مراحل کار با Applocker \(نیازمند GUI\):

**Step 1:** Create a new GPO.

**Step 2:** Right-click on it to edit, and then navigate through Computer Configuration, Policies, Windows Settings, Security Settings, Application Control Policies and Applocker. Click Configure Rule Enforcement.

**Step 3:** Under Executable Rules, check the Configured box and then make sure Enforce Rules is selected from the drop-down box. Click OK.

**Step 4:** In the left pane, click Executable Rules.

**Step 5:** Right-click in the right pane and select Create New Rule.

**Step 6:** On the Before You Begin screen, click Next.

**Step 7:** On the Permissions screen, click Next.

**Step 8:** On the Conditions screen, select the Publisher condition and click Next.

**Step 9:** Click the Browse button and browse to any executable file on your system. It doesn't matter which.

**Step 10:** Drag the slider up to Any Publisher and then click Next.

**Step 11:** Click Next on the Exceptions screen.

**Step 12:** Name policy, Example uonly run executables that are signed" and click Create.

**Step 13:** If this is your first time creating an Applocker policy, Windows will prompt you to create default rule, click Yes. 

**Step 14:** Ensure Application Identity Service is Running.

```text
C:\> net start AppIDSvc
C:\> REG add
"HKLM\SYSTEM\CurrentControlSet\services\AppIDSvc" /v
Start /t REG_DWORD /d 2 /f
```

**Step 15:** Changes require reboot.

```text
C:\ shutdown.exe /r
C:\ shutdown.exe /r /m \\<IP ADDRESS OR COMPUTER
NAME> /f
```

#### استفاده از ماژول Applocker در PowerShell:

```text
PS C:\> import-module Applocker
```

#### اطلاعات درباره پرونده و فایل های اجرایی و غیر اجرای در مسیر C:\Windows\System32 را نمایش می دهد:

```text
PS C:\> Get-ApplockerFileinformation -Directory
C:\Windows\System32\ -Recurse -FileType Exe, Script
```

#### ایجاد policy در Applocker برای کلیه فایل های اجرایی در مسیر C:\Windows\System32:

```text
PS C:\> Get-ApplockerFileinformation -Directory
C:\Windows\System32\ -Recurse -FileType Exe, Script
```

#### ایجاد policy در Applocker برای اجازه به کلیه فایل های اجرایی در مسیر C:\Windows\System32:

```text
PS C:\> Get-Childitem C:\Windows\System32\*,exe I
Get-ApplockerFileinformation I New-ApplockerPolicy -
RuleType Publisher, Hash -User Everyone -
RuleNamePrefix System32
```

#### تغییر policy های موجود با استفاده از فایل  C:\Policy.xml:

```text
PS C:\> Set-AppLockerPolicy -XMLPolicy C:\Policy.xml
```

#### استفاده از policy های Applocker برای اجازه به اجرای notepad و calc برای کاربرانی که عضو گروه everyone هستند:

```text
PS C:\> Test-AppLockerPolicy -XMLPolicy
C:\Policy.xml -Path C:\Windows\System32\calc.exe,
C:\Windows\System32\notepad.exe -User Everyone
```

#### ایجاد محدودیت برای تعداد اجرا:

```text
PS C:\> Get-ApplockerFileinformation -Eventlog -
Logname "Microsoft-Windows-Applocker\EXE and DLL" -
EventType Audited -Statistics
```

#### ایجاد یک policy برای Applocker از event های audited شده برای فایل های exe و dll:

```text
PS C:\> Get-ApplockerFileinformation -Eventlog -
LogPath "Microsoft-Windows-AppLocker/EXE and DLL" -
EventType Audited I New-ApplockerPolicy -RuleType
Publisher,Hash -User domain\<GROUP> -
IgnoreMissingFileinformation I Set-ApplockerPolicy -
LDAP "LDAP://<DC>,<DOMAIN>.com/CN={31B2F340-016D-
11D2-945F-
00C04FB984F9},CN=Policies,CN=System,DC=<DOMAIN>,DC=com"
```

#### استخراج کلیه policy های Applocker:

```text
PS C:\> Get-AppLockerPolicy -Local I Test­
AppLockerPolicy -Path C:\Windows\System32\*,exe -
User domain\<USER NAME> -Filter Denied I Format-List
-Property Path > C:\DeniedFiles.txt
```

#### بررسی و تست فایل استخراج شده policy های Applocker:

```text
PS C:\> Get-Childitem <DirectoryPathtoReview> -
Filter <FileExtensionFilter> -Recurse I Convert-Path
I Test-ApplockerPolicy -XMLPolicy
<PathToExportedPolicyFile> -User <domain\username> -
Filter <TypeofRuletoFilterFor> I Export-CSV
<PathToExportResultsTo.CSV>
```

#### نمایش لیست GridView برای کلیه rule ها:

```text
PS C:\> Get-AppLockerPolicy -Local -Xml I Out­-GridView
```

### دستور IPSEC

#### ایجاد یک Local Security Policy برای Applocker برای هر گونه اتصال و پروتکلی و با استفاده از preshared key:

```text
C:\> netsh ipsec static add filter
filterlist=MyIPsecFilter srcaddr=Any dstaddr=Any
protocol=ANY
C:\> netsh ipsec static add filteraction
name=MyIPsecAction action=negotiate
C:\> netsh ipsec static add policy
name=MyIPsecPolicy assign=yes
C:\> netsh ipsec static add rule name=MyIPsecRule
policy=MyIPsecPolicy filterlist=MyIPsecFilter
filteraction=MyIPsecAction conntype=all activate=yes
psk=<PASSWORD>
```

#### اضافه نمودن rule مربوط به اجازه به پورت 80 و 443 در ipsec:

```text
C:\> netsh ipsec static add filteraction name=Allow
action=permit
C:\> netsh ipsec static add filter
filterlist=WebFilter srcaddr=Any dstaddr=Any
protocol=TCP dstport=80
C:\> netsh ipsec static add filter
filterlist=WebFilter srcaddr=Any dstaddr=Any
protocol=TCP dstport=443
C:\> netsh ipsec static add rule name=WebAllow
policy=MyIPsecPolicy filterlist=WebFilter
filteraction=Allow conntype=all activate=yes
psk=<PASSWORD>
```

#### نمایش کلیه Local Security Policy در ipsec که اسم آن "MyIPsecPolicy":

```text
C:\> netsh ipsec static show policy
name=MyIPsecPolicy
```

#### توقف و یا عدم استفاده از policy ها در IPSEC:

```text
C:\> netsh ipsec static set policy
name=MyIPsecPolicy
```

#### ایجاد یک policy و rule و preshared key جدید برای هر گونه اتصالی:

```text
C:\> netsh advfirewall consec add rule name= u IPSEC"
endpointl=any endpoint2=any
action=requireinrequireout qmsecmethods=default
```

#### نیازمند preshared key برای کلیه درخواست های outgoing در ipsec:

```text
C:\> netsh advfirewall firewall add rule
name= u IPSEC_Out" dir=out action=allow enable=yes
profile=any localip=any remoteip=any protocol=any
interfacetype=any security=authenticate
```

#### ایجاد یک rule برای  web browsing:

```text
C:\> netsh advfirewall firewall add rule name="Allow
Outbound Port 80 11 dir=out localport=80 protocol=TCP
action=allow
```

#### ایجاد یک rule برای DNS:

```text
C:\> netsh advfirewall firewall add rule name="Allow
Outbound Port 53 11 dir=out localport=53 protocol=UDP
action=allow
```

#### حذف Rule در IPSEC:

```text
C:\> netsh advfirewall firewall delete rule
name="IPSEC_RULE"
```

### ACTIVE DIRECTORY \(AD\) و GROUP POLICY OBJECT \(GPO\)

#### دریافت و اعمال policie های جدید:

```text
C:\> gpupdate /force
C:\> gpupdate /sync
```

#### Audit موفق و ناموفق برای کاربر Bob:

```text
C:> auditpol /set /user:bob /category:"Detailed
Tracking" /include /success:enable /failure:enable
```

#### ایجاد یک Organization Unit برای انتقال کاربران و رایانه های مشکوک:

```text
C:\> dsadd OU <QUARANTINE BAD OU>
```

#### انتقال کاربران active directory به گروه جدید NEW GROUP:

```text
PS C:\> Move-ADObject 'CN=<USER NAME>,CN=<OLD USER
GROUP>,DC=<OLD DOMAIN>,DC=<OLD EXTENSION>' -
TargetPath 'OU=<NEW USER GROUP>,DC=<OLD
DOMAIN>,DC=<OLD EXTENSION>'
```

**روش مشابه:**

```text
C:\> dsmove "CN=<USER NAME>,OU=<OLD USER OU>,DC=<OLD
DOMAIN>,DC=<OLD EXTENSION>" -newparent OU=<NEW USER
GROUP>,DC=<OLD DOMAIN>,DC=<OLD EXTENSION>
```

### سیستم بدون ACTIVE DIRECTORY \(AD\)

#### عدم اجازه به فایل .exe:

```text
C:\> reg add
"HKCU\Software\Microsoft\Windows\CurrentVersion\Poli
cies\Explorer" /v DisallowRun /t REG_DWORD /d
"00000001" /f
C:\> reg add
"HKCU\Software\Microsoft\Windows\CurrentVersion\Poli
cies\Explorer\DisallowRun" /v badfile.exe /t REG_SZ
/d <BAD FILE NAME>.exe /f
```

#### غیرفعال سازی Remote Desktop:

```text
C:\> reg add
"HKLM\SYSTEM\Cu rrentCont ro lSet\Cont ro l \ Terminal
Server" /f /v fDenyTSConnections /t REG_DWORD /d 1
```

#### ارسال پاسخ NTLMv2 فقط برای LM و NTLM: \(به صورت پیش فرض در ویندوز 7\)

```text
C:\> reg add
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v
lmcompatibilitylevel /t REG_DWORD /d 5 /f
```

#### محدود نموده دسترسی ناشناس:

```text
C:\> reg add
HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v
restrictanonymous /t REG_DWORD /d 1 /f
```

#### عدم اجازه دسترسی ناشناسان به SAM accounts و shares:

```text
C:\> reg add
HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v
restrictanonymoussam /t REG_DWORD /d 1 /f
```

#### غیر فعال سازی IPV6:

```text
C:\> reg add
HKLM\SYSTEM\CurrentControlSet\services\TCPIP6\Parame
ters /v DisabledComponents /t REG_DWORD /d 255 /f
```

#### غیر فعال سازی کلید ها sticky:

```text
C:\> reg add "HKCU\Control
Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ
/d 506 /f
```

#### غیر فعال سازی تغییر کلید ها:

```text
C:\> reg add "HKCU\Control
Panel \Accessibility\ ToggleKeys" /v Flags /t REG_SZ
Id 58 /f
```

#### غیر فعال سازی کلید های فیتلر:

```text
C:\> reg add "HKCU\Control
Panel\Accessibility\Keyboard Response" /v Flags /t
REG_SZ /d 122 /f
```

#### غیرفعال سازی On-screen Keyboard:

```text
C:\> reg add
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI 
/f /v ShowTabletKeyboard /t REG_DWORD /d 0
```

#### غیرفعال سازی Administrative Shares - Workstations:

```text
C:\> reg add
HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\
Parameters /f /v AutoShareWks /t REG_DWORD /d 0
```

#### غیرفعال سازی Administrative Shares - Severs

```text
C:\> reg add
HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\
Parameters /f /v AutoShareServer /t REG_DWORD /d 0
```

#### حذف هش های مربوط به حمله Pass the Hash \(نیازمند راه اندازی مجدد و تغییر کلمه عبور برای هش های قدیمی\):

```text
C:\> reg add
HKLM\SYSTEM\CurrentControlSet\Control\Lsa /f /v
NoLMHash /t REG_DWORD /d 1
```

#### غیرفعال سازی ویرایش رجیستری: \(High Risk\)

```text
C:\> reg add
HKCU\Software\Microsoft\Windows\CurrentVersion\Polic
ies\System /v DisableRegistryTools /t REG_DWORD /d 1
/f
```

#### غیر فعال سازی IE Password Cache:

```text
C:\> reg add
HKCU\Software\Microsoft\Windows\CurrentVersion\Inter
net Settings /v DisablePasswordCaching /t REG_DWORD
/d 1 /f
```

#### غیر فعال سازی CMD prompt:

```text
C:\> reg add
HKCU\Software\Policies\Microsoft\Windows\System /v
DisableCMD /t REG_DWORD /d 1 /f
```

#### غیر فعال سازی حافظه نهان احراز هویت Admin در میزبان با استفاده از rdp:

```text
C:\> reg add
HKLM\System\CurrentControlSet\Control\Lsa /v
DisableRestrictedAdmin /t REG_DWORD /d 0 /f
```

#### عدم پردازش فایل هایی که فقط یکبار اجرا شده اند:

```text
C:\> reg add
HKLM\Software\Microsoft\Windows\CurrentVersion\Polic
ies\Explorer /v DisableLocalMachineRunOnce /t
REG_DWORD /d 1

C:\> reg add
HKCU\Software\Microsoft\Windows\CurrentVersion\Polic
ies\Explorer /v DisableLocalMachineRunOnce /t
REG_DWORD /d 1
```

#### نیاز مند دسترسی User Access Control \(UAC\):

```text
C:\> reg add
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Polic
ies\System /v EnableLUA /t REG_DWORD /d 1 /f
```

#### نیاز مند دسترسی User Access Control \(UAC\):

```text
C:\> reg add
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Polic
ies\System /v EnableLUA /t REG_DWORD /d 1 /f
```

#### تغییر کلمه عبور بعد از ورود مجدد:

```text
PS C:\> Set-ADAccountPassword <USER> -NewPassword
$newpwd -Reset -PassThru I Set-ADuser -
ChangePasswordAtLogon $True
```

#### کلمه عبور را در ورود بعدی برای گروه OU تغییر کند:

```text
PS C:\> Get-ADuser -filter "department -eq '<OU GROUP>' -AND enabled -eq 'True'" | Set-ADuser - ChangePasswordAtLoggon $True
```

#### فعال سازی گزارش گیری در فایروال:

```text
C:\> netsh firewall set logging droppedpackets
connections = enable
```

## لینوکس

### غیر فعال و یا توقف سرویس ها

#### اطلاعات سرویس ها:

```text
# service --status-all
# ps -ef
# ps -aux
```

#### نمایش لیست سرویس های راه انداز:

```text
# initctl list
```

#### نمونه ای از شروع و توقف سرویس ها در ubuntu 

#### در Ubuntu:

```text
# /etc/init,d/apache2 start
# /etc/init.d/apache2 restart
# /etc/init.d/apache2 stop (stops only until reboot)
# service mysql start
# service mysql restart
# service mysql stop (stops only until reboot)
```

#### لیست کلیه سرویس های راه انداز:

```text
# ls /etc/init/*,conf
```

#### بررسی وضیعت سرویس راه انداز:

```text
# status ssh
```

#### بررسی وضیعت سرویس در صورتی که عضو راه انداز نباشد:

```text
# update-rc.d apache2 disable
# service apache2 stop
```

### فایروال میزبان

### ذخیره سازی کلیه rule های موجود iptables:

```text
# iptables-save > firewall.out
```

#### ویرایش فایل حاوی rule ها:

```text
# vi firewall.out
```

#### بارگذاری مجدد rule های iptables:

```text
# iptables-restore < firewall.out
```

#### دستورات نمونه iptables شامل محدود نمودن ip و port ها:

```text
# iptables -A INPUT -s 10.10.10.10 -j DROP
# iptables -A INPUT -s 10,10.10.0/24 -j DROP
# iptables -A INPUT -p tcp --dport ssh -s 10.10.10.10 -j DROP
# iptables -A INPUT -p tcp --dport ssh -j DROP
```

#### مسدود نمودن تمامی ارتباطات:

```text
# iptables-policy INPUT DROP
# iptables-policy OUTPUT DROP
# iptables-policy FORWARD DROP
```

#### گزارش گیری تمام rule های denied در iptables:

```text
# iptables -I INPUT 5 -m limit --limit 5/min -j LOG
--log-prefix "iptables denied: " --log-level 7
```

#### ذخیره سازی تمام rule های iptables:

**در Ubuntu:**

```text
# /etc/init.d/iptables save
# /sbin/service iptables save
```

**در RedHat یا CentOS:**

```text
# /etc/init.d/iptables save
# /sbin/iptables-save
```

#### لیست تمام rule های iptables:

```text
# iptables -L
```

#### راه اندازی مجدد rule های iptables:

```text
# iptables -F
```

####  شروع و متوقف نمودن گزارش گیری سرویس iptables:

```text
# service iptables start
# service iptables stop
```

#### شروع و متوقف نمودن گزارش گیری سرویس ufw:

```text
# ufw enable
# ufw disable
```

#### شروع و متوقف نمودن گزارش گیری ufw:

```text
# ufw logging on
# ufw logging off
```

#### تهیه نسخه پشتیبان از rule های ufw:

```text
# cp /lib/ufw/{user.rules,user6.rules} /<BACKUP
LOCATION>
# cp /lib/ufw/{user.rules,user6.rules} ./
```

#### نمونه ای از دستورات فایروال(ufw) برای محدود نموده ip و port ها:

```text
# ufw status verbose
# ufw delete <RULE#>
# ufw allow for <IP ADDRESS>
# ufw allow all 80/tcp
# ufw allow all ssh
# ufw deny from <BAD IP ADDRESS> proto udp to any
port 443
```

### کلمه عبور ها

#### تغییر کلمه عبور:

```text
$ passwd (For current user)
$ passwd bob (For user Bob)
$ sudo su passwd (For root)
```

### فایل های میزبان

#### اضافه نمودن دامنه مخرب و هدایت آن به localhost:

```text
# echo 127.0.0,1 <MALICIOUS DOMAIN> >> /etc/hosts
```

#### بررسی فایل های هاست با ارسال ping 127.0.0.1:

```text
# ping -c 1 <MALICIOUS DOMAIN>
```

#### راه اندازی مجدد DNS cache در ubuntu:

```text
# /etc/init.d/dns-clean start
```

#### 4 راه برای راه اندازی مجدد DNS cache :

```text
# /etc/init.d/nscd restart
# service nscd restart
# service nscd reload
# nscd -i hosts
```

#### راه اندازی مجدد DNS cache:

```text
# /etc/init.d/dnsmasq restart
```

### لیست سفید

#### ایجاد و استفاده از فایل Proxy Auto Config\(PAC\) برای url و ip های مشکوک:

```text
function FindProxyForURL(url, host) {
II Send bad DNS name to the proxy
if (dnsDomainis(host, ",badsite.com"))
return "PROXY http:11127.0.0.1:8080";
II Send bad IPs to the proxy
if (isinNet(myipAddress(), "222.222.222.222",
"255.255.255.0"))
return "PROXY http:11127.0.0.1:8080";
II All other traffic bypass proxy
return "DIRECT";
}
```

### دستور IPSEC

#### اجازه به فایروال برای ترافیک IPSEC:

```text
# iptables -A INPUT -p esp -j ACCEPT
# iptables -A INPUT -p ah -j ACCEPT
# iptables -A INPUT -p udp --dport 500 -j ACCEPT
# iptables -A INPUT -p udp --dport 4500 -j ACCEPT
```

#### Pass IPSEC traffic:

**مرحله 1:** نصب Racoon utility در  &lt;IP ADDRESS میزبان 1&gt;

و &lt;IP ADDRESS میزبان 2&gt; برای فعال سازی تونل IPSEC در

Ubuntu.

```text
# apt-get install racoon
```

**مرحله 2:** ویرایش /etc/ipsec­ tools.conf در &lt;IP ADDRESS میزبان 1&gt; and &lt;IP ADDRESS میزبان 2&gt; .

```text
flush;
spdflush;
spdadd <HOST1 IP ADDRESS> <HOST2 IP ADDRESS> any -P
out ipsec
esp/transport//require;
spdadd <HOST2 IP ADDRESS> <HOST1 IP ADDRESS> any -P
in ipsec
esp/transport//require;
```

**مرحله 3:** ویرایش /etc/racoon/racoon.conf در  &lt;IP ADDRESS میزبان 1&gt; و &lt;IP ADDRESS میزبان 2&gt;.

```text
log notify;
path pre_shared_key "/etc/racoon/psk.txt";
path certificate "/etc/racoon/certs";
remote anonymous {
exchange_mode main,aggressive;
proposal {
encryption_algorithm aes_256;
hash_algorithm sha256;
authentication_method
pre_shared_key;
dh_group modp1024;
}
generate_policy off;
}
sainfo anonymous{
pfs_group 2;
encryption_algorithm aes_256;
authentication_algorithm hmac_sha256;
compression_algorithm deflate;
}
```

**مرحله 4:** اضافه نمودن preshared key به دو میزبان.

#### در میزبان 1:

```text
# echo <HOST2 IP ADDRESS> <PRESHARED PASSWORD>
>>/etc/racoon/psk.txt
```

#### در میزبان 2:

```text
# echo <HOSTl IP ADDRESS> <PRESHARED PASSWORD>
>>/etc/racoon/psk.txt
```

**مرحله 5:** راه اندازی مجدد دو سیستم.

```text
# service setkey restart
```

#### برنامه پیکربندی و قوانین :

```text
# setkey -D
# setkey -DP
```
