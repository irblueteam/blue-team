# پس از حمله

## پیاده سازی

### ویندوز

#### استفاده از یک بروزرسانی Hotfix برای ویندوز 7 و یا بالا تر:

```text
C:\> wusa.exe C:\<PATH TO HOTFIX>\Windows6.0-
KB934307-x86.msu
```

#### استفاده از یک بروزرسانی Hotfix برای ویندوز 7 و یا بالا تر با استفاده از اسکریپت batch:

```text
@echo off
setlocal
set PATHTOFIXES=E:\hotfix
%PATHTOFIXES%\Q123456_w2k_sp4_x86.exe /2 /M
%PATHTOFIXES%\Ql23321_w2k_sp4_x86.exe /2 /M
%PATHTOFIXES%\Q123789_w2k_sp4_x86.exe /2 /M
```

#### بررسی بروزرسانی های ویندوز 7 و یا بالاتر:

```text
C:\> wuauclt.exe /detectnow /updatenow
```

### لینوکس

#### توزیع Ubuntu:

#### دریافت لیست بروزرسانی ها:

```text
# apt-get update
```

#### ارتقا بسته های فعلی:

```text
# apt-get upgrade
```

#### نصب بروزرسانی ها \(جدید\):

```text
# apt-get dist-upgrade
```

#### توریع Red Hat Enterprise Linux 2.1,3,4:

```text
# up2date
```

#### بروزرسانی بدون تعامل:

```text
# up2date-nox --update
```

#### نصب بسته ای با نام آن:

```text
# up2date <PACKAGE NAME>
```

#### بروزرسانی بسته ای با نام آن:

```text
# up2date -u <PACKAGE NAME>
```

#### توزیع Red Hat Enterprise Linux 5:

```text
# pup
```

#### توزیع Red Hat Enterprise Linux 6:

```text
# yum update
```

#### لیست بست های نصب شده:

```text
# yum list installed <PACKAGE NAME>
```

#### نصب بسته ای با نام آن:

```text
# yum install <PACKAGE NAME>
```

#### بروزرسانی بسته ای با نام آن:

```text
# yum update <PACKAGE NAME>
```

#### توریع Kali:

```text
# apt-get update && apt-get upgrade
```

### پشتیبان گیری

#### ویندوز

#### نسخه پشتیبان از Backup GPO Audit Policy در فایل csv:

```text
C:\> auditpol /backup /file:C\auditpolicy.csv
```

#### بازگرداندن نسخه پشتیبان GPO Audit Policy از فایل csv:

```text
C:\> auditpol /restore /file:C:\auditpolicy.csv
```

#### تهیه نسخه پشتیبان از تمامی GPO های در دامین و ذخیره آن در مسیر مشخص:

```text
PS C:\> Backup-Gpo -All -Path \\<SERVER>\<PATH TO
BACKUPS>
```

#### بازگرداندن نسخه پشتیبان GPO های در دامین و از مسیر مشخص:

```text
PS C:\> Restore-GPO -All -Domain <INSERT DOMAIN
NAME> -Path \\Serverl\GpoBackups
```

#### شروع سرویس Volume Shadow:

```text
C:\> net start VSS
```

#### لیست کلیه فایل های shadow و storage:

```text
C:\> vssadmin List ShadowStorage
```

#### لیست کلیه فایل های shadow:

```text
C:\> vssadmin List Shadows
```

#### جست و جو Shadow Copy برای فایل ها و فولدر ها:

```text
C:\> mklink /d c:\<CREATE FOLDER>\<PROVIDE FOLDER
NAME BUT DO NOT CREATE>
\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyl\
```

#### پرش به فایل shadow انتخاب شده در ویندوز سرور و ویندوز 8:

```text
C:\> vssadmin revert shadow /shadow={<SHADOW COPY
ID>} /ForceDismount
```

#### تاریخچه نسخه های قبلی فایل را با volrest.exe بازیابی کنید:

منبع. [https://www.microsoft.com/enus/](https://www.microsoft.com/enus/) download/details.aspx?id=17657

```text
C:\> "\Program Files (x86)\Windows Resource
Kits\Tools\volrest.exe" "\\localhost\c$\<PATH TO
FILE>\<FILE NAME>"
```

#### پرش به نسخه انتخاب شده از فایل یا  @GMT با استفاده از volrest.exe:

```text
C:\> subst Z: \\localhost\c$\$\<PATH TO FILE>
C:\> "\Program Files (x86)\Windows Resource
Kits\Tools\volrest.exe" "\\localhost\c$\<PATH TO
FILE>\<CURRENT FILE NAME OR @GMT FILE NAME FROM LIST
COMMAND ABOVE>" /R:Z:\
C:\> subst Z: /0
```

#### پرش به مسیر و یا زیر مسیر دیگر با استفاده از volrest.exe:

```text
C: \> "\Program Files (x86) \Windows Resource
Kits\Tools\volrest.exe" \\localhost\c$\<PATH TO
FOLDER\*·* /5 /r:\\localhost\c$\<PATH TO FOLDER>\
```

#### پرش به فایل shadow انتخاب شده در ویندوز سرور و ویندوز 7 و ویندوز 10 با استفاده از wmic:

```text
C:\> wmic shadowcopy call create Volume='C:\'
```

#### ایجاد یک کپی shadow از volume C بر روی ویندوز 7 و ویندوز 10 با استفاده از PowerShell:

```text
PS C:\> (gwmi -list
win32_shadowcopy).Create('C:\', 'ClientAccessible')
```

#### ایجاد یک shadow copy از volume C بر روی ویندوز سرور 2003 و ویندوز سرور 2008:

```text
C:\> vssadmin create shadow /for=c:
```

#### ایجاد یک نقطه بازیابی در ویندوز:

```text
C:\> wmic.exe /Namespace:\\root\default Path
SystemRestore Call CreateRestorePoint "%DATE%", 100,
7
```

#### بازیابی به نقطه بازیابی در ویندوز Windows XP:

```text
C:\> sc config srservice start= disabled
C:\> reg add
"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows
NT\CurrentVersion\SystemRestore" /v DisableSR /t
REG_DWORD /d 1 /f
C:\> net stop srservice
```

#### لیست نقاط قابل بازیابی:

```text
PS C:\> Get-ComputerRestorePoint
```

#### بازگرداندن به نقطه قابل بازیابی:

```text
PS C:\> Restore-Computer -RestorePoint <RESTORE
POINT#> -Confirm
```

### لینوکس

#### راه اندازی مجدد کلمه عبور کاربر root در حالت single user mode:

**مرحله 1:** راه اندازی مجدد سیستم.

```text
# reboot -f
```

**مرحله 2:** فشردن کلید ESC برای ورود به صفحه GRUB.

**مرحله 3:** انتخاب موجودیت پیش فرض و فشردن کلید e برای ویرایش.

**مرحله 4:** جست و جو برای خطی که آغاز آن با کلمات linux و linux16 یا linuxefi آغاز شده است.

**مرحله 5:** انتهای آن این خط 'rw init=/bin/bash' را اضافه کنید.

**مرحله 6:** فشردن کلید های ترکیبی Ctrl-X برای راه اندازی مجدد.

**مرحله 7:** بعد از راه اندازی مجدد باید در حالت  single user mode و کاربر root وارد شوید وبتوانید کلمه عبور خود را با دستور زیر تغییر دهید.

```text
# passwd
```

**مرحله 8:** راه اندازی مجدد سیستم.

```text
# reboot -f
```

#### نصب مجدد بسته ها:

```text
# apt-get install --reinstall <COMPROMISED PACKAGE
NAME>
```

#### نصب مجدد تمام بسته ها:

```text
# apt-get install --reinstall $(dpkg --getselections
lgrep -v deinstall)
```

## حذف فرآیند MALWARE

### ویندوز

#### ابزار Malware Removal:

منبع. [http://www.gmer.net/](http://www.gmer.net/)

```text
C:\> gmer.exe (GUI)
```

#### حذف فایل مشکوک در حال اجرا:

```text
C:\> gmer.exe -killfile
C:\WINDOWS\system32\drivers\<MALICIOUS FILENAME>.exe
```

#### حذف فایل مشکوک در حال اجرا در PowerShell:

```text
PS C:\> Stop-Process -Name <PROCESS NAME>
PS C:\> Stop-Process -ID <PID>
```

### لینوکس

#### توقف فرآیند malware:

```text
# kill <MALICIOUS PID>
```

#### ایجاد قابلیت اجرایی malware و تغییر مسیر آن:

```text
# chmod -x /usr/sbin/<SUSPICIOUS FILE NAME>
# mkdir /home/quarantine/
# mv /usr/sbin/<SUSPICIOUS FILE NAME>
/home/quarantine/
```
