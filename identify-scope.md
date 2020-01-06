# Identify\(Scope\)

## SCANNING AND VULNERABILITIES

### NMAP

#### Ping sweep for network:

```text
# nmap -sn -PE <IP ADDRESS OR RANGE>
```

#### Scan and show open ports:

```text
# nmap --open <IP ADDRESS OF RANGE>
```

#### Determine open services:

```text
# nmap -sV <IP ADDRESS>
```

#### Scan two common TCP ports, HTTP and HTTPS:

```text
# nmap -p 80,443 <IP ADDRESS OR RANGE>
```

#### Scan common UDP port, DNS:

```text
# nmap -sU -p 53 <IP ADDRESS OR RANGE>
```

#### Scan UDP and TCP together, be verbose on a single host and include optional skip ping:

```text
# nmap -v -Pn -SU -ST -p U:53,111,137,T:21-
25,80,139,8080 <IP ADDRESS>
```

### NESSUS

#### Basic Nessus scan:

```text
# nessus -q -x -T html <NESSUS SERVER IP ADDRESS>
<NESSUS SERVER PORT 1241> <ADMIN ACCOUNT> <ADMIN
PASSWORD> <FILE WITH TARGETS>,txt <RESULTS FILE
NAME>.html
# nessus [-vnh] [-c .refile] [-VJ [-T <format>]
```

#### Batch-mode scan:

```text
# nessus -q [-pPS] <HOST> <PORT> <USER NAME>
<PASSWORD> <targets-file> <result-file>
```

#### Report conversion:

```text
# nessus -i in. [nsrlnbe] -o
out. [xmllnsrlnbelhtmlltxt]
```

### OPENVAS

**Step 1:** Install the server, client and plugin packages:

```text
# apt-get install openvas-server openvas-client
openvas-plugins-base openvas-plugins-dfsg
```

**Step 2:** Update the vulnerability database

```text
# openvas-nvt-sync
```

**Step 3:** Add a user to run the client:

```text
# openvas-adduser
```

**Step 4:** Login: sysadm

**Step 5:** Authentication \(pass/cert\) \[pass\]: \[HIT ENTER\]

**Step 6:** Login password: 

You will then be asked to add "User rules".

**Step 7:** Allow this user to scan authorized network by typing:

```text
accept <YOUR IP ADDRESS OR RANGE>
default deny
```

**Step 8**: type ctrl-D to exit, and then accept.

**Step 9:** Start the server:

```text
# service openvas-server start
```

**Step 10:** Set targets to scan:

Create a text file with a list of hosts/networks to scan.

```text
# vi scanme.txt
```

**Step 11:** Add one host, network per line:

```text
<IP ADDRESS OR RANGE>
```

**Step 12:** Run scan:

```text
# openvas-client -q 127.0.0.1 9390 sysadm nsrc+ws
scanme.txt openvas-output-.html -T txt -V -x
```

**Step 13:** \(Optional\)run scan with HTML format:

```text
# openvas-client -q 127.0.0.1 9390 sysadm nsrc+ws
scanme.txt openvas-output.txt -T html -V -x
```

## WINDOWS

### NETWORK DISCOVERY

#### Basic network discovery:

```text
C:> net view /all
C:> net view \\<HOST NAME>
```

#### Basic ping scan and write output to file:

```text
C:\> for /L %I in (1,1,254) do ping -w 30 -n 1
192.168. l.%I I find "Reply" >> <OUTPUT FILE
NAME>.txt
```

### DHCP

#### Enable DHCP server logging:

```text
C:\> reg add
HKLM\System\CurrentControlSet\Services\DhcpServer\Pa
rameters /v ActivityLogFlag /t REG_DWORD /d 1
```

#### **Default Location Windows 2003/2008/2012:**

```text
C:> %windir%\System32\Dhcp
```

### DNS

#### Default location Windows 2003:

```text
C:\> %SystemRoot%\System32\Dns
```

#### Default location Windows 2008:

```text
C:\> %SystemRoot%\System32\Winevt\Logs\DNS
Server. evtx
```

#### Default location of enhanced DNS Windows 2012 R2:

```text
C:\> %SystemRoot%\System32\Winevt\Logs\Microsoft­
Windows-DNSServer%4Analytical.etl
```

Ref. [https://technet.microsoft.com/en­](https://technet.microsoft.com/en­) us/library/cc940779.aspx

#### Enable DNS Logging:

```text
C:\> DNSCmd <DNS SERVER NAME> /config /logLevel
0x8100F331
```

#### Set log location:

```text
C:\> DNSCmd <DNS SERVER NAME> /config /LogFilePath
<PATH TO LOG FILE>
```

#### Set size of log file:

```text
C:\> DNSCmd <DNS SERVER NAME> /config
/logfilemaxsize 0xffffffff
```

### HASHING

#### File Checksum Integrity Verifier \(FCIV\):

Ref. [http://support2.microsoft.com/kb/841290](http://support2.microsoft.com/kb/841290)

#### Hash a file:

```text
C:\> fciv.exe <FILE TO HASH>
```

#### Hash all files on C: into a database file:

```text
C:\> fciv.exe c:\ -r -mdS -xml <FILE NAME>.xml
```

#### List all hashed files:

```text
C:\> fciv.exe -list -shal -xml <FILE NAME>.xml
```

#### Verify previous hashes in db with file system:

```text
C:\> fciv.exe -v -shal -xml <FILE NAME>.xml
```

#### Note: May be possible to create a master db and compare to all systems from a cmd line. Fast baseline and difference.

Ref. [https://technet.microsoft.com/en­](https://technet.microsoft.com/en­) us/library/dn520872.aspx

```text
PS C:\> Get-FileHash <FILE TO HASH> I Format-List
PS C:\> Get-FileHash -algorithm md5 <FILE TO HASH>
C:\> certutil -hashfile <FILE TO HASH> SHAl
C:\> certutil -hashfile <FILE TO HASH> MD5
```

### NETBIOS

#### Basic nbtstat scan:

```text
C:\> nbtstat -A <IP ADDRESS>
```

#### Cached NetBIOS info on localhost:

```text
C:> nbtstat -c
```

#### Script loop scan:

```text
C:\> for /L %I in (1,1,254) do nbstat -An
192.168.l.%I
```

### USER ACTIVITY

Ref. [https://technet.microsoft.com/en­](https://technet.microsoft.com/en­) us/sysinternals/psloggedon.aspx

#### Get users logged on:

```text
C:\> psloggedon \\computername
```

#### Script loop scan:

C:&gt; for /L %i in \(1,1,254\) do psloggedon \192.168.l.%i &gt;&gt; C:\users\_output.txt

### PASSWORDS

#### Password guessing or checks:

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

### MICROSOFT BASELINE SECURITY ANALYZER \(MBSA\)

#### Basic scan of a target IP address:

```text
C:\> mbsacli.exe /target <TARGET IP ADDRESS> /n
os+iis+sql+password
```

#### Basic scan of a target IP range:

```text
C:\> mbsacli.exe /r <IP ADDRESS RANGE> /n
os+iis+sql+password
```

#### Basic scan of a target domain:

```text
C:\> mbsacli.exe /d <TARGET DOMAIN> /n
os+iis+sql+password
```

#### Basic scan of a target computer names in text file:

```text
C:\> mbsacli.exe /listfile <LISTNAME OF COMPUTER
NAMES>.txt /n os+iis+sql+password
```

### ACTIVE DIRECTORY INVENTORY

#### List all OUs:

```text
C:\> dsquery ou DC=<DOMAIN>,DC=<DOMAIN EXTENSION>
```

#### List of workstations in the domain:

```text
C:\> netdom query WORKSTATION
```

#### List of servers in the domain:

```text
C:\> netdom query SERVER
```

#### List of domain controllers:

```text
C:\> netdom query DC
```

#### List of organizational units under which the specified user can create a machine object:

```text
C:\> netdom query OU
```

#### List of primary domain controller:

```text
C:\> netdom query PDC
```

#### List the domain trusts:

```text
C:\> netdom query TRUST
```

#### Query the domain for the current list of FSMO owners

```text
C:\> netdom query FSMO
```

#### List all computers from Active Directory:

```text
C:\> dsquery COMPUTER "OU=servers,DC=<DOMAIN
NAME>,DC=<DOMAIN EXTENSION>" -o rdn -limit 0 >
C:\machines.txt
```

#### List user accounts inactive longer than 3 weeks:

```text
C:\> dsquery user domainroot -inactive 3
```

#### Find anything \(or user\) created on date in UTC using timestamp format YYYYMMDDHHMMSS.sZ:

```text
C:\> dsquery * -filter
"(whenCreated>=20101022083730,0Z)"
C:\> dsquery * -filter
"((whenCreated>=20101022083730.0Z)&(objectClass=user
) ) II
```

#### **Alt option:**

```text
C:\> ldifde -d ou=<OU NAME>,dC=<DOMAIN
NAME>,dc=<DOMAIN EXTENSION> -l whencreated,
whenchanged -p onelevel -r "(ObjectCategory=user)" -
f <OUTPUT FILENAME>
```

**The last logon timestamp format in UTC: YYYYMMDDHHMMSS**

**Alt option:**

```text
C:\> dsquery * dc=<DOMAIN NAME>,dc=<DOMAIN
EXTENSION> -filter "(&(objectCategory=Person)
(objectClass=User)(whenCreated>=20151001000000.0Z))"
```

**Alt option:**

```text
C:\> adfind -csv -b dc=<DOMAIN NAME>,dc=<DOMAIN
EXTENSION> -f "(&(objectCategory=Person)
(objectClass=User)(whenCreated>=20151001000000.0Z))"
```

#### Using PowerShell, dump new Active Directory accounts in last 90 Days:

```text
PS C:\> import-module activedirectory
PS C:\> Get-QADUser -CreatedAfter (Get­
Date).AddDays(-90)
PS C:\> Get-ADUser -Filter * -Properties whenCreated
I Where-Object {$_.whenCreated -ge ((Get­
Date).AddDays(-90)).Date}
```

## LINUX

### NETWORK DISCOVERY

#### Net view scan:

```text
# smbtree -b
# smbtree -D
# smbtree -5
```

#### View open 5MB shares:

```text
# smbclient -L <HOST NAME>
# smbstatus
```

#### Basic ping scan:

```text
# for ip in $(seq 1 254); do ping -c 1
192.168.1.$ip>/dev/null; [ $? -eq 0 ] && echo
"192.168.1. $ip UP" || : ; done
```

### DHCP

#### View DHCP lease logs:

#### **Red Hat 3:**

```text
# cat /var/lib/dhcpd/dhcpd. leases
```

**Ubuntu:**

```text
# grep -Ei 'dhcp' /var/log/syslog.1
```

Ubuntu DHCP logs:

```text
# tail -f dhcpd. log
```

### DNS

#### Start DNS logging:

```text
rndc querylog
```

#### View DNS logs:

```text
# tail -f /var/log/messages I grep named
```

### HASHING

#### Hash all executable files in these specified locations:

```text
# find /<PATHNAME TO ENUMERATE> -type f -exec mdSsum
{} >> mdSsums.txt \;
# mdSdeep -rs /> mdSsums.txt
```

### NETBIOS

#### Basic nbtstat scan:

```text
nbtscan <IP ADDRESS OR RANGE>
```

### PASSWORDS

#### Password and username guessing or checks:

```text
while read line; do username=$line; while read
line; do smbclient -L <TARGET IP ADDRESS> -U
$username%$line -g -d 0; echo $username:$line;
done<<PASSWORDS>.txt;done<<USER NAMES>.txt
```

