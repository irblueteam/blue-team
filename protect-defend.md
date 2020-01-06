# Protect\(Defend\)

## WINDOWS

### DISABLE/STOP SERVICES

#### Get a list of services and disable or stop:

```text
C:\> sc query
C:\> sc config "<SERVICE NAME>" start= disabled
C:\> sc stop "<SERVICE NAME>"
C:\> wmic service where name='<SERVICE NAME>' call
ChangeStartmode Disabled
```

### HOST SYSTEM FIREWALLS

#### Show all rules:

```text
C:\> netsh advfirewall firewall show rule name=all
```

#### Set firewall on/off:

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

#### Set firewall rules examples:

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

#### Setup togging location:

```text
C:\> netsh advfirewall set currentprofile logging
C:\<LOCATION>\<FILE NAME>
```

#### Windows firewall tog location and settings:

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

#### Display firewall logs:

```text
PS C:\> Get-Content
$env:systemroot\system32\LogFiles\Firewall\pfirewall
. log
```

### PASSWORDS

#### Change password:

```text
C:\> net user <USER NAME> * /domain
C:\> net user <USER NAME> <NEW PASSWORD>
```

### Change password remotely:

Ref. [https://technet.microsoft.com/en­](https://technet.microsoft.com/en­) us/sysinternals/bb897543 

```text
C:\> pspasswd.exe \\<IP ADDRESS or NAME OF REMOTE
COMPUTER> -u <REMOTE USER NAME> -p <NEW PASSWORD>
```

#### Change password remotely:

```text
PS C:\> pspasswd.exe \\<IP ADDRESS or NAME OF REMOTE
COMPUTER>
```

### HOST FILE

#### Flush DNS of malicious domain/IP:

```text
C:\> ipconfig /flushdns
```

#### Flush NetBios cache of host/IP:

```text
C:\> nbtstat -R
```

#### Add new malicious domain to hosts file, and route to localhost:

```text
C:\> echo 127.0.0.1 <MALICIOUS DOMAIN> >>
C:\Windows\System32\drivers\etc\hosts
```

#### Check if hosts file is working, by sending ping to 127.0.0.1:

```text
C:\> ping <MALICIOUS DOMAIN> -n 1
```

### WHITELIST

#### Use a Proxy Auto Config\(PAC\) file to create Bad URL or IP List \(IE, Firefox, Chrome\):

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

### APPLICATION RESTRICTIONS

#### Applocker - Server 2008 R2 or Windows 7 or higher: Using GUI Wizard configure:

* Executable Rules \(. exe, . com\)
* DLL Rules \( .dll, .ocx\)
* Script Rules \(.psl, .bat, .cmd, .vbs, .js\)
* Windows Install Rules \( .msi, .msp, .mst\)

#### Steps to employ Applocker \(GUI is needed for digital signed app restrictions\):

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

#### Add the Applocker cmdlets into PowerShell:

```text
PS C:\> import-module Applocker
```

#### Gets the file information for all of the executable files and scripts in the directory C:\Windows\System32:

```text
PS C:\> Get-ApplockerFileinformation -Directory
C:\Windows\System32\ -Recurse -FileType Exe, Script
```

#### Create a Applocker Policy that allow rules for all of the executable files in C:\Windows\System32:

```text
PS C:\> Get-ApplockerFileinformation -Directory
C:\Windows\System32\ -Recurse -FileType Exe, Script
```

#### Create a Applocker Policy that allow rules for all of the executable files in C:\Windows\System32:

```text
PS C:\> Get-Childitem C:\Windows\System32\*,exe I
Get-ApplockerFileinformation I New-ApplockerPolicy -
RuleType Publisher, Hash -User Everyone -
RuleNamePrefix System32
```

#### Sets the local Applocker policy to the policy specified in C:\Policy.xml:

```text
PS C:\> Set-AppLockerPolicy -XMLPolicy C:\Policy.xml
```

#### Uses the Applocker policy in C:\Policy.xml to test whether calc.exe and notepad.exe are allowed to run for users who are members of the Everyone group. If you do not specify a group, the Everyone group is used by default:

```text
PS C:\> Test-AppLockerPolicy -XMLPolicy
C:\Policy.xml -Path C:\Windows\System32\calc.exe,
C:\Windows\System32\notepad.exe -User Everyone
```

#### Review how many times a file would have been blocked from running if rules were enforced:

```text
PS C:\> Get-ApplockerFileinformation -Eventlog -
Logname "Microsoft-Windows-Applocker\EXE and DLL" -
EventType Audited -Statistics
```

#### Creates a new Applocker policy from the audited events in the local Microsoft-Windows-Applocker/EXE and DLL event log, applied to  and current Applocker policy will be overwritten:

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

#### Export the local Applocker policy, comparing User's explicitly denied access to run, and output text file:

```text
PS C:\> Get-AppLockerPolicy -Local I Test­
AppLockerPolicy -Path C:\Windows\System32\*,exe -
User domain\<USER NAME> -Filter Denied I Format-List
-Property Path > C:\DeniedFiles.txt
```

#### Export the results of the test to a file for analysis:

```text
PS C:\> Get-Childitem <DirectoryPathtoReview> -
Filter <FileExtensionFilter> -Recurse I Convert-Path
I Test-ApplockerPolicy -XMLPolicy
<PathToExportedPolicyFile> -User <domain\username> -
Filter <TypeofRuletoFilterFor> I Export-CSV
<PathToExportResultsTo.CSV>
```

#### GridView list of any local rules applicable:

```text
PS C:\> Get-AppLockerPolicy -Local -Xml I Out­-GridView
```

### IPSEC

#### Create a IPSEC Local Security Policy, applied to any connection, any protocol, and using a preshared key:

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

#### Add rule to allow web browsing port 80\(HTTP\) and 443\(HTTPS\) over IPSEC:

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

#### Shows the IPSEC Local Security Policy with name "MyIPsecPolicy":

```text
C:\> netsh ipsec static show policy
name=MyIPsecPolicy
```

#### Stop or Unassign a IPSEC Policy:

```text
C:\> netsh ipsec static set policy
name=MyIPsecPolicy
```

#### Create a IPSEC Advance Firewall Rule and Policy and preshared key from and to any connections:

```text
C:\> netsh advfirewall consec add rule name= u IPSEC"
endpointl=any endpoint2=any
action=requireinrequireout qmsecmethods=default
```

#### Require IPSEC preshared key on all outgoing requests:

```text
C:\> netsh advfirewall firewall add rule
name= u IPSEC_Out" dir=out action=allow enable=yes
profile=any localip=any remoteip=any protocol=any
interfacetype=any security=authenticate
```

#### Create a rule for web browsing:

```text
C:\> netsh advfirewall firewall add rule name="Allow
Outbound Port 80 11 dir=out localport=80 protocol=TCP
action=allow
```

#### Create a rule for DNS:

```text
C:\> netsh advfirewall firewall add rule name="Allow
Outbound Port 53 11 dir=out localport=53 protocol=UDP
action=allow
```

#### Delete ISPEC Rule:

```text
C:\> netsh advfirewall firewall delete rule
name="IPSEC_RULE"
```

### ACTIVE DIRECTORY \(AD\) - GROUP POLICY OBJECT \(GPO\)

#### Get and force new policies:

```text
C:\> gpupdate /force
C:\> gpupdate /sync
```

#### Audit Success and Failure for user Bob:

```text
C:> auditpol /set /user:bob /category:"Detailed
Tracking" /include /success:enable /failure:enable
```

#### Create an Organization Unit to move suspected or infected users and machines:

```text
C:\> dsadd OU <QUARANTINE BAD OU>
```

#### Move an active directory user object into NEW GROUP:

```text
PS C:\> Move-ADObject 'CN=<USER NAME>,CN=<OLD USER
GROUP>,DC=<OLD DOMAIN>,DC=<OLD EXTENSION>' -
TargetPath 'OU=<NEW USER GROUP>,DC=<OLD
DOMAIN>,DC=<OLD EXTENSION>'
```

**Alt Option:**

```text
C:\> dsmove "CN=<USER NAME>,OU=<OLD USER OU>,DC=<OLD
DOMAIN>,DC=<OLD EXTENSION>" -newparent OU=<NEW USER
GROUP>,DC=<OLD DOMAIN>,DC=<OLD EXTENSION>
```

### STAND ALONE SYSTEM - WITHOUT ACTIVE DIRECTORY \(AD\)

#### Disallow running a .exe file:

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

#### Disable Remote Desktop:

```text
C:\> reg add
"HKLM\SYSTEM\Cu rrentCont ro lSet\Cont ro l \ Terminal
Server" /f /v fDenyTSConnections /t REG_DWORD /d 1
```

#### Send NTLMv2 response only/refuse LM and NTLM: \(Windows 7 default\)

```text
C:\> reg add
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v
lmcompatibilitylevel /t REG_DWORD /d 5 /f
```

#### Restrict Anonymous Access:

```text
C:\> reg add
HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v
restrictanonymous /t REG_DWORD /d 1 /f
```

#### Do not allow anonymous enumeration of SAM accounts and shares:

```text
C:\> reg add
HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v
restrictanonymoussam /t REG_DWORD /d 1 /f
```

#### Disable IPV6:

```text
C:\> reg add
HKLM\SYSTEM\CurrentControlSet\services\TCPIP6\Parame
ters /v DisabledComponents /t REG_DWORD /d 255 /f
```

#### Disable sticky keys:

```text
C:\> reg add "HKCU\Control
Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ
/d 506 /f
```

#### Disable Toggle Keys:

```text
C:\> reg add "HKCU\Control
Panel \Accessibility\ ToggleKeys" /v Flags /t REG_SZ
Id 58 /f
```

#### Disable Filter Keys:

```text
C:\> reg add "HKCU\Control
Panel\Accessibility\Keyboard Response" /v Flags /t
REG_SZ /d 122 /f
```

#### Disable On-screen Keyboard:

```text
C:\> reg add
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI 
/f /v ShowTabletKeyboard /t REG_DWORD /d 0
```

#### Disable Administrative Shares - Workstations:

```text
C:\> reg add
HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\
Parameters /f /v AutoShareWks /t REG_DWORD /d 0
```

#### Disable Administrative Shares - Severs

```text
C:\> reg add
HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\
Parameters /f /v AutoShareServer /t REG_DWORD /d 0
```

#### Remove Creation of Hashes Used to Pass the Hash Attack \(Requires password reset and reboot to purge old hashes\):

```text
C:\> reg add
HKLM\SYSTEM\CurrentControlSet\Control\Lsa /f /v
NoLMHash /t REG_DWORD /d 1
```

#### To Disable Registry Editor: \(High Risk\)

```text
C:\> reg add
HKCU\Software\Microsoft\Windows\CurrentVersion\Polic
ies\System /v DisableRegistryTools /t REG_DWORD /d 1
/f
```

#### Disable IE Password Cache:

```text
C:\> reg add
HKCU\Software\Microsoft\Windows\CurrentVersion\Inter
net Settings /v DisablePasswordCaching /t REG_DWORD
/d 1 /f
```

#### Disable CMD prompt:

```text
C:\> reg add
HKCU\Software\Policies\Microsoft\Windows\System /v
DisableCMD /t REG_DWORD /d 1 /f
```

#### Disable Admin credentials cache on host when using RDP:

```text
C:\> reg add
HKLM\System\CurrentControlSet\Control\Lsa /v
DisableRestrictedAdmin /t REG_DWORD /d 0 /f
```

#### Do not process the run once list:

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

#### Require User Access Control \(UAC\) Permission:

```text
C:\> reg add
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Polic
ies\System /v EnableLUA /t REG_DWORD /d 1 /f
```

#### Require User Access Control \(UAC\) Permission:

```text
C:\> reg add
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Polic
ies\System /v EnableLUA /t REG_DWORD /d 1 /f
```

#### Change password at next logon:

```text
PS C:\> Set-ADAccountPassword <USER> -NewPassword
$newpwd -Reset -PassThru I Set-ADuser -
ChangePasswordAtLogon $True
```

#### Change password at next logon for OU Group:

```text
PS C:\> Get-ADuser -filter "department -eq '<OU GROUP>' -AND enabled -eq 'True'" | Set-ADuser - ChangePasswordAtLoggon $True
```

#### Enabled Firewall logging:

```text
C:\> netsh firewall set logging droppedpackets
connections = enable
```

## LINUX

### DISABLE/STOP SERVICES

#### Services information:

```text
# service --status-all
# ps -ef
# ps -aux
```

#### Get a list of upstart jobs:

```text
# initctl list
```

#### Example of start, stop, restarting a service in 

#### Ubuntu:

```text
# /etc/init,d/apache2 start
# /etc/init.d/apache2 restart
# /etc/init.d/apache2 stop (stops only until reboot)
# service mysql start
# service mysql restart
# service mysql stop (stops only until reboot)
```

#### List all Upstart services:

```text
# ls /etc/init/*,conf
```

#### Show if a program is managed by upstart and the process ID:

```text
# status ssh
```

#### If not managed by upstart:

```text
# update-rc.d apache2 disable
# service apache2 stop
```

### HOST SYSTEM FIREWALLS

### Export existing iptables firewall rules:

```text
# iptables-save > firewall.out
```

#### Edit firewall rules and chains in firewall.out and save the file:

```text
# vi firewall.out
```

#### Apply iptables:

```text
# iptables-restore < firewall.out
```

#### Example iptables commands \(IP, IP Range, Port Blocks\):

```text
# iptables -A INPUT -s 10.10.10.10 -j DROP
# iptables -A INPUT -s 10,10.10.0/24 -j DROP
# iptables -A INPUT -p tcp --dport ssh -s 10.10.10.10 -j DROP
# iptables -A INPUT -p tcp --dport ssh -j DROP
```

#### Block all connections:

```text
# iptables-policy INPUT DROP
# iptables-policy OUTPUT DROP
# iptables-policy FORWARD DROP
```

#### Log all denied iptables rules:

```text
# iptables -I INPUT 5 -m limit --limit 5/min -j LOG
--log-prefix "iptables denied: " --log-level 7
```

#### Save all current iptables rules:

**Ubuntu:**

```text
# /etc/init.d/iptables save
# /sbin/service iptables save
```

**RedHat / CentOS:**

```text
# /etc/init.d/iptables save
# /sbin/iptables-save
```

#### List all current iptables rules:

```text
# iptables -L
```

#### Flush all current iptables rules:

```text
# iptables -F
```

#### Start/Stop iptables service:

```text
# service iptables start
# service iptables stop
```

#### Start/Stop ufw service:

```text
# ufw enable
# ufw disable
```

#### Start/Stop ufw logging:

```text
# ufw logging on
# ufw logging off
```

#### Backup all current ufw rules:

```text
# cp /lib/ufw/{user.rules,user6.rules} /<BACKUP
LOCATION>
# cp /lib/ufw/{user.rules,user6.rules} ./
```

#### Example uncomplicated firewall \(ufw\) Commands \(IP, IP range, Port blocks\):

```text
# ufw status verbose
# ufw delete <RULE#>
# ufw allow for <IP ADDRESS>
# ufw allow all 80/tcp
# ufw allow all ssh
# ufw deny from <BAD IP ADDRESS> proto udp to any
port 443
```

### PASSWORDS

#### Change password:

```text
$ passwd (For current user)
$ passwd bob (For user Bob)
$ sudo su passwd (For root)
```

### HOST FILE

#### Add new malicious domain to hosts file, and route to localhost:

```text
# echo 127.0.0,1 <MALICIOUS DOMAIN> >> /etc/hosts
```

#### Check if hosts file is working, by sending ping to 127.0.0.1:

```text
# ping -c 1 <MALICIOUS DOMAIN>
```

#### Ubuntu/Debian DNS cache flush:

```text
# /etc/init.d/dns-clean start
```

#### Flush nscd DNS cache four ways:

```text
# /etc/init.d/nscd restart
# service nscd restart
# service nscd reload
# nscd -i hosts
```

#### Flush dnsmasq DNS cache:

```text
# /etc/init.d/dnsmasq restart
```

### WHITELIST

#### Use a Proxy Auto Config\(PAC\) file to create bad URL or IP List:

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

### IPSEC

#### Allow firewall to pass IPSEC traffic:

```text
# iptables -A INPUT -p esp -j ACCEPT
# iptables -A INPUT -p ah -j ACCEPT
# iptables -A INPUT -p udp --dport 500 -j ACCEPT
# iptables -A INPUT -p udp --dport 4500 -j ACCEPT
```

#### Pass IPSEC traffic:

**Step 1:** Install Racoon utility on  &lt;HOST1 IP ADDRESS&gt;

and &lt;HOST2 IP ADDRESS&gt; to enable IPSEC tunnel in

Ubuntu.

```text
# apt-get install racoon
```

**Step 2:** Choose direct then edit /etc/ipsec­ tools.conf on &lt;HOST1 IP ADDRESS&gt; and &lt;HOST2 IP ADDRESS&gt; .

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

**Step 3:** Edit /etc/racoon/racoon.conf on  &lt;HOST1 IP ADDRESS&gt; and &lt;HOST2 IP ADDRESS&gt;.

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

**Step 4:** Add preshared key to both hosts.

#### On HOST1:

```text
# echo <HOST2 IP ADDRESS> <PRESHARED PASSWORD>
>>/etc/racoon/psk.txt
```

#### On HOST2:

```text
# echo <HOSTl IP ADDRESS> <PRESHARED PASSWORD>
>>/etc/racoon/psk.txt
```

**Step 5:** Restart service on both systems.

```text
# service setkey restart
```

#### Check security associations, configuration and polices:

```text
# setkey -D
# setkey -DP
```

