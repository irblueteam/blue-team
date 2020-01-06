# Tactics\(Tips & Tricks\)

## OS CHEATS

### WINDOWS

#### Pipe output to clipboard:

```text
C:\> some_command.exe I clip
```

#### Output clip to file: \(Requires PowerShell 5\)

```text
PS C:\> Get-Clipboard> clip.txt
```

#### Add time stamps into log file:

```text
C:\> echo %DATE% %TIME%>> <TXT LOG>,txt
```

#### Add/Modify registry value remotely:

```text
C:\> reg add \\<REMOTE COMPUTER
NAME>\HKLM\Software\<REG KEY INFO>
```

#### Get registry value remotely:

```text
C:\> reg query \\<REMOTE COMPUTER
NAME>\HKLM\Software\<REG KEY INFO>
```

#### Test to see if Registry Path exists:

```text
PS C:\> Test-Path "HKCU:\Software\Microsoft\<HIVE>"
```

#### Copy files remotely:

```text
C:\> robocopy C:\<SOURCE SHARED FOLDER>
\\<DESTINATION COMPUTER>\<DESTINATION FOLDER> /E
```

#### Check to see if certain file extensions are in a directory:

```text
PS C:\> Test-Path C:\Scripts\Archive\* -include
*·PSl, *,VbS
```

#### Show contents of a file:

```text
C:\> type <FILE NAME>
```

#### Combine contents of multiple files:

```text
C:\> type <FILE NAME 1> <FILE NAME 2> <FILE NAME 3>
> <NEW FILE NAME>
```

#### Desktops, allows multiple Desktop Screens:

Ref. [https://technet.microsoft.com/enus/](https://technet.microsoft.com/enus/) sysinternals/cc817881

#### Run live option:

```text
C:\> "%ProgramFiles%\Internet Explorer\iexplore.exe
"https://live.sysinternals.com/desktops.exe
```

#### Remote mounting, Read and Read/Write:

```text
C:\> net share MyShare_R=c:\<READ ONLY FOLDER>
/GRANT:EVERYONE,READ
C:\> net share MyShare_RW=c:\<READ/WRITE FOLDER>
/GRANT:EVERYONE,FULL
```

#### Remote task execution using PSEXEC:

Ref. [https://technet.microsoft.com/enus/](https://technet.microsoft.com/enus/) sysinternals/psexec.aspx

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

#### Remote task execution and send output to share:

```text
C:\> wmic /node:ComputerName process call create
ucmd,exe /c netstat -an > \\<REMOTE SHARE>\<OUTPUT
FILE NAME>,txt"
```

#### Compare two files for changes:

```text
PS C:\> Compare-Object (Get-Content ,<LOG FILE NAME
l>, log) -DifferenceObject (Get-Content .<LOG FILE
NAME 2>,log)
```

#### Remote task execution using PowerShell:

```text
PS C:\> Invoke-Command -<COMPUTER NAME> {<PS
COMMAND>}
```

#### PowerShell Command Help:

```text
PS C:\> Get-Help <PS COMMAND> -full
```

### LINUX

#### Analyze traffic remotely over ssh:

```text
# ssh root@<REMOTE IP ADDRESS OF HOST TO SNIFF>
tcpdump -i any -U -s 0 -w - 'not port 22'
```

#### Manually add note/data to syslog:

```text
# logger usomething important to note in Log"
# dmesg I grep <COMMENT>
```

#### Simple read only mounting:

```text
# mount -o ro /dev/<YOUR FOLDER OR DRIVE> /mnt
```

#### Mounting remotely over SSH:

```text
# apt-get install sshfs
# adduser <USER NAME> fuse
Log out and log back in.
mkdir 󰁝/<WHERE TO MOUNT LOCALLY>
# sshfs <REMOTE USER NAME>@<REMOTE HOST>:/<REMOTE
PATH> 󰁝/<WHERE TO MOUNT LOCALLY>
```

#### Creating SMB share in Linux:

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

#### Visit share from remote system:

```text
> smb:\\<IP ADDRESS OF LINUX SMB SHARE>
```

#### Copy files to remote system:

```text
> scp <FILE NAME> <USER NAME>@<DESTINATION IP
ADDRESS>:/<REMOTE FOLDER>
```

#### Mount and SMB share to remote system:

```text
# mount -t smbfs -o username=<USER NAME> //<SERVER
NAME OR IP ADDRESS>/<SHARE NAME> /mnt/<MOUNT POINT>/
```

#### Monitor a website or file is still up/there:

```text
#while :; do curl -sSr http://<URL> I head -n 1;
sleep 60; done
```

method 2\([reference](https://unix.stackexchange.com/questions/84814/health-check-of-web-page-using-curl)\):

```text
for i in `curl -s -L cnn.com |egrep --only-matching "http(s?):\/\/[^ \"\(\)\<\>]*" | uniq` ;
do curl -s -I $i 2>/dev/null |head -n 1 | cut -d$' ' -f2; sleep 60; done
```

## DECODING

### HEX CONVERSION

#### Convert from hex to decimal in Windows:

```text
C:\> set /a 0xff
255
PS C:\> 0xff
255
```

#### Other Basic Math in Windows:

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

#### Decode Base64 text in a file:

```text
C:\> certutil -decode <BASE64
<DECODED FILE NAME>
```

#### Decode XOR and search for http:

Ref, [https://blog.didierstevens.com/programs/xorsearch/](https://blog.didierstevens.com/programs/xorsearch/)

```text
C:\> xorsearch,exe -i -s <INPUT FILE NAME> http
```

#### Convert from hex to decimal in Linux:

```text
# echo u0xff"lwcalc -d
= 255
```

#### Convert from decimal to hex in Linux:

```text
$ echo u25s"1wcalc -h
= 0xff
```

#### Decode HTML Strings:

```text
PS C:\> Add-Type -AssemblyName System.Web
PS C:\>
[System.Uri] ::UnescapeDataString("HTTP%3a%2f%2fHello
%20World.com")
HTTP://Hello World.com
```

## SNORT

### SNORT RULES

#### Snort Rules to detect Meterpreter traffic:

Ref. [https://blog.didierstevens.com/2015/06/16/metasploit](https://blog.didierstevens.com/2015/06/16/metasploit) -meterpreter-reverse-https-snort-rule/

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

#### Snort Rules to detect PSEXEC traffic:

Ref. [https://github.com/John-Lin/dockersnort/](https://github.com/John-Lin/dockersnort/) blob/master/snortrules-snapshot- 2972/rules/policy-other.rules

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

## DOS/DDOS

### FINGERPRINT DOS/DDOS

#### Fingerprinting the type of DoS/DDoS:

Ref. [https://www.trustwave.com/Resources/SpiderLabsBlog/](https://www.trustwave.com/Resources/SpiderLabsBlog/) PCAP-Files-Are-Great-Arn-t-They--/ 

**Volumetric:** Bandwidth consumption Example, sustaining sending 1Gb of traffic to 10Mb connection 

Ref. [http://freecode.com/projects/iftop](http://freecode.com/projects/iftop)

```text
# iftop -n
```

**and Protocol:** Use of specific protocol 

Example, SYN Flood, ICMP Flood, UDP flood

```text
# tshark -r <FILE NAME>,pcap -q -z io,phs
# tshark -c 1000 -q -z io,phs
# tcpdump -tn r $FILE I awk -F '. ' '{print
$1","$2"."$3","$4}' I sort I uniq -c I sort -n I
tail
# tcpdump -qnn "tcp[tcpflags] & (tcp-syn) != 0"
# netstat -s
```

Example, isolate one protocol and or remove other protocols

```text
# tcpdump -nn not arp and not icmp and not udp
# tcpdump -nn tcp
```

**Resource:** State and connection exhaustion 

Example, Firewall can handle 10,000 simultaneous connections, and attacker sends 20,000

```text
# netstat -n I awk '{print $6}' I sort I uniq -c
sort -nr I head
```

**Application:** Layer 7 attacks

Example, HTTP GET flood, for a large image file.

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

#### Example, look for excessive file requests, GIF, ZIP, JPEG, PDF, PNG.

```text
# tshark -Y "http contains "ff:d8"" | "http
contains "GIF89a"" || "http contains
" \x50\x4B\x03\x04"" || "http contains\xff\xd8" " ||
"http contains "%PDF"" || "http contains
"\x89\x50\x4E\x47""
```

#### Example, Look for web application 'user-agent' pattern of abuse.

```text
# tcpdump -c 1000 -Ann I grep -Ei 'user-agent'
sort I uniq -c I sort -nr I head -10
```

#### Example, show HTTP Header of requested resources.

```text
# tcpdump -i en0 -A -s 500 I grep -i refer
```

#### Sniff HTTP Headers for signs of repeat abuse:

```text
# tcpdump -s 1024 -l -A dst <EXAMPLE.COM>
```

**Poison:** Layer 2 attacks

Example, ARP poison, race condition DNS, DHCP

```text
# tcpdump 'arp or icmp'
# tcpdump -tnr <SAMPLE TRAFFIC FILE>.pcap ARP lawk -
F ',' '{print $1"."$2","$3","$4}' I sort I uniq -c
sort -n I tail
# tshark -r <SAMPLE TRAFFIC FILE>.pcap -q -z io,phsl
grep arp.duplicate-address-detected
```

## TOOL SUITES

### PREBUILT ISO, VIRTUAL MACHINE AND DISTRIBUTIONS

#### KALI - Open Source Pentesting Distribution

Ref. [https://www.kali.org](https://www.kali.org)

#### SIFT - SANS Investigative Forensics Toolkit

Ref. [http://sift.readthedocs.org/](http://sift.readthedocs.org/)

#### REMNUX - A Linux Toolkit for Reverse-Engineering and Analyzing Malware

Ref. [https://remnux.org](https://remnux.org)

#### OPEN VAS - Open Source vulnerability scanner and manager

Ref. [http://www.openvas.org](http://www.openvas.org)

#### MOLOCH - Large scale IPv4 packet capturing \(PCAP\), indexing and database system

Ref. [https://github.com/aol/moloch/wiki](https://github.com/aol/moloch/wiki)

#### SECURITY ONION - Linux distro for intrusion detection, network security monitoring, and log management

Ref. [https://security-onionsolutions](https://security-onionsolutions). github.io/security-onion/

#### NAGIOS - Network Monitoring, Alerting, Response, and Reporting Tool

Ref. [https://www.nagios.org](https://www.nagios.org)

#### OSSEC - Scalable, multi-platform, open source Hostbased Intrusion Detection System

Ref. [http://ossec.github.io](http://ossec.github.io)

#### SAMURAI WTF - Pre-configured web pen-testing environment

Ref. [http://samurai.inguardians.com](http://samurai.inguardians.com)

#### RTIR - Request Tracker for Incident Response

Ref. [https://www.bestpractical.com/rtir/](https://www.bestpractical.com/rtir/)

#### HONEYDRIVE - Pre-configured honeypot software packages

Ref. [http://sourceforge.net/projects/honeydrive/](http://sourceforge.net/projects/honeydrive/)

#### The Enhanced Mitigation Experience Toolkit - helps prevent vulnerabilities in software from being successfully exploited

Ref. [https://support.microsoft.com/en-us/kb/2458544](https://support.microsoft.com/en-us/kb/2458544)

#### ATTACK SURFACE ANALYZER BY MICROSOFT - Baseline Tool

Ref. [https://www.microsoft.com/enus/](https://www.microsoft.com/enus/) download/confirmation.aspx?id=24487

#### WINDOWS TO GO - USB Portable Windows 8

Ref. [https://technet.microsoft.com/enus/](https://technet.microsoft.com/enus/) library/hh831833.aspx

#### WINFE - Windows Forensic Environment on CD/USB

Ref. [http://winfe.wordpress.com/](http://winfe.wordpress.com/)

#### DCEPT - Deploying and detecting use of Active Directory honeytokens

Ref. [https://www.secureworks.com/blog/dcept](https://www.secureworks.com/blog/dcept)

#### TAILS - The Amnesic Incognito Live System

Ref. [https://tails.boum.org](https://tails.boum.org)











