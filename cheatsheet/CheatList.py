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

$user = 'user'
$pw = 'password'
$secure_pw = ConvertTo-SecureString $pw -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential $user, $secure_pw
Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock { whoami }"""

######################################
######################################

Test = Cheat("PSCredenpois")
Test.category = "Linux"
Test.output = "Isto é só um teste..."

######################################
######################################

icmp_reverse_shell_windows = Cheat("ICMP - Reverse Shell Windows (Nishang)")
icmp_reverse_shell_windows.category = "Windows"
icmp_reverse_shell_windows.output = """[*] Reverse Shell when TCP and UDP connection are blocked by Firewall rules.

# Download Nishang
# Remove all blank lines and commented lines for no bugs
# convert into base64 encoded string


"""