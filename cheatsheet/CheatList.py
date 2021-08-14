def Cheat(name, category, output):
    global cheatList
    cheatList.append({"name": name, "category": category, "output": output})


cheatList = []


Cheat(
    "PSCredential",
    "Windows",
    """
Create a Credential Object for PowerShell:

\t[+] $user = 'user'
\t[+] $pw = 'password'
\t[+] $secure_pw = ConvertTo-SecureString $pw -AsPlainText -Force
\t[+] $cred = New-Object System.Management.Automation.PSCredential $user, $secure_pw
\t[+] Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock { whoami }
""",
)

Cheat(
	"test",
	"Windows",
	"""Testing""",
)