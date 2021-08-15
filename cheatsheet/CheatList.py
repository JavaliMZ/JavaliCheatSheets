class Cheat:
    def __init__(self, name):
        self.name = name
        self.category = None
        self.output = None

    def addToList(self):
        global cheatList
        cheatList.append(self)


cheatList = []

######################################
######################################
######################################
PSCredential = Cheat("PSCredential")
PSCredential.category = "Windows"
PSCredential.output = """Create a Credential Object for PowerShell:

\t[+] $user = 'user'
\t[+] $pw = 'password'
\t[+] $secure_pw = ConvertTo-SecureString $pw -AsPlainText -Force
\t[+] $cred = New-Object System.Management.Automation.PSCredential $user, $secure_pw
\t[+] Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock { whoami }"""
PSCredential.addToList()
######################################
######################################
######################################

######################################
######################################
######################################
Test = Cheat("Test")
Test.category = "Linux"
Test.output = "Isto é só um teste..."
Test.addToList()
######################################
######################################
######################################
