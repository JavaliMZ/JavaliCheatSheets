import sys
import signal
import os
from pwn import log
from CheatList import cheatList


class CheatSheets:
	def __init__(self):
		self.cheat = {}
		self.categories = []

	def addNewCheat(self, cheat_obj):
		self.cheat[cheat_obj.name] = cheat_obj
		self.addNewCategory(cheat_obj.category)

	def addNewCategory(self, category):
		if not category in self.categories:
			self.categories.append(category)

	def getAllCategories(self):
		return self.categories


class Cheat:
	def __init__(self, name, category, output):
		self.name = name
		self.category = category
		self.output = output

	def output(self):
		return self.output

	def getCategory(self):
		return self.category


def signal_handler(sig, frame):
	print("\n\n")
	log.failure("You pressed Ctrl-C!...")
	sys.exit(1)


def newCheat(name, category, output):
	global JavaliCheatSheet
	JavaliCheatSheet.addNewCheat(Cheat(name, category, output))


def printCheat(name):
	global JavaliCheatSheet
	printed = False

	for key, value in JavaliCheatSheet.cheat.items():
		if name.strip().lower() in key.lower():
			printed = True
			print()
			log.success(f"\033[1;32m{JavaliCheatSheet.cheat[key].name}\033[0m\n\n")
			# \033[1;31mbold red text\033[0m\n

			print(JavaliCheatSheet.cheat[key].output)

	if not printed:
		log.failure("CheatSheet don't existe...")


def selectCategories(categories):
	print("********************************************")
	options = {}
	for index, category in enumerate(categories):
		log.success(f"{index + 1} - {category}")
		options[category] = index + 1


	option = input("\tSelect one category:     ")
	try:
		num = int(option) - 1
		while num < 0 or num >= len(categories):
			num = int(input("\tSelect a valide category number:     ")) - 1
		return num
	except:
		print(options[option])
		return options[option]



def selectCheat(category):
	global JavaliCheatSheet
	print("********************************************")
	log.info(f"For {category}, we have that cheats:\n\n")
	cheatNameList = []
	options = {}
	count = 1
	for name, cheat in JavaliCheatSheet.cheat.items():
		if cheat.category == category:
			cheatNameList.append(name)
			log.success(f"{count} - {name}")
			options[count] = name
			count += 1
	option = input("\tSelect the CheatSheet:     ")
	try:
		return options[int(option)]
	except:
		return option


def manualSelection():
	global JavaliCheatSheet
	log.success("Javali Cheat Sheets!!\n\n")
	print(
		f"Select one category OR search for a cheat with new command <python3 {sys.argv[0]} {{cheat}}>\n\n"
	)

	categories = JavaliCheatSheet.getAllCategories()
	option = selectCategories(categories)
	cheatName = selectCheat(categories[option])
	printCheat(cheatName)


def main():
	signal.signal(signal.SIGINT, signal_handler)

	for cheat in cheatList:
		newCheat(cheat["name"], cheat["category"], cheat["output"])


	if len(sys.argv) == 1:
		manualSelection()
	if len(sys.argv) == 2:
		try:
			printCheat(sys.argv[1])
		except:
			log.failure("Cheat not found!")


JavaliCheatSheet = CheatSheets()
main()
