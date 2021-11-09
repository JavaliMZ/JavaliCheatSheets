#!/usr/bin/python3.9
# coding: utf-8

import sys
import signal
import os
import subprocess
from time import sleep
from pwn import log
from CheatList import cheatList


# COLORS
big = "\033[01m"
red = "\033[31m"
green = "\033[32m"
yellow = "\033[33m"
blue = "\033[34m"
commentaryColor = "\033[38;5;9m"
reset = "\033[0m"
underline = "\033[4m"
# Global Var
CURSOR_UP_ONE = "\x1b[1A"
ERASE_LINE = "\x1b[2K"
TAB_SIZE = 7


def debug(message):
	log.failure(str(message))
	sleep(3)

def banner():
	banner = f"""{yellow}
	 ██████╗██╗  ██╗███████╗ █████╗ ████████╗███████╗██╗  ██╗███████╗███████╗████████╗███████╗
	██╔════╝██║  ██║██╔════╝██╔══██╗╚══██╔══╝██╔════╝██║  ██║██╔════╝██╔════╝╚══██╔══╝██╔════╝
	██║     ███████║█████╗  ███████║   ██║   ███████╗███████║█████╗  █████╗     ██║   ███████╗
	██║     ██╔══██║██╔══╝  ██╔══██║   ██║   ╚════██║██╔══██║██╔══╝  ██╔══╝     ██║   ╚════██║
	╚██████╗██║  ██║███████╗██║  ██║   ██║   ███████║██║  ██║███████╗███████╗   ██║   ███████║
	 ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝   ╚══════╝
										   By JavaliMZ                                                                  
	{reset}"""
	return banner

def helpPanel():
	print(banner())
	log.info(
		f"Usage => search with keyword:  {sys.argv[0].split('/')[-1]} <keyword for search>"
	)
	log.info(f"Usage => search with menu:     {sys.argv[0].split('/')[-1]}")
	log.info(f"Usage => add new cheatSheet:   {sys.argv[0].split('/')[-1]} -a")

def signal_handler(sig, frame):
	sys.exit(1)

def moveCursorToFirstLine():
	print("\033[H", end="")

def clear():
	os.system("clear")
	moveCursorToFirstLine()

def createTempFile():
	with open("/tmp/temp.txt", "w") as file:
		file.close()

def appendToTempFile(text, filename="/tmp/temp.txt", end="\n"):
	with open(filename, "a") as file:
		file.write(text + end)

def eraseLastPrintedLine():
	print(CURSOR_UP_ONE + ERASE_LINE + CURSOR_UP_ONE)

def getMaxColumnSize():
	_, columns = os.popen("stty size", "r").read().split()
	return int(columns)

def getCategories(cheats):
	categories = list(set([cheat.category for cheat in cheats]))
	categories.sort()
	return categories

def getSubCategories(cheats, category):
	subCategories = list(set([cheat.subCategory for cheat in cheats if cheat.category == category]))
	subCategories.sort()
	return subCategories

def getCheatName(cheats, category, subCategory):
	cheatsNames = list(set([cheat.name for cheat in cheats if cheat.category == category and cheat.subCategory == subCategory]))
	cheatsNames.sort()
	return cheatsNames
	
def getChoice(options, category=None):
	clear()
	print(banner())

	if category == None:
		log.success(f"Select the category you want: \n\n")
	else:
		log.success(f"Select the wanted CheatSheet in {yellow + big + category.upper() + reset} category.\n\n")

	for index, option in enumerate(options):
		log.info(f"{green + big }{index:2}{reset} => {yellow + big}{option}{reset}")

	option = input(f"\n\tSelect a valide option... (Number):   \t").strip()
	eraseLastPrintedLine()

	while True:
		try:
			option = int(option)
			if option < 0 or option > len(options):
				raise		
			break	
		except:
			option = input(f"\t[{red}!{reset}]Select a {green}valide option... (Number){reset}:     \t").strip()
			eraseLastPrintedLine()

	return options[option]

def printFormatedCheat(cheat):
	clear()
	createTempFile()
	appendToTempFile(banner())
	maxColumnSize = getMaxColumnSize()
	maxLenList = [
		len(line) + TAB_SIZE for line in cheat.output.replace("\t", "    ").split("\n")
	]
	maxLenList.append(len(cheat.name) + 18)
	maxLenList.sort()
	separatorLine = maxLenList[-1] if maxLenList[-1] < maxColumnSize else maxColumnSize

	appendToTempFile(f"\n{blue}{'▓' * separatorLine }{reset}\n")
	appendToTempFile(f"[{green}+{reset}] Category:     {underline + yellow + cheat.category + reset}")
	appendToTempFile(f"[{green}+{reset}] Sub Category: {underline + yellow + cheat.subCategory + reset}")
	appendToTempFile(f"[{green}+{reset}] Name:         {yellow + cheat.name + reset}")
	appendToTempFile(f"\n{blue}{'▓' * separatorLine }{reset}\n")

	for lineNumber, line in enumerate(cheat.output.split("\n")):
		try:
			commented = line.split()[0] == "#"
			title = line[0:3] == "[*]"
			if commented:
				appendToTempFile(f"{commentaryColor}{line}{reset}")
			elif title:
				appendToTempFile(f"{big + underline + green}{line}{reset}")
			else:
				line = line.replace("#", f"{commentaryColor}#")
				appendToTempFile(f"{reset}{line}")
		except:
			appendToTempFile(f"{reset}{line}")
	appendToTempFile(f"{blue}{'▓' * separatorLine }{reset}\n\n")
	os.system("bash -c 'less -r /tmp/temp.txt'")
	os.system("rm /tmp/temp.txt")

def findAndGetCorrectCheatNames(cheatList, names):
	cheatNames = [cheat.name for cheat in cheatList]
	listOfWordsForSearch = names.strip().split()
	finalCheatList = []

	for cheat in cheatList:
		if all(word.lower() in cheat.name.lower() for word in listOfWordsForSearch):
			finalCheatList.append(cheat)

	if len(finalCheatList) > 1:
		finalCheatName = getChoice([cheat.name for cheat in finalCheatList], "Personalized")
		for cheat in cheatList:
			if cheat.name == finalCheatName:
				return cheat
	if len(finalCheatList) == 0:
		log.failure("Could not find a cheat with the given arguments")
		exit(0)
	if len(finalCheatList) == 1:
		return finalCheatList[0]

def manualSelection():
	categories    = getCategories(cheatList)
	category      = getChoice(categories)
	subCategories = getSubCategories(cheatList, category)
	subCategory   = getChoice(subCategories, category)
	cheatNames    = getCheatName(cheatList, category, subCategory)
	cheatName     = getChoice(cheatNames, subCategory)
	cheat         = findAndGetCorrectCheatNames(cheatList, cheatName)
	printFormatedCheat(cheat)

def editCheatListFile():
	cheatListPath = (
		"/".join(os.path.realpath(__file__).split("/")[:-1]) + "/CheatList.py"
	)
	subprocess.call(["code", cheatListPath])

def main():
	signal.signal(signal.SIGINT, signal_handler)

	if len(sys.argv) == 1:
		manualSelection()

	if len(sys.argv) >= 2:
		if sys.argv[1] == "-a":
			editCheatListFile()
		elif sys.argv[1] == "-h" or sys.argv[1] == "--help":
			helpPanel()
		else:
			cheat = findAndGetCorrectCheatNames(cheatList, " ".join(sys.argv[1:]))
			printFormatedCheat(cheat)

main()
