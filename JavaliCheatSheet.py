#!/usr/bin/python3
# coding: utf-8

import sys
import signal
import os
import subprocess
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
CURSOR_UP_ONE = "\x1b[1A"
ERASE_LINE = "\x1b[2K"


def signal_handler(sig, frame):
	sys.exit(1)

def clear():
	print(chr(27) + "[2J"+ chr(27) + "[H")


def eraseLastPrintedLine():
	print(CURSOR_UP_ONE + ERASE_LINE + CURSOR_UP_ONE)


def banner():
	print(
		f"""{yellow}
	 ██████╗██╗  ██╗███████╗ █████╗ ████████╗███████╗██╗  ██╗███████╗███████╗████████╗███████╗
	██╔════╝██║  ██║██╔════╝██╔══██╗╚══██╔══╝██╔════╝██║  ██║██╔════╝██╔════╝╚══██╔══╝██╔════╝
	██║     ███████║█████╗  ███████║   ██║   ███████╗███████║█████╗  █████╗     ██║   ███████╗
	██║     ██╔══██║██╔══╝  ██╔══██║   ██║   ╚════██║██╔══██║██╔══╝  ██╔══╝     ██║   ╚════██║
	╚██████╗██║  ██║███████╗██║  ██║   ██║   ███████║██║  ██║███████╗███████╗   ██║   ███████║
	 ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝   ╚══════╝
										   By JavaliMZ                                                                  
{reset}"""
	)


def printCheat(cheatList, names):
	clear()
	printed = False
	_, columns = os.popen('stty size', 'r').read().split()
	columns = int(columns)

	if type(names) == str:
		names = [names]
	try:
		for cheat in cheatList:
			if all(name.strip().lower() in cheat.name.strip().lower() for name in names):
				maxLen = [len(line) for line in cheat.output.split("\n")]
				maxLen.sort()
				separatorLine = maxLen[-1] + 4
				if separatorLine > columns:
					separatorLine = columns
				print(f"\n{blue}{'▓' * separatorLine }{reset}")
				print(f"{blue}▓ {reset}")
				print(f"{blue}▓ {reset}", end="")
				log.success(f"Category: {underline + yellow}{cheat.category}{reset}\n")
				print(f"{blue}▓ {reset}", end="")
				log.success(f"Name:     {yellow}{cheat.name}{reset}\n")

				for line in cheat.output.split("\n"):
					try:
						commented = line.split()[0] == "#"
						title = line.split()[0] == "[*]"
						if commented:
							print(f"{blue}▓ {big + commentaryColor}{line}{reset}")
						elif title:
							print(f"{blue}▓ {big + underline + green}{line}{reset}")
						else:
							print(f"{blue}▓ {reset}{line}")
					except:
						print(f"{blue}▓ {reset}{line}")

				print(f"{blue}{'▓' * separatorLine }{reset}\n\n")
				printed = True

	except Exception as e:
		log.critical("Something wrong is not right...")
		log.critical(e)
	if not printed:
		log.failure(f"{big + red}Cheat not found!...{reset}")


def valideOption(possibilities):
	optionsIndex = [str(index) for index in range(0, len(possibilities))]

	option = input(f"\n\tSelect a valide option... (Number):   \t").strip()
	eraseLastPrintedLine()
	while option not in optionsIndex:
		option = input(
			f"\t[{red}!{reset}]Select a {green}valide option... (Number){reset}:     \t"
		).strip()
		eraseLastPrintedLine()

	return possibilities[int(option)]


def printOptions(category=None):
	clear()
	banner()
	options = set()
	for cheat in cheatList:
		if category == None:
			options.add(cheat.category)
		if cheat.category == category:
			options.add(cheat.name)

	options = list(options)
	options.sort()

	if category == None:
		log.success(f"Select the category you want: \n\n")
	else:
		log.success(f"Select the wanted CheatSheet in {category.upper()} category.\n\n")

	for index, option in enumerate(options):
		print("\t", end="")
		log.info(f"{index} - {option}")

	return valideOption(options)


def manualSelection():
	category = None
	name = None

	category = printOptions()
	cheatName = printOptions(category)
	printCheat(cheatList, cheatName)


def editCheatListFile():
	cheatListPath = (
		"/".join(os.path.realpath(__file__).split("/")[:-1]) + "/CheatList.py"
	)
	subprocess.call(["code", cheatListPath])


def helpPanel():
	banner()
	log.info(
		f"Usage => search with keyword:  {sys.argv[0].split('/')[-1]} <keyword for search>"
	)
	log.info(f"Usage => search with menu:     {sys.argv[0].split('/')[-1]}")
	log.info(f"Usage => add new cheatSheet:   {sys.argv[0].split('/')[-1]} -a")


def main():
	signal.signal(signal.SIGINT, signal_handler)

	if len(sys.argv) == 1:
		manualSelection()
		while True:
			input("Press any key to continue...\nCtrl-C to exit...")
			manualSelection()

	if len(sys.argv) >= 2:
		if sys.argv[1] == "-a":
			editCheatListFile()
		elif sys.argv[1] == "-h":
			helpPanel()
		else:
			printCheat(cheatList, sys.argv[1:])


main()
