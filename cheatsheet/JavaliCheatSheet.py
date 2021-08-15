import sys
import signal
import os
from pwn import log
from CheatList import cheatList


# COLORS
big = "\033[01m"
red = "\033[31m"
green = "\033[32m"
reset = "\033[0m"


def signal_handler(sig, frame):
	print("\n\n")
	log.failure("You pressed Ctrl-C!...")
	sys.exit(1)


def printCheat(cheatList, name):
	printed = False
	try:
		for cheat in cheatList:
			if name.strip().lower() in cheat.name.strip().lower():
				print("\n\n")
				log.success(f"{big + green}{cheat.name}{reset}\n\n")
				print(cheat.output)
				printed = True
	except:
		log.critical("Something wrong is not right...")
		log.critical("Can't print this Cheat...")
	if not printed:
		log.failure(f"{big + red}Cheat not found!...{reset}")



def valideOption(possibilities):
	optionsIndex = [str(index) for index in range(0,len(possibilities))]

	option = input(f"\n\tSelect a valide option... (Number):   \t").strip()
	while option not in optionsIndex:
		option = input(f"\t[{red}!{reset}]Select a {green}valide option... (Number){reset}:     \t").strip()

	return possibilities[int(option)]


def chooseCategory():
	options = set()
	for cheat in cheatList:
		options.add(cheat.category)
	
	for index, option in enumerate(options):
		log.info(f"{index} - {option}")
	
	return valideOption(list(options))

def chooseCheatName(category):
	options = set()
	for cheat in cheatList:
		if cheat.category == category:
			options.add(cheat.name)
	
	for index, option in enumerate(options):
		log.info(f"{index} - {option}")
	
	return valideOption(list(options))


def manualSelection():
	category = None
	name = None

	category = chooseCategory()
	cheatName = chooseCheatName(category)
	printCheat(cheatList, cheatName)


def main():
	signal.signal(signal.SIGINT, signal_handler)

	if len(sys.argv) == 1:
		manualSelection()
	if len(sys.argv) == 2:
		printCheat(cheatList, sys.argv[1])


main()
