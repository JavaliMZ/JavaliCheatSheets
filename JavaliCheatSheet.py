#!/usr/bin/python3.9
# coding: utf-8

import sys
import signal
import os
import subprocess
from pwn import log
from cheat_sheets import cheat_list, Color



# Global Var
CURSOR_UP_ONE = "\x1b[1A"
ERASE_LINE = "\x1b[2K"
TAB_SIZE = 7


def debug(message):
	from time import sleep
	log.failure(str(message))
	sleep(3)


def banner():
	banner = f"""{Color.YELLOW}
	 ██████╗██╗  ██╗███████╗ █████╗ ████████╗███████╗██╗  ██╗███████╗███████╗████████╗███████╗
	██╔════╝██║  ██║██╔════╝██╔══██╗╚══██╔══╝██╔════╝██║  ██║██╔════╝██╔════╝╚══██╔══╝██╔════╝
	██║     ███████║█████╗  ███████║   ██║   ███████╗███████║█████╗  █████╗     ██║   ███████╗
	██║     ██╔══██║██╔══╝  ██╔══██║   ██║   ╚════██║██╔══██║██╔══╝  ██╔══╝     ██║   ╚════██║
	╚██████╗██║  ██║███████╗██║  ██║   ██║   ███████║██║  ██║███████╗███████╗   ██║   ███████║
	 ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝   ╚══════╝
										   By JavaliMZ                                                                  
	{Color.RESET}"""
	return banner


def help_panel():
	print(banner())
	log.info(f"Usage => search with keyword:      {sys.argv[0].split('/')[-1]} <keyword for search>")
	log.info(f"Usage => search with menu:         {sys.argv[0].split('/')[-1]}")
	log.info(f"Option -a => add new cheatSheet:   {sys.argv[0].split('/')[-1]} -a")
	log.info(f"Option -i => print an Indice:      {sys.argv[0].split('/')[-1]} -i")


def signal_handler(sig, frame):
	sys.exit(1)


def move_cursor_to_first_line():
	print("\033[H", end="")


def clear():
	os.system("clear")
	move_cursor_to_first_line()


def create_temp_file():
	with open("/tmp/temp.txt", "w") as file:
		file.close()


def append_to_temp_file(text, filename="/tmp/temp.txt", end="\n"):
	with open(filename, "a") as file:
		file.write(text + end)


def erase_last_printed_line():
	print(CURSOR_UP_ONE + ERASE_LINE + CURSOR_UP_ONE)


def get_tty_size():
	_, columns = os.popen("stty size", "r").read().split()
	return int(columns)


def get_categories(cheats):
	categories = list(set([cheat.category for cheat in cheats]))
	categories.sort()
	return categories


def get_sub_categories(cheats, category):
	sub_categories = list(
		set([cheat.sub_category for cheat in cheats if cheat.category == category])
	)
	sub_categories.sort()
	return sub_categories


def get_cheat_name(cheats, category, sub_category):
	cheatsNames = list(
		set(
			[
				cheat.name
				for cheat in cheats
				if cheat.category == category and cheat.sub_category == sub_category
			]
		)
	)
	cheatsNames.sort()
	return cheatsNames


def get_choice(options, category=None):
	clear()
	print(banner())

	if category == None:
		log.success(f"Select the category you want: \n\n")
	else:
		log.success(
			f"Select the wanted CheatSheet in {Color.YELLOW + Color.BOLD + category.upper() + Color.RESET} category.\n\n"
		)

	for index, option in enumerate(options):
		log.info(f"{Color.GREEN + Color.BOLD }{index:2}{Color.RESET} => {Color.YELLOW + Color.BOLD}{option}{Color.RESET}")

	option = input(f"\n\tSelect a valide option... (Number):   \t").strip()
	erase_last_printed_line()

	while True:
		try:
			option = int(option)
			if option < 0 or option >= len(options):
				raise
			break
		except:
			option = input(
				f"\t[{red}!{Color.RESET}]Select a {Color.GREEN}valide option... (Number){Color.RESET}:     \t"
			).strip()
			erase_last_printed_line()

	return options[option]


def line_separator(len_line):
	return f"\n{Color.BLUE}{'▓' * len_line }{Color.RESET}\n"


def get_beautiful_text(title, category, importante=True):
	if importante:
		return f"[{Color.GREEN}+{Color.RESET}] {title}: {Color.UNDERLINE + Color.YELLOW + category + Color.RESET}"
	else:
		return f"[{Color.GREEN}+{Color.RESET}] {title}: {Color.YELLOW + category + Color.RESET}"


def get_max_size(tty_size, cheat):
	len_list = [len(line) + TAB_SIZE for line in cheat.output.replace("\t", "    ").split("\n")]
	len_list += [len(cheat.name) + 18]
	return min(tty_size, max(len_list))


def colorized_text(cheat):
	text = ""
	for lineNumber, line in enumerate(cheat.output.split("\n")):
		try:
			commented = line.split()[0] == "#"
			title = line[0:3] == "[*]"
			if commented:
				text += (f"{Color.COMMENTARY_COLOR}{line}{Color.RESET}\n")
			elif title:
				text += (f"{Color.BOLD + Color.UNDERLINE + Color.GREEN}{line}{Color.RESET}\n")
			else:
				line = line.replace("#", f"{Color.COMMENTARY_COLOR}#")
				text += (f"{Color.RESET}{line}\n")
		except:
			text += (f"{Color.RESET}{line}\n")
	
	return text


def print_formated_cheat(cheat):
	clear()
	create_temp_file()

	len_line = get_max_size(get_tty_size(), cheat)

	append_to_temp_file(banner())
	append_to_temp_file(line_separator(len_line))
	append_to_temp_file(get_beautiful_text("Category     ", cheat.category))
	append_to_temp_file(get_beautiful_text("Sub category ", cheat.sub_category))
	append_to_temp_file(get_beautiful_text("Name         ", cheat.name, False))
	append_to_temp_file(line_separator(len_line))
	append_to_temp_file(colorized_text(cheat))
	append_to_temp_file(line_separator(len_line))
	
	os.system("bash -c 'less -r /tmp/temp.txt'")
	os.system("rm /tmp/temp.txt")


def printIndice(cheat_list):
	clear()
	print(banner())
	categories = get_categories(cheat_list)
	log.success(f"{Color.BOLD + Color.BLUE}INDICE{Color.RESET}\n\n")
	for category in categories:
		log.success(f"{Color.BOLD + Color.GREEN + category.upper() + Color.RESET}")
		sub_categories = get_sub_categories(cheat_list, category)
		for sub_category in sub_categories:
			cheat_names = get_cheat_name(cheat_list, category, sub_category)
			for cheat_name in cheat_names:
				print("", end="")
				print(f"{Color.BOLD + Color.YELLOW + sub_category + Color.RESET:^35} => {cheat_name}")


def find_and_get_correct_cheat_names(cheat_list, names):
	cheatDict = {}
	for cheat in cheat_list:
		cheatDict[cheat.name] = cheat
	cheat_names = [*cheatDict]
	listOfWordsForSearch = names.strip().split()
	finalcheat_list = []

	for cheat_name in cheat_names:
		if all(word.lower() in cheat_name.lower() for word in listOfWordsForSearch):
			finalcheat_list.append(cheatDict[cheat_name])

	if len(finalcheat_list) > 1:
		finalCheatName = get_choice([cheat.name for cheat in finalcheat_list], "Personalized")
		return cheatDict[finalCheatName]
	if len(finalcheat_list) == 0:
		log.failure("Could not find a cheat with the given arguments")
		exit(0)
	else:
		return finalcheat_list[0]


def manual_selection():
	categories = get_categories(cheat_list)
	category = get_choice(categories)
	sub_categories = get_sub_categories(cheat_list, category)
	sub_category = get_choice(sub_categories, category)
	cheat_names = get_cheat_name(cheat_list, category, sub_category)
	cheat_name = get_choice(cheat_names, sub_category)
	cheat = find_and_get_correct_cheat_names(cheat_list, cheat_name)
	print_formated_cheat(cheat)


def edit_cheat_list_file():
	cheat_listPath = (
		"/".join(os.path.realpath(__file__).split("/")[:-1]) + "/cheat_sheets/cheat_list.py"
	)
	subprocess.call(["code", cheat_listPath])


def main():
	signal.signal(signal.SIGINT, signal_handler)

	if len(sys.argv) == 1:
		manual_selection()

	if len(sys.argv) >= 2:
		if sys.argv[1] == "-a":
			edit_cheat_list_file()
		elif sys.argv[1] == "-h" or sys.argv[1] == "--help":
			help_panel()
		elif sys.argv[1] == "-i":
			printIndice(cheat_list)
		else:
			cheat = find_and_get_correct_cheat_names(cheat_list, " ".join(sys.argv[1:]))
			print_formated_cheat(cheat)


main()
