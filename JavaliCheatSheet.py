#!/usr/bin/python 
# coding: utf-8

from operator import sub
import sys
import signal
import os
import subprocess
from pwn import log, options
from cheat_sheets import cheat_list, Color, get_options


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
	log.info(f"Usage      => search with menu    :  {sys.argv[0].split('/')[-1]}")
	log.info(
		f"Usage      => search with keyword :  {sys.argv[0].split('/')[-1]} <keyword for search>"
	)
	log.info(f"Option -a  => add new cheatSheet  :  {sys.argv[0].split('/')[-1]} -a")
	log.info(f"Option -i  => print an Indice     :  {sys.argv[0].split('/')[-1]} -i")


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
	categories = map(lambda cheat: cheat.category, cheats)
	return sorted(list(set(categories)))


def get_sub_categories(cheats, category):
	cheats_with_same_category = filter(lambda cheat: cheat.category == category, cheats)
	sub_categories = map(lambda cheat: cheat.sub_category, cheats_with_same_category)
	return sorted(list(set(sub_categories)))


def get_cheat_names(cheats, category, sub_category):
	cheats_with_same_sub_category = filter(
		lambda cheat: cheat.category == category and cheat.sub_category == sub_category,
		cheats,
	)
	cheat_names = map(lambda cheat: cheat.name, cheats_with_same_sub_category)
	return sorted(list(set(cheat_names)))


def get_choice(options, category=None):
	clear()
	print(banner())

	title = ""
	if category == None:
		title = f"Select the category you want: \n\n"
	else:
		title = f"Select the wanted CheatSheet in {Color.YELLOW + Color.BOLD + category.upper() + Color.RESET} category.\n\n"
	# for index, option in enumerate(options):
	# 	log.info(
	# 		f"{Color.GREEN + Color.BOLD}{index:2}{Color.RESET} => {Color.YELLOW + Color.BOLD}{option}{Color.RESET}"
	# 	)

	# option = input(f"\n\tSelect a valide option... (Number):   \t").strip()
	# erase_last_printed_line()

	# while option not in map(str, range(len(options))):
	# 	option = input(
	# 		f"\t[{Color.RED}!{Color.RESET}]Select a {Color.GREEN}valide option... (Number){Color.RESET}:     \t"
	# 	).strip()
	# 	erase_last_printed_line()

	# return options[int(option)]

	pretty_options = []
	for option in options:
		pretty_options += [f"{Color.YELLOW + Color.BOLD}{option}{Color.RESET}"]

	option = get_options(title, pretty_options, 0)
	return options[option]


def line_separator(len_line):
	return f"\n{Color.BLUE}{'▓' * len_line }{Color.RESET}\n"


def get_beautiful_text(title, category, importante=True):
	if importante:
		return f"[{Color.GREEN}+{Color.RESET}] {title}: {Color.UNDERLINE + Color.YELLOW + category + Color.RESET}"
	else:
		return f"[{Color.GREEN}+{Color.RESET}] {title}: {Color.YELLOW + category + Color.RESET}"


def get_max_size(tty_size, cheat):
	len_list = [
		len(line) + TAB_SIZE for line in cheat.output.replace("\t", "    ").split("\n")
	]
	len_list += [len(cheat.name) + 18]
	return min(tty_size, max(len_list))


def colorized_text(output):
	text = ""
	for lineNumber, line in enumerate(output.split("\n")):
		try:
			commented = line.split()[0] == "#"
			title = line[0:3] == "[*]"
			if commented:
				text += f"{Color.COMMENTARY_COLOR}{line}{Color.RESET}\n"
			elif title:
				text += (
					f"{Color.BOLD + Color.UNDERLINE + Color.GREEN}{line}{Color.RESET}\n"
				)
			else:
				line = line.replace("#", f"{Color.COMMENTARY_COLOR}#")
				text += f"{Color.RESET}{line}\n"
		except:
			text += f"{Color.RESET}{line}\n"

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
	append_to_temp_file(colorized_text(cheat.output))
	append_to_temp_file(line_separator(len_line))

	os.system("bash -c 'less -r /tmp/temp.txt'")
	os.system("rm /tmp/temp.txt")


def printIndice(cheat_list):
	clear()
	print(banner())
	log.success(f"{Color.BOLD + Color.BLUE}INDICE{Color.RESET}\n\n")

	categories = get_categories(cheat_list)
	for category in categories:
		print(f"{Color.BOLD + Color.GREEN}", end="")
		title = f" {category.upper()} "
		title = f"{title:*^23}"
		print(title)

		sub_categories = get_sub_categories(cheat_list, category)
		for sub_category in sub_categories:
			cheat_names = get_cheat_names(cheat_list, category, sub_category)

			for cheat_name in cheat_names:
				print(f"{Color.BOLD + Color.YELLOW}", end="")
				sub_title = f" {sub_category} "
				line = f"{sub_title:^23}{Color.RESET} => {cheat_name}"
				print(line)


def find_and_get_correct_cheat_names(cheat_list, name):
	cheat_dict = {}
	for cheat in cheat_list:
		cheat_dict[cheat.name] = cheat
	cheat_names = [*cheat_dict]
	list_of_word_for_search = name.strip().split()
	final_cheats_list = []

	for cheat_name in cheat_names:
		if all(word.lower() in cheat_name.lower() for word in list_of_word_for_search):
			final_cheats_list.append(cheat_dict[cheat_name])

	if len(final_cheats_list) > 1:
		finalCheatName = get_choice(
			list(map(lambda cheat: cheat.name, final_cheats_list)), "Personalized"
		)
		return cheat_dict[finalCheatName]
	if len(final_cheats_list) == 0:
		log.failure("Could not find a cheat with the given arguments")
		exit(0)
	else:
		return final_cheats_list[0]


def manual_selection():
	categories = get_categories(cheat_list)
	category = get_choice(categories)
	sub_categories = get_sub_categories(cheat_list, category)
	sub_category = get_choice(sub_categories, category)
	cheat_names = get_cheat_names(cheat_list, category, sub_category)
	cheat_name = get_choice(cheat_names, sub_category)
	cheat = find_and_get_correct_cheat_names(cheat_list, cheat_name)
	print_formated_cheat(cheat)


def edit_cheat_list_file():
	cheat_listPath = "/".join(os.path.realpath(__file__).split("/")[:-1])
	cheat_listPath += "/cheat_sheets/cheat_list.py"
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
