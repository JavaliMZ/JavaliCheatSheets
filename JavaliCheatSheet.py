#!/usr/bin/python3
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
CURSOR_UP_ONE = "\x1b[1A"
ERASE_LINE = "\x1b[2K"


def signal_handler(sig, frame):
    sys.exit(1)


def moveCursorToFirstLine():
    print("\033[H", end="")


def clear():
    os.system("clear")
    moveCursorToFirstLine()


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


def getMaxColumnSize():
    _, columns = os.popen("stty size", "r").read().split()
    return int(columns)


def normalizeNames(names):
    if type(names) == str:
        names = [names]
    return names


def pressAnyKeyToContinue(text):
    if sys.platform == "linux":
        os.system(
            f"""bash -c 'read -n 1 -s -r -p "{reset}\n\033[100;6;1m{text}...{reset}"'"""
        )
    else:
        print(f"{reset}\n\033[100;6;1m{text}...{reset}")
        os.system("PAUSE")


def printFormatedCheat(cheat):
    clear()
    banner()
    maxColumnSize = getMaxColumnSize()
    maxLenList = [
        len(line) + 4 for line in cheat.output.replace("\t", "    ").split("\n")
    ]
    maxLenList.append(len(cheat.name) + 18)
    maxLenList.sort()
    separatorLine = maxLenList[-1] if maxLenList[-1] < maxColumnSize else maxColumnSize

    print(f"\n{blue}{'▓' * separatorLine }{reset}")
    print(f"{blue}▓ {reset}")
    print(f"{blue}▓ {reset}", end="")
    log.success(f"Category: {underline + yellow + cheat.category + reset}\n")
    print(f"{blue}▓ {reset}", end="")
    log.success(f"Name:     {yellow + cheat.name + reset}\n")

    for lineNumber, line in enumerate(cheat.output.split("\n")):
        if lineNumber >= 20 and lineNumber % 20 == 0:
            pressAnyKeyToContinue("More")
            print(f"\033[F\033[F{reset + blue}▓")
        try:
            commented = line.split()[0] == "#"
            title = line[0:3] == "[*]"
            if commented:
                print(f"{blue}▓ {commentaryColor}{line}{reset}")
            elif title:
                print(f"{blue}▓ {big + underline + green}{line}{reset}")
            else:
                line = line.replace("#", f"{commentaryColor}#")
                print(f"{blue}▓ {reset}{line}")
        except:
            print(f"{blue}▓ {reset}{line}")
    print(f"{blue}{'▓' * separatorLine }{reset}\n\n")


def printCheat(cheatList, names):
    cheatExist = False
    listOfCheatNamesToPrint = []
    names = normalizeNames(names)

    try:
        for cheat in cheatList:
            areAllWordsInCheatName = all(
                name.strip().lower() in cheat.name.strip().lower() for name in names
            )
            if areAllWordsInCheatName:
                cheatExist = True
                listOfCheatNamesToPrint.append(cheat.name)

        if len(listOfCheatNamesToPrint) == 1:
            cheat = [
                cheat for cheat in cheatList if cheat.name == listOfCheatNamesToPrint[0]
            ][0]
            printFormatedCheat(cheat)
            return

        elif len(listOfCheatNamesToPrint) > 1:
            cheatName = printOptions(filtered_list=listOfCheatNamesToPrint)
            printCheat(cheatList, cheatName)

    except Exception as e:
        log.critical("Something wrong is not right...")
        log.critical(e)

    if not cheatExist:
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


def printOptions(category=None, filtered_list=None):
    clear()
    banner()
    options = set()
    for cheat in cheatList:
        if filtered_list:
            if cheat.name in filtered_list:
                options.add(cheat.name)
        elif category == None:
            options.add(cheat.category)
        elif cheat.category == category:
            options.add(cheat.name)

    options = list(options)
    options.sort()

    if category == None:
        log.success(f"Select the category you want: \n\n")
    elif filtered_list != None:
        log.success(f"To much Cheats? Select only one in the list")
    else:
        log.success(
            f"Select the wanted CheatSheet in {yellow + big + category.upper() + reset} category.\n\n"
        )

    for index, option in enumerate(options):
        print("\t", end="")
        if filtered_list:
            for cheat in cheatList:
                if option == cheat.name:
                    log.info(
                        f"{green + big }{index:2}{reset} => {yellow + big}{cheat.category}{reset} - {option}"
                    )
        else:
            log.info(f"{green + big }{index:2}{reset} => {option}")

    return valideOption(options)


def manualSelection():
    category = None
    name = None

    category = printOptions()
    cheatName = printOptions(category=category)
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
            print("Press Enter to continue...")
            response = input("Write 'exit', 'q' or 'quit' to quit...").lower().strip()
            if response in ["exit", "q", "quit"]:
                sys.exit(0)
            manualSelection()

    if len(sys.argv) >= 2:
        if sys.argv[1] == "-a":
            editCheatListFile()
        elif sys.argv[1] == "-h" or sys.argv[1] == "--help":
            helpPanel()
        else:
            printCheat(cheatList, sys.argv[1:])


main()
