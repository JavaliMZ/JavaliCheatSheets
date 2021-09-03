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
# Global Var
CURSOR_UP_ONE = "\x1b[1A"
ERASE_LINE = "\x1b[2K"
TAB_SIZE = 7


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


def getMaxColumnSize():
    _, columns = os.popen("stty size", "r").read().split()
    return int(columns)


def normalizeNames(names):
    if type(names) == str:
        names = [names]
    return names


def createTempFile():
    with open("/tmp/temp.txt", "w") as file:
        file.close()


def appendToTempFile(text, filename="/tmp/temp.txt", end="\n"):

    with open(filename, "a") as file:
        file.write(text + end)


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

    appendToTempFile(f"\n{blue}{'▓' * separatorLine }{reset}")
    appendToTempFile(f"{blue}▓ {reset}")
    appendToTempFile(f"{blue}▓ {reset}", end="")
    appendToTempFile(
        f"[{green}+{reset}] Category: {underline + yellow + cheat.category + reset}"
    )
    appendToTempFile(f"{blue}▓ {reset}", end="")
    appendToTempFile(f"[{green}+{reset}] Name:     {yellow + cheat.name + reset}")

    for lineNumber, line in enumerate(cheat.output.split("\n")):
        try:
            commented = line.split()[0] == "#"
            title = line[0:3] == "[*]"
            if commented:
                appendToTempFile(f"{blue}▓ {commentaryColor}{line}{reset}")
            elif title:
                appendToTempFile(f"{blue}▓ {big + underline + green}{line}{reset}")
            else:
                line = line.replace("#", f"{commentaryColor}#")
                appendToTempFile(f"{blue}▓ {reset}{line}")
        except:
            appendToTempFile(f"{blue}▓ {reset}{line}")
    appendToTempFile(f"{blue}{'▓' * separatorLine }{reset}\n\n")
    os.system("bash -c 'less -r /tmp/temp.txt'")
    os.system("rm /tmp/temp.txt")


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
    print(banner())
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
    print(banner())
    log.info(
        f"Usage => search with keyword:  {sys.argv[0].split('/')[-1]} <keyword for search>"
    )
    log.info(f"Usage => search with menu:     {sys.argv[0].split('/')[-1]}")
    log.info(f"Usage => add new cheatSheet:   {sys.argv[0].split('/')[-1]} -a")


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
            printCheat(cheatList, sys.argv[1:])


main()
