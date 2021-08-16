#!/usr/bin/python3
# coding: utf-8

import sys
import signal
import os
from pwn import log
from CheatList import cheatList


# COLORS
big = "\033[01m"
red = "\033[31m"
green = "\033[32m"
yellow = "\033[33m"
blue = "\033[34m"
reset = "\033[0m"
CURSOR_UP_ONE = "\x1b[1A"
ERASE_LINE = "\x1b[2K"


def signal_handler(sig, frame):
    sys.exit(1)


def eraseLastPrintedLine():
    print(CURSOR_UP_ONE + ERASE_LINE + CURSOR_UP_ONE)


def banner():
    print(
        f"""{yellow}
:'######::'##::::'##:'########::::'###::::'########::'######::'##::::'##:'########:'########:'########::'######::
'##... ##: ##:::: ##: ##.....::::'## ##:::... ##..::'##... ##: ##:::: ##: ##.....:: ##.....::... ##..::'##... ##:
 ##:::..:: ##:::: ##: ##::::::::'##:. ##::::: ##:::: ##:::..:: ##:::: ##: ##::::::: ##:::::::::: ##:::: ##:::..::
 ##::::::: #########: ######:::'##:::. ##:::: ##::::. ######:: #########: ######::: ######:::::: ##::::. ######::
 ##::::::: ##.... ##: ##...:::: #########:::: ##:::::..... ##: ##.... ##: ##...:::: ##...::::::: ##:::::..... ##:
 ##::: ##: ##:::: ##: ##::::::: ##.... ##:::: ##::::'##::: ##: ##:::: ##: ##::::::: ##:::::::::: ##::::'##::: ##:
. ######:: ##:::: ##: ########: ##:::: ##:::: ##::::. ######:: ##:::: ##: ########: ########:::: ##::::. ######::
:......:::..:::::..::........::..:::::..:::::..::::::......:::..:::::..::........::........:::::..::::::......:::                                                                                                    	
{reset}"""
    )


def printCheat(cheatList, name):
    printed = False
    try:
        for cheat in cheatList:
            if name.strip().lower() in cheat.name.strip().lower():
                maxLen = [len(line) for line in cheat.output.split("\n")]
                maxLen.sort()
                print(f"\n{blue}{'▓' * (maxLen[-1] + 4) }{reset}")
                print(f"{blue}▓ {reset}")
                print(f"{blue}▓ {reset}", end="")
                log.success(f"{big + green}{cheat.name}{reset}\n")
                print(f"{blue}▓ {reset}")

                for line in cheat.output.split("\n"):
                    print(f"{blue}▓ {reset}{line}")

                print(f"{blue}▓ {reset}")
                print(f"{blue}{'▓' * (maxLen[-1] + 4) }{reset}\n\n")
                printed = True
    except:
        log.critical("Something wrong is not right...")
        log.critical("Can't print this Cheat...")
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


def main():
    signal.signal(signal.SIGINT, signal_handler)
    banner()

    if len(sys.argv) == 1:
        manualSelection()
        while True:
            input("Press any key to continue...\nCtrl-C to exit...")
            manualSelection()

    if len(sys.argv) == 2:
        printCheat(cheatList, sys.argv[1])


main()
