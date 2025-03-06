import os


def printLogo() -> str:
    return """ ▄▄ •  ▄▄▄· ▄▄▄▄▄▄▄▄ .▄▄▄▄· ▄▄▄  ▄▄▄ . ▄▄▄· ▄ •▄ ▄▄▄ .▄▄▄  
▐█ ▀ ▪▐█ ▀█ •██  ▀▄.▀·▐█ ▀█▪▀▄ █·▀▄.▀·▐█ ▀█ █▌▄▌▪▀▄.▀·▀▄ █·
▄█ ▀█▄▄█▀▀█  ▐█.▪▐▀▀▪▄▐█▀▀█▄▐▀▀▄ ▐▀▀▪▄▄█▀▀█ ▐▀▀▄·▐▀▀▪▄▐▀▀▄ 
▐█▄▪▐█▐█ ▪▐▌ ▐█▌·▐█▄▄▌██▄▪▐█▐█•█▌▐█▄▄▌▐█ ▪▐▌▐█.█▌▐█▄▄▌▐█•█▌
·▀▀▀▀  ▀  ▀  ▀▀▀  ▀▀▀ ·▀▀▀▀ .▀  ▀ ▀▀▀  ▀  ▀ ·▀  ▀ ▀▀▀ .▀  ▀
        https://github.com/rayjenkinsXD/gatebreaker\n"""


def b(message: str) -> str:
    """ Делает жирный шрифт в терминале """
    return "\033[1m" + message + "\033[0m"


class MessageBuffer:
    __buffer = []

    @staticmethod
    def push(message):
        MessageBuffer.__buffer.append(message)
    
    @staticmethod
    def render():
        os.system("clear")

        for message in MessageBuffer.__buffer:
            print(message)

    @staticmethod
    def errorLog(message: str) -> None:
        MessageBuffer.__buffer.append("[\033[1m\033[31m✘\033[0m] " + message)

    @staticmethod
    def successLog(message: str) -> None:
        MessageBuffer.__buffer.append("[\033[1m\033[32m✔\033[0m] " + message)

    @staticmethod
    def debugLog(message: str) -> str:
        MessageBuffer.__buffer.append("[\033[1m\033[33m@\033[0m] " + message)
