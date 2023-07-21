import sys

from multiprocessing import freeze_support
from crypto import init_crypto
from menus import open_main_menu
from emailclient import init_emailclient, EmailClient
from colorama import init as init_colorama


def main():
	client = EmailClient()
	open_main_menu(client)
	client.disconnect()


if __name__ == "__main__":
	if sys.platform.startswith("win"):
		freeze_support()
	init_colorama()
	init_crypto()
	init_emailclient()
	main()
