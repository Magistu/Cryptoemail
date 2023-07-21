import json
import os

from imaplib import IMAP4
from smtplib import SMTPException

from crypto import pub_key_path, decrypt, keys_folder, KEY_FILE_NAME
from menu import Menu
from emailclient import USER_JSON, MESSAGE_JSON, obtain_body, EmailClient


YES_STATES = ["y", "yes", "Y"]
NO_STATES = ["n", "no", "N"]


def yes_or_no(prompt):
	state = input(prompt)
	while True:
		if state in YES_STATES:
			return True
		if state in NO_STATES:
			return False
		state = input()


def add_pub_key(address, pem):
	path = pub_key_path(address)
	if os.path.exists(path) and not yes_or_no(f"{path} already exists. Overwrite?(Y/N)\n"):
		return
	folder = keys_folder(address)
	if not os.path.isdir(folder):
		os.mkdir(folder)
	with open(path, "w") as f:
		f.write(pem)


def open_inbox_page(client: EmailClient):
	page = int(input("page: "))
	client.view_mailbox(page)
	print("")


def read_inbox_message(client: EmailClient):
	i_message = int(input("number of message: "))
	client.view_message(i_message)
	print("")


def view_mailbox_list(client: EmailClient):
	print("\n".join([f"{i}: {mailbox}" for i, mailbox in enumerate(client.get_mailbox_list())]))
	print("")


def read_mailbox_message(client: EmailClient):
	print("available mailboxes:")
	view_mailbox_list(client)
	mailbox = input("mailbox: ")
	if str.isdigit(mailbox):
		mailbox = client.get_mailbox_list()[int(mailbox)]
	i_message = int(input("number of message: "))
	client.view_message(i_message, mailbox)
	print("")


def open_mailbox_page(client: EmailClient):
	print("available mailboxes:")
	view_mailbox_list(client)
	mailbox = input("mailbox: ")
	if str.isdigit(mailbox):
		mailbox = client.get_mailbox_list()[int(mailbox)]
	page = int(input("page: "))
	client.view_mailbox(page, mailbox)
	print("")


def add_pub_key_from_message(client: EmailClient):
	i_message = int(input("number of message: "))
	attachments = client.get_attachments(i_message)
	if len(attachments) == 0:
		raise ValueError("no public key found")

	filtered_attachments = list(filter(lambda x: x.get_filename() == KEY_FILE_NAME + ".pub", attachments))
	if len(filtered_attachments) == 0:
		attachment = attachments[0]
	else:
		attachment = filtered_attachments[0]
	
	address = client.get_author(i_message)
	pem = obtain_body(attachment)
	add_pub_key(address, pem)
	print("DONE\n")


def encrypt_and_send_from_default_json(client: EmailClient):
	client.send_from_json()
	print("DONE\n")
	

def text_input(prompt="", endc="."):
	print(prompt, end="")
	text = ""
	while True:
		line = input()
		if line == endc:
			return text
		text += line


def write_and_send(client: EmailClient):
	send_to = input("send to:\n")
	subject = input("subject:\n")
	text = text_input("text (ending with a separate . char):\n")
	encrypt_message = yes_or_no("encrypt message?(Y/N)\n")
	files_str = input("attached files (separated with a space):\n")
	files = files_str.split() if len(files_str) > 0 else []
	client.send(send_to, subject, text, encrypt_message, files)
	print("DONE\n")


def open_mailbox_menu(client: EmailClient):
	print("")
	MAILBOX_MENU.open(client)
	print("")


def decrypt_file_contents(client: EmailClient):
	path = input("enter file path: ")
	with open(path, "r") as f:
		print(decrypt(f.read(), client.priv_key()).decode("utf-8"))
	print("")


def send_pub_key(client: EmailClient):
	address = input("send to: ")
	client.send(address, "PUBLIC KEY TRANSFER", "", False, [pub_key_path(client.email)])
	print("DONE\n")


def add_pub_key_from_file(client: EmailClient):
	key_path = input("path to the public key: ")
	address = input("email address: ")
	with open(key_path, "r") as f:
		pem = f.read()
	add_pub_key(address, pem)
	print("DONE\n")


def gen_new_keys(client: EmailClient):
	print("generating new keys...")
	with open(USER_JSON, "r") as f:
		data = json.load(f)
	client.gen_keys(data["keySize"])
	print("DONE\n")


def connect(client: EmailClient):
	print("connecting to the server...")
	client.connect()


def reconnect(client: EmailClient):
	print("reconnecting to the server...")
	client.connect()
	print("DONE\n")


def handle_exception(client: EmailClient, e: Exception):
	if isinstance(e, IMAP4.error) or isinstance(e, SMTPException):
		connect(client)
		return True
	return False


MAILBOX_MENU_TEXT = """enter:
0 to open an inbox page
1 to read a message from inbox
2 to open a mailbox page
3 to read a message from mailbox
4 to add a public key from message
back to go back"""
MAILBOX_MENU_OPTIONS = {
	"0": open_inbox_page,
	"1": read_inbox_message,
	"2": open_mailbox_page,
	"3": read_mailbox_message,
	"4": add_pub_key_from_message,
}
MAILBOX_MENU = Menu(MAILBOX_MENU_TEXT, MAILBOX_MENU_OPTIONS, exit_state="back", handle_exception=handle_exception)


MAIN_MENU_TEXT = """enter:
0 to encrypt and send a message specified in %s
1 to write and send a message
2 to read mailbox
3 to decrypt file contents
4 to send a public key
5 to add a public key from file
6 to generate new keys
7 to reconnect
exit to exit""" % MESSAGE_JSON
MAIN_MENU_OPTIONS = {
	"0": encrypt_and_send_from_default_json,
	"1": write_and_send,
	"2": open_mailbox_menu,
	"3": decrypt_file_contents,
	"4": send_pub_key,
	"5": add_pub_key_from_file,
	"6": gen_new_keys,
	"7": reconnect,
}
MAIN_MENU = Menu(MAIN_MENU_TEXT, MAIN_MENU_OPTIONS, exit_state="exit", handle_exception=handle_exception)


def open_main_menu(client: EmailClient):
	MAIN_MENU.open(client)
