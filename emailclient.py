import os
import json
import re
import colors
import sys

from pwinput import pwinput
from rsa import DecryptionError
from smtplib import SMTP_SSL, SMTPAuthenticationError
from imaplib import IMAP4_SSL, IMAP4
from email.message import Message
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email import message_from_bytes
from email.header import decode_header
from os.path import basename
from typing import Union
from crypto import gen_keys, load_pub_key, load_priv_key, encrypt, keys_folder, is_pem, decrypt, hpasswd_exists, \
	save_passwd, check_passwd, pub_key_path, priv_key_path, simple_decrypt, simple_encrypt, is_image, decrypt_image, \
	encrypt_file
from colors import dye
from auto_decoder import fix_encoding


ROOT_FILES_FOLDER = "files"
MAIL_SMTP_ADDR = "smtp.mail.ru"
MAIL_SMTP_PORT = 465
MAIL_IMAP_ADDR = "imap.mail.ru"
MAIL_IMAP_PORT = 993
USER_JSON = "user.json"
MESSAGE_JSON = "message.json"
HEMAILPASSWD_PATH = "hemailpasswd"
IV = b"\xc8\xe7\xb0\xf9\x95\xa3V\x1e\xcd\xef\xbaw\xdb\xfc\xf9\xd1"


def passwd_input(prompt=""):
	if "sitecustomize" in sys.modules:
		return input(prompt)
	return pwinput(prompt)


def init_emailclient():
	if not os.path.isdir(ROOT_FILES_FOLDER):
		os.mkdir(ROOT_FILES_FOLDER)


def files_folder(i_message):
	return ROOT_FILES_FOLDER + "/" + str(i_message)


def clean(text):
	# clean text for creating a folder
	return "".join(c if c.isalnum() else "_" for c in text)


def obtain_header(msg: Message):
	# decode the email subject
	subject, encoding = decode_header(msg["Subject"])[0]
	if encoding is None:
		encoding = "utf-8"
	if isinstance(subject, bytes):
		subject = subject.decode(encoding)
	
	# decode email sender
	sent_from, encoding = decode_header(msg.get("From"))[0]
	if isinstance(sent_from, bytes):
		sent_from = sent_from.decode(encoding)
	
	datetime = decode_header(msg.get("Date"))[0][0]
	return subject, sent_from, datetime


def obtain_body(msg: Message, priv_key=None, dye_=False):
	body = msg.get_payload(decode=True).decode("utf-8")
	if priv_key is not None and is_pem(body):
		try:
			dec = fix_encoding(decrypt(body, priv_key).decode("utf-8"), decoding="utf-8")
			if dye_:
				dec = dye(dec, colors.GREEN)
			return dec
		except DecryptionError:
			pass
		if dye_:
			body = dye(body, colors.RED)
	return body


def print_header(subject, sent_from, datetime):
	subject = dye(subject, colors.WHITE, 1)
	sent_from = dye(sent_from, colors.WHITE, 1)
	datetime = dye(datetime, colors.WHITE, 1)
	print(f"Subject:{subject}\nFrom:{sent_from}\nDate:{datetime}")


def download_attachment(part, i_message, priv_key=None, path=None):
	filename = part.get_filename()
	if not filename:
		return
	folder = files_folder(i_message)
	if not os.path.isdir(folder):
		os.mkdir(folder)
	if path is None:
		path = folder + "/" + filename
	i = 2
	basepath, extension = os.path.splitext(path)
	while os.path.exists(path):
		path = f"{basepath}-{i}{extension}"
		i += 1
	
	if not is_image(filename):
		with open(path, "w") as f:
			f.write(obtain_body(part, priv_key))
		return
	payload = part.get_payload(decode=True)
	try:
		contents = payload.decode("ascii")
		if priv_key is not None and is_pem(contents):
			print("decrypting image...")
			with open(path, "wb") as f:
				f.write(decrypt_image(contents, priv_key))
			return
		with open(path, "wb") as f:
			f.write(payload)
	except UnicodeDecodeError:
		with open(path, "wb") as f:
			f.write(payload)


class EmailClient:
	def __init__(self, user_json_path=USER_JSON):
		self.__passwd = None
		self.__enter_or_create_passwd()
		user_data = self.load_or_create_user_data(user_json_path)
		self.email = user_data["email"]
		self.__emailpasswd = user_data["passphrase"]
		nbits = user_data["keySize"]
		self.smtp = None
		self.imap = None
		self.connect()
		if not os.path.isdir(keys_folder(self.email)) or \
				not os.path.exists(pub_key_path(self.email)) or \
				not os.path.exists(priv_key_path(self.email)):
			print("generating new keys...")
			self.gen_keys(nbits)
			print("DONE")
	
	def __enter_or_create_passwd(self):
		if not hpasswd_exists():
			self.__create_passwd()
			return
		self.__enter_passwd()
	
	def __create_passwd(self):
		if hpasswd_exists():
			raise OSError("password has been already created")
		while True:
			passwd = passwd_input("create a password: ")
			repeated_passwd = passwd_input("repeat: ")
			if passwd == repeated_passwd:
				break
			print("password mismatch")
		save_passwd(passwd)
		self.__passwd = passwd

	def __enter_passwd(self):
		if hpasswd_exists():
			while True:
				passwd = passwd_input("enter the password: ")
				if check_passwd(passwd):
					break
				print("wrong password")
			self.__passwd = passwd

	def create_user_data(self, user_json_path=USER_JSON):
		user_data = {
			"email": input("enter your mail.ru address: "),
			"keySize": 4096
		}
		with open(user_json_path, "w") as f:
			json.dump(user_data, f)
		self.__enter_emailpasswd()
		user_data["passphrase"] = self.__emailpasswd
		return user_data

	def load_or_create_user_data(self, user_json_path=USER_JSON):
		if not os.path.exists(user_json_path):
			user_data = {
				"email": input("enter your mail.ru address: "),
				"keySize": 4096
			}
			with open(user_json_path, "w") as f:
				json.dump(user_data, f)
		else:
			with open(user_json_path, "r") as f:
				user_data = json.load(f)
		self.__load_or_enter_emailpasswd()
		user_data["passphrase"] = self.__emailpasswd
		return user_data

	def __enter_emailpasswd(self):
		self.__emailpasswd = passwd_input("enter mail.ru application passphrase: ")
		with open(HEMAILPASSWD_PATH, "wb") as f:
			f.write(simple_encrypt(self.__passwd, IV, self.__emailpasswd))

	def __load_or_enter_emailpasswd(self):
		if not os.path.exists(HEMAILPASSWD_PATH):
			self.__enter_emailpasswd()
			return
		with open(HEMAILPASSWD_PATH, "rb") as f:
			self.__emailpasswd = simple_decrypt(self.__passwd, IV, f.read())

	def gen_keys(self, nbits):
		gen_keys(nbits, keys_folder(self.email), self.__passwd, IV)
	
	def priv_key(self):
		try:
			return load_priv_key(keys_folder(self.email), self.__passwd, IV)
		except DecryptionError as e:
			print(e)
			self.__enter_passwd()

	def pub_key(self, address=None):
		if address is None:
			address = self.email
		return load_pub_key(keys_folder(address))

	def connect(self):
		try:
			self.smtp = SMTP_SSL(MAIL_SMTP_ADDR, MAIL_SMTP_PORT)
			self.smtp.login(self.email, self.__emailpasswd)
			self.imap = IMAP4_SSL(MAIL_IMAP_ADDR, MAIL_IMAP_PORT)
			self.imap.login(self.email, self.__emailpasswd)
		except (IMAP4.error, SMTPAuthenticationError):
			print("failed to sign in")
			self.create_user_data()
			self.connect()
			
	def disconnect(self):
		try:
			self.smtp.quit()
		except (Exception,):
			pass
		try:
			self.imap.close()
		except (Exception,):
			pass

	def send_from_json(self, path=MESSAGE_JSON):
		with open(path, "r") as f:
			data = json.load(f)
		self.send(data["sendTo"], data["subject"], data["text"], data["files"], data["encryptMessage"])

	def new_message(self, send_from, send_to: str, subject: str, text: Union[str, bytes], encrypt_message=False, files=None):
		msg = MIMEMultipart()
		msg["From"] = send_from
		msg["To"] = send_to
		msg["Subject"] = subject
		for file in files or []:
			if encrypt_message:
				contents = encrypt_file(file, self.pub_key(send_to))
			else:
				with open(file, "rb") as f:
					contents = f.read()
			part = MIMEApplication(contents, Name=basename(file))
			part["Content-Disposition"] = f"attachment; filename=\"{basename(file)}\""
			msg.attach(part)
		if encrypt_message:
			text = encrypt(text, self.pub_key(send_to)).decode("utf-8")
		msg.attach(MIMEText(text, _charset="utf-8"))
		return msg

	def send(self, send_to, subject, text, encrypt_message=False, files=None):
		msg = self.new_message(self.email, send_to, subject, text, encrypt_message, files)
		self.smtp.sendmail(self.email, send_to, msg.as_string())

	def view_mailbox(self, page=0, mailbox="INBOX"):
		messages = self.imap.select(mailbox)
		n = int(messages[1][0])  # get number of messages

		for i in range(n - page * 10, n - (page + 1) * 10, -1):
			res, msg = self.imap.fetch(str(i), "(RFC822)")  # fetches email using ID

			for response in filter(lambda x: isinstance(x, tuple), msg):
				msg = message_from_bytes(response[1])
				print(f"\n{i}")
				print_header(*obtain_header(msg))

	def view_message(self, i_message, mailbox="INBOX"):
		self.imap.select(mailbox)
		res, msg = self.imap.fetch(str(i_message), "(RFC822)")  # fetches email using ID

		for response in filter(lambda x: isinstance(x, tuple), msg):
			msg = message_from_bytes(response[1])
			subject, sent_from, datetime = obtain_header(msg)
			print("")
			print_header(subject, sent_from, datetime)

			if not msg.is_multipart():
				print(obtain_body(msg, self.priv_key(), True))
				continue

			# iterate over email parts
			for part in msg.walk():
				# extract content type of email
				content_type = part.get_content_type()
				content_disposition = str(part.get("Content-Disposition"))

				if content_type == "text/plain" and "attachment" not in content_disposition:
					try:
						print(obtain_body(part, self.priv_key(), True))
					except (Exception,):
						pass
				elif "attachment" in content_disposition:
					download_attachment(part, i_message, self.priv_key())

	def get_author(self, i_message, mailbox="INBOX"):
		self.imap.select(mailbox)
		res, msg = self.imap.fetch(str(i_message), "(RFC822)")  # fetches email using ID
		for response in filter(lambda x: isinstance(x, tuple), msg):
			msg = message_from_bytes(response[1])
			return re.sub(r"[(){}<>\[\]]", "", msg.get("Return-path").split()[-1])
		return None

	def get_attachments(self, i_message, mailbox="INBOX"):
		self.imap.select(mailbox)
		res, msg = self.imap.fetch(str(i_message), "(RFC822)")  # fetches email using ID
		attachments = []

		for response in filter(lambda x: isinstance(x, tuple), msg):
			msg = message_from_bytes(response[1])

			if not msg.is_multipart():
				continue
			
			attachments += [part for part in msg.walk() if "attachment" in str(part.get("Content-Disposition"))]
		return attachments

	def get_mailbox_list(self):
		return [entry.decode("utf-8").split()[-1].strip("\"") for entry in self.imap.list()[1]]
