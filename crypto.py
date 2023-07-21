import re
import rsa
import base64
import os

from multiprocessing import cpu_count
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pyasn1.type import univ, namedtype
from pyasn1.codec.der import encoder, decoder
from rsa import common, compute_hash, DecryptionError
from rsa.pem import save_pem, load_pem
from typing import Union


ROOT_KEYS_FOLDER = "keys"
KEY_FILE_NAME = "key"
HPASSWD_PATH = "hpasswd"

base64_pattern = r"([A-Z]|[a-z]|\=|\+|/|\d)"
pem_pattern = r"-+BEGIN .+-+(" + base64_pattern + r"|\n)+-+END .+-+"


def init_crypto():
	if not os.path.isdir(ROOT_KEYS_FOLDER):
		os.mkdir(ROOT_KEYS_FOLDER)


def cut(string, slice_size):
	return [string[i:i + slice_size] for i in range(0, len(string), slice_size)]


def int2bytes(x: int) -> bytes:
	return x.to_bytes((x.bit_length() + 7) // 8, "big")


class AsnData(univ.Sequence):
	componentType = namedtype.NamedTypes(namedtype.NamedType("data", univ.Integer()))


def keys_folder(email):
	return ROOT_KEYS_FOLDER + "/" + email


def pub_key_path(email):
	return keys_folder(email) + "/" + KEY_FILE_NAME + ".pub"


def priv_key_path(email):
	return keys_folder(email) + "/" + KEY_FILE_NAME


def gen_keys(nbits, folder, passwd, iv, file_name=KEY_FILE_NAME):
	if not isinstance(passwd, bytes):
		passwd = passwd.encode("utf-8")
	AES_GCM_key = compute_hash(passwd, "MD5")
	if not os.path.isdir(folder):
		os.mkdir(folder)
	n_cpu = cpu_count() if nbits > 1024 else 1
	pub_key, priv_key = rsa.newkeys(nbits, poolsize=n_cpu)
	# pub_key, priv_key = rsa.newkeys(nbits)
	with open(folder + "/" + file_name + ".pub", "w") as text_file:
		text_file.write(pub_key.save_pkcs1().decode("ascii"))
	with open(folder + "/" + file_name, "wb") as text_file:
		text_file.write(encrypt_AES_GCM(AES_GCM_key, iv, priv_key.save_pkcs1().decode("ascii")))


def check_passwd(passwd: Union[str, bytes]):
	if not isinstance(passwd, bytes):
		passwd = passwd.encode("utf-8")
	return load_hpasswd() == compute_hash(passwd, "SHA-384")


def encrypt_AES_GCM(key, iv, text: Union[str, bytes], associated_data=b""):
	if not isinstance(text, bytes):
		text = text.encode("utf-8")
	return AESGCM(key).encrypt(iv, text, associated_data)


def decrypt_AES_GCM(key, iv, enc: bytes, associated_data=b""):
	return  AESGCM(key).decrypt(iv, enc, associated_data)


def simple_encrypt(passwd: Union[str, bytes], iv, text: Union[str, bytes]):
	if not isinstance(passwd, bytes):
		passwd = passwd.encode("utf-8")
	return encrypt_AES_GCM(compute_hash(passwd, "MD5"), iv, text)


def simple_decrypt(passwd: Union[str, bytes], iv, enc: bytes) -> str:
	if not isinstance(passwd, bytes):
		passwd = passwd.encode("utf-8")
	return decrypt_AES_GCM(compute_hash(passwd, "MD5"), iv, enc).decode("utf-8")


def load_priv_key(path, passwd: Union[str, bytes], iv):
	if not isinstance(passwd, bytes):
		passwd = passwd.encode("utf-8")
	if not check_passwd(passwd):
		raise DecryptionError("wrong password")
	if os.path.isdir(path):
		path = os.path.join(path, KEY_FILE_NAME)
	with open(path, mode="rb") as f:
		AES_GCM_key = compute_hash(passwd, "MD5")
		key_data = decrypt_AES_GCM(AES_GCM_key, iv, f.read())
	return rsa.PrivateKey.load_pkcs1(key_data)


def hpasswd_exists(path=HPASSWD_PATH):
	return os.path.exists(path)


def save_passwd(passwd: Union[str, bytes], path=HPASSWD_PATH):
	if not isinstance(passwd, bytes):
		passwd = passwd.encode("utf-8")
	with open(path, mode="wb") as f:
		hpasswd = compute_hash(passwd, "SHA-384")
		f.write(hpasswd)
	os.chmod(path, 400)


def load_hpasswd(path=HPASSWD_PATH):
	with open(path, mode="rb") as f:
		return f.read()


def load_pub_key(path):
	if os.path.isdir(path):
		path = os.path.join(path, KEY_FILE_NAME + ".pub")
	with open(path, mode="rb") as f:
		key_data = f.read()
	return rsa.PublicKey.load_pkcs1(key_data)


def verify(msg, signature, pub_key):
	signature = base64.b64decode(signature)
	return rsa.verify(msg, signature, pub_key)


def sign(msg, priv_key):
	signature = rsa.sign(msg, priv_key, "SHA-1")
	return base64.b64encode(signature)


def encrypt(data: Union[str, bytes], key) -> bytes:
	pems = b""
	if not isinstance(data, bytes):
		data = data.encode("utf-8")
	slice_size = common.byte_size(key.n) // 2
	for s in cut(data, slice_size):
		enc = rsa.encrypt(s, key)
		asn_data = AsnData().setComponentByName("data", int.from_bytes(enc, byteorder="big"))
		pems += save_pem(encoder.encode(asn_data), "ENCRYPTED DATA")
	return pems


def decrypt(pems_text: Union[str, bytes], priv_key) -> bytes:
	dec = b""
	if isinstance(pems_text, bytes):
		pems_text = pems_text.decode("ascii")
	for match in finditer_pems(pems_text):
		asn_data = decoder.decode(load_pem(match.group(), "ENCRYPTED DATA"), asn1Spec=AsnData())[0]
		enc = int2bytes(int(asn_data["data"]))
		dec += rsa.decrypt(enc, priv_key)
	return dec


def finditer_pems(contents):
	return re.finditer(pem_pattern, contents)


def is_pem(contents):
	return re.search(pem_pattern, contents) is not None


def encrypt_image(image_path, key) -> bytes:
	return encrypt(image_to_base64(image_path), key)


def decrypt_image(enc_image, priv_key) -> bytes:
	return base64_to_image(decrypt(enc_image, priv_key))


def image_to_base64(image_path) -> bytes:
	with open(image_path, "rb") as image_file:
		return base64.b64encode(image_file.read())


def base64_to_image(base64_string: Union[str, bytes]) -> bytes:
	if not isinstance(base64_string, bytes):
		base64_string = base64_string.encode("ascii")
	return base64.b64decode(base64_string)


def is_image(filename):
	return filename.lower().endswith(('.png', '.jpg', '.jpeg', '.tiff', '.bmp', '.gif'))


def encrypt_file(path, key) -> bytes:
	if is_image(path):
		contents = encrypt_image(path, key)
	else:
		with open(path, "rb") as f:
			contents = encrypt(f.read(), key).decode("ascii")
	return contents
