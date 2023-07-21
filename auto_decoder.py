import charset_normalizer
import ftfy

codecs = ["ascii", "cp037", "cp424", "cp437", "cp500", "cp737", "cp775", "cp850", "cp852", 
		  "cp855", "cp856", "cp857", "cp860", "cp861", "cp862", "cp863", "cp864", "cp865", 
		  "cp869", "cp874", "cp875", "cp1006", "cp1026", "cp1140", "cp1250", "cp1251", "cp1252", 
		  "cp1253", "cp1254", "cp1255", "cp1256", "cp1257", "cp1258", "latin_1", "iso8859_2", 
		  "iso8859_3", "iso8859_4", "iso8859_5", "iso8859_6", "iso8859_7", "iso8859_8", 
		  "iso8859_9", "iso8859_10", "iso8859_13", "iso8859_14", "iso8859_15", "koi8_r", "koi8_u", 
		  "mac_cyrillic", "mac_greek", "mac_iceland", "mac_latin2", "mac_roman", "mac_turkish", 
		  "utf_16", "utf_16_be", "utf_16_le", "utf_7", "utf_8"]


def count_diff(string_1, string_2):
	count = 0
	for c_1, c_2 in zip(string_1, string_2):
		if c_1 == " " or c_2 == " ":
			continue
		if c_1 != c_2:
			count += 1
	print(count, string_2)
	return count


def detect_encodings(broken_str: str):
	matches = []
	found_language = False
	for codec in codecs:
		try:
			enc = broken_str.encode(codec)
			detection = charset_normalizer.detect(enc)
			confidence = detection["confidence"]
			if confidence is None:
				continue
		except (UnicodeEncodeError, UnicodeDecodeError):
			continue
		if detection["language"] != "":
			found_language = True
		detection["encoding"] = codec
		matches.append(detection)
	if len(matches) == 0:
		raise ValueError("encoding not found")
	if found_language:
		matches = filter(lambda x: x["language"] != "", matches)
	return [match["encoding"] for match in sorted(matches, key=lambda x: x["confidence"])]


def detect_decodings(broken_bytes: bytes):
	matches = {}
	for codec in codecs:
		try:
			dec = broken_bytes.decode(codec)
			confidence = charset_normalizer.detect(dec.encode("utf-8"))
		except (UnicodeEncodeError, UnicodeDecodeError):
			continue
		if not ftfy.is_bad(dec):
			matches[codec] = confidence
	if len(matches) == 0:
		raise ValueError("decoding not found")
	return sorted(matches)


def fix_encoding(broken_str: str, encodings=None, decodings=None, depth=5):
	possible_fixes = []
	try:
		for encoding in encodings or detect_encodings(broken_str)[:depth]:
			enc = broken_str.encode(encoding)
			print("encoding:", encoding)
			for decoding in decodings or detect_decodings(enc)[:depth]:
				dec = enc.decode(decoding)
				possible_fixes.append(dec)
				print(f"\tdecoding:\t{decoding}\t{enc.decode(decoding)}")
	except ValueError as e:
		print(e)
		return broken_str
	
	print(possible_fixes)
	
	return sorted(possible_fixes, key=lambda x: count_diff(broken_str, x))


def test():
	# broken_str = "РџРѕ СЂСѓСЃСЃРєРё РЅР°СѓС‡РёСЃСЊ СЃРЅР°С‡Р°Р»Р° РіРѕРІРѕСЂРёС‚СЊ"
	broken_str = "çàäàåì ñèñòåìó äèôô. óðàâíåíèé"
	# broken_str = input()
	possible_fixes = fix_encoding(broken_str)
	print(possible_fixes)
	# print("\n".join(fix_encoding(broken_str)))
	fixed_str = ftfy.fix_encoding(broken_str)
	# print(fixed_str, explain)
	# print(fixed_str)


if __name__ == "__main__":
	test()
