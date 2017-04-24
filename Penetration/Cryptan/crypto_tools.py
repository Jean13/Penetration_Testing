# A collection of useful little tools for encryption/decryption.


def xor(data, key):
	return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(data, key))


def Hex2Raw(string):
	from binascii import unhexlify
	raw = unhexlify(string)
	return raw


def toBase64(string):
	from binascii import b2a_base64
	base64 = b2a_base64(string)
	return base64


def toHex(string):
	in_hex = string.encode('hex')
	return in_hex


def toLittleEndian(string):
	little_endian = '0x' + "".join(reversed([string[i:i+2] 
		for i in range(0, len(string), 2)]))
	return little_endian


def xorHex(string1, string2):
	xored = ""
	for x,y in zip(string1, string2):
		xored += chr(ord(x) ^ ord(y))

	fixed_xor = xored.encode('hex')
	return fixed_xor


def score(string):
	freq = dict()

	# English character frequency
	# See: https://www.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
	freq['a'] = 812
	freq['b'] = 149
	freq['c'] = 271
	freq['d'] = 432
	freq['e'] = 1202
	freq['f'] = 230
	freq['g'] = 203
	freq['h'] = 592
	freq['i'] = 731
	freq['j'] = 10
	freq['k'] = 69
	freq['l'] = 398
	freq['m'] = 261
	freq['n'] = 695
	freq['o'] = 768
	freq['p'] = 182
	freq['q'] = 11
	freq['r'] = 602
	freq['s'] = 628
	freq['t'] = 910
	freq['u'] = 288
	freq['v'] = 111
	freq['w'] = 209
	freq['x'] = 17
	freq['y'] = 211
	freq['z'] = 7
	freq[' '] = 2320

	the_score = 0

	# Scoring
	for c in string.lower():
		if c in freq:
			the_score += freq[c]

	return the_score


def singleByteXORDecrypt(enc, k):
	decrypted = ''.join(chr(ord(i) ^ k) for i in enc)

	return decrypted


def repeatingKeyXOR(data, k):
	# Cycle through the given key
	key = cycle(k)

	# Encrypted with repeating-key XOR
	encrypted = ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(data, key))

	return encrypted


# Computes the hamming distance (the number of differing bits) between two strings
def hamming(x, y):
    assert(len(x) == len(y))

    def popcount(a):
        if a == 0:
            return 0
        else:
            return (a % 2) + popcount(a / 2)

    return sum(popcount(ord(a) ^ ord(b)) for a, b in zip(x, y))


# Normalizes the hamming distance
def norm_distance(keysize):
	numblocks = (len(data) / keysize)
	blocksum = 0

	for i in range(numblocks - 1):
		a = data[i * keysize: (i + 1) * keysize]
		b = data[(i + 1) * keysize: (i + 2) * keysize]
		blocksum += hamming(a, b)

	# Normalizing the result
	blocksum /= float(numblocks)
	blocksum /= float(keysize)
	return blocksum


# Determines the key in a repeating-key algorithm
def repeating_key(upper_key_range):
	keysize = min(range(2, int(upper_key_range)), key=norm_distance)
	print "[*] Determined keysize =", keysize

	key = [None] * keysize

	for i in range(keysize):
		d = data[i::keysize]
		key[i] = max(range(256), key=lambda k: score(xor(d, k)))

	key = ''.join(map(chr,key))
	return key


# Detect Single-Character XOR
def detect_SC_XOR(data):
	from tqdm import tqdm

	keys = [max(range(256), key=lambda k: score(singleByteXORDecrypt(e, k))) for e in tqdm(data)]

	decrypted = [singleByteXORDecrypt(e, k) for e, k in zip(data, keys)]

	result = max(decrypted, key=score)
	return result


def AES_ECB_encrypt(data, key):
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)


def AES_ECB_decrypt(data, key):
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(data)


# Detect data that has been encrypted with ECB
def is_ecb_encoded(ciphertext, block_size):
	# Creating a set to test for membership 
	# ECB is stateless and deterministic, meaning that the same 16-byte plaintext block
	# will always produce the same 16-byte ciphertext
	blocks = set()
	
	for beginning in range(0, len(ciphertext), block_size):
		# Creating blocks of appropriate block size
		block = ciphertext[beginning : beginning + block_size]
		if block in blocks:
			return True
		blocks.add(block)

	return False


# Takes a message and pads it to the desired block size.
def pad(data, block_size):
	new_msg_len = (len(data) / block_size + 1) * block_size
	padding = new_msg_len - len(data)
	padded = data + chr(padding) * padding
	return padded


def unpad(data, block_size):
	if len(data) % block_size != 0:
		raise Exception

	to_unpad = ord(data[-1])

	if to_unpad < 0 or to_unpad > block_size:
		raise Exception

	if data[-to_unpad:] != chr(to_unpad) * to_unpad:
		raise Exception

	return data[:-to_unpad]


# Encrypt data via AES in CBC mode.
def AES_CBC_encrypt(data, key, iv):
	assert(len(key) == 16 or 24 or 32)
	assert(len(iv) == 16 or 24 or 32)
	assert(len(data) % 16 or 24 or 32 == 0)

	encrypted = ''
	key_len = len(key)

	for i in range(0, len(data), key_len):
		block = data[i: i + key_len]
		iv = AES_ECB_encrypt(xor(iv, block), key)
		encrypted += iv

	return encrypted


# Breaks base64-encoded data that has been encrypted via AES in CBC mode.
def AES_CBC_decrypt(data, key, iv):
	assert(len(key) == 16 or 24 or 32)
	assert(len(iv) == 16 or 24 or 32)
	assert(len(data) % 16 or 24 or 32 == 0)

	decrypted = ""
	key_len = len(key)

	for i in range(0, len(data), key_len):
	# In CBC mode, the first plaintext block, which has no associated previous
	# ciphertext block, is added to a fake block called the "initialization vector"
		decrypted += xor(iv, AES_ECB_decrypt(data[i: i + key_len], key))
		iv = data[i : i + key_len]

	return decrypted


def encrypt_ECB_or_CBC(data):
	from random import randint
	from crypto_tools import pad
	from crypto_tools import AES_CBC_encrypt
	from crypto_tools import AES_ECB_encrypt

	def rand_k(n):
		return ''.join(chr(randint(0, 255)) for _ in range(n))

	# Appending 5-10 bytes chosen at random
	data = rand_k(randint(5, 10)) + data + rand_k(randint(5,10))
	data = pad(data, 16)

	if randint(0, 1) == 0:
		cipher = AES_ECB_encrypt(data, rand_k(16))

	else:
		cipher = AES_CBC_encrypt(data, rand_k(16), rand_k(16))

	return cipher


def detect_ECB_or_CBC(data):
	from crypto_tools import is_ecb_encoded

	guess = is_ecb_encoded(data, 16)

	if guess:
		return "[*] Encryption Mode Detected: ECB"
	else:
		return "[*] Encryption Mode Detected: CBC"


def rand_k(n):
	from random import randint
	return ''.join(chr(randint(0, 255)) for _ in range(n))


def get_block_size(oracle):
	i = 0
	prev_size = len(oracle(''))
	while True:
		i += 1
		new_size = len(oracle('A' * i))
		if new_size > prev_size:
			block_size = new_size - prev_size
			return block_size


def block_size_minus_one(oracle):
	i = 0
	prev_size = len(oracle(''))

	while True:
		i += 1
		new_size = len(oracle('A' * i))
		if new_size > prev_size:
			bz_minus_one = prev_size - i
			return bz_minus_one


# Byte-at-a-time ECB decryption
# Breaks encrypted ECB data through repeated calls to the oracle function
def bAAT_ECB_decrypt(oracle):
	from crypto_tools import get_block_size
	from crypto_tools import block_size_minus_one

	block_size = get_block_size(oracle)
	decrypted = ""

	for _ in range(block_size_minus_one(oracle)):
		block = 'A' * ((block_size - len(decrypted) - 1) % block_size)
		encrypted_len = len(block) + len(decrypted) + 1

		assert(encrypted_len % block_size == 0)

		encrypted_block = oracle(block)[:encrypted_len]

		for i in range(256):
			current = block + decrypted + chr(i)
			encrypted_current = oracle(current)[:encrypted_len]
			if encrypted_block == encrypted_current:
				decrypted += chr(i)
				break

	return decrypted


# Returns a modified oracle with the prefix removed
def remove_prefix(oracle):
	block_size = get_block_size(oracle)

	def get_info():
		prefixer = '\x00' * block_size
		i = 0

		while True:
			# Using i to keep track of the prefix length
			enc = oracle(prefixer + '\x00' * i)
			for b in range(0, len(enc) - 2 * 16, 16):
				# If the following is true, then b:b+48 is the prefix
				if enc[b:b+16] == enc[b+16:b+32] == enc[b+32:b+48]:
					return (prefixer + '\x00' * i, b + 48)
			i += 1

	prefix, root = get_info()

	def modified_oracle(data):
		return oracle(prefix + data)[root:]

	return modified_oracle


def verify_pkcs7_padding(data):
	try:
		original = data
		unpaded = unpad(original, 16)
		print "Original data:", original
		print "Verified data:", unpaded
		print

	except:
		print "Original data:", original
		print "[!] Invalid padding!"
		print


'''
Modify an AES-CBC-encrypted ciphertext to include an arbitrary string, without knowing the key
'''
def modify_CBC():

	# Using test encryption oracle; for real-scenario use, replace with real ciphertext
	prefix = encryption('')
	data = encryption('A' * (16 * 3))

	for i in range(0, len(prefix), 16):
		# If the prefix block is not the same as the data block
		if prefix[i : i + 16] != data[i : i + 16]:
			attack = data[:i]
			# Using XOR to pass our string
			attack += xor(data[i : i + 16], xor(";admin=true;xxxx", 'A' * 16))
			attack += data[i + 16:]
			break

	# If successful
	if decryption(attack):
		print "[*] Admin access granted.\n"
	else:
		print "[!] Attack failed.\n"





# Add more...


