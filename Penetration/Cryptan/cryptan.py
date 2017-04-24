'''
<Cryptan Cryptography Program>

Currently has the following capabilities:
    * Format conversion: Hex, Ascii, Decimal, Octal, Binary
    * XOR Encryption/Decryption
    * Caesar Cipher Encryption/Decryption
    * Caesar Cipher Brute-force Decryption
    * Single Byte XOR Decryption
    * Single Character XOR Detection & Decryption
    * Repeating-Key XOR (Vigenere) Decryption
    * AES-ECB Detection
    * AES-ECB Decryption
    * PKCS#7 Padding
    * AES-CBC Decryption
    * ECB/CBC Detection
    * ECB Cut-and-Paste
    * Byte-At-A-Time ECB Decryption
    * PKCS#7 Padding Validation
    * CBC Bitflipping Attack


Currently working on adding:
    * A lot more functionality (:
'''

import sys

from format_convert import ascToHex
from format_convert import toLittleEndian
from format_convert import toDecimal
from format_convert import toAscii
from format_convert import toOctal
from format_convert import hexToBin
from format_convert import binToHex
from format_convert import decToHex
from format_convert import hexToB64

from crypto_tools import Hex2Raw
from crypto_tools import xorHex
from crypto_tools import score
from crypto_tools import singleByteXORDecrypt
from crypto_tools import detect_SC_XOR
from crypto_tools import hamming
from crypto_tools import is_ecb_encoded
from crypto_tools import AES_ECB_decrypt
from crypto_tools import pad
from crypto_tools import AES_CBC_decrypt
from crypto_tools import rand_k
from crypto_tools import encrypt_ECB_or_CBC
from crypto_tools import detect_ECB_or_CBC
from crypto_tools import unpad
from crypto_tools import verify_pkcs7_padding

from itertools import cycle
from binascii import unhexlify


def main():
    global data
    if len(sys.argv[1:]) != 1:
        print '''
<Cryptan Cryptography Program>

-1  : Format conversion: Hex, Ascii, Decimal, Octal, Binary, Base64
-2  : XOR Encryption/Decryption
-3  : Caesar Cipher Encryption/Decryption
-4  : Caesar Cipher Brute-force Decryption
-5  : Single Byte XOR Decryption
-6  : Single Character XOR Detection & Decryption
-7  : Repeating-Key XOR (Vigenere) Decryption
-8  : AES-ECB Detection
-9  : AES-ECB Decryption
-10  : PKCS#7 Padding
-11  : AES-CBC Decryption			
-12  : ECB/CBC Detection			
-13  : ECB Cut-and-Paste			[Under work]
-14  : Byte-At-A-Time ECB Decryption		[Under work]
-15  : PKCS#7 Padding Validation		
-16  : CBC Bitflipping Attack			[Under work]
        '''
        sys.exit(0)

    option = sys.argv[1]


    if option == "-1":
        print '''
Options:
-asc2hex    : Ascii to hex
-2ascii     : Hex to ascii
-2dec       : To decimal
-2oct       : To octal
-2le        : Big endian to little endian
-hex2bin    : Hex to binary
-bin2hex    : Binary to hex
-dec2hex    : Decimal to hex
-hex2b64    : Hex to base64
        '''

        mode = raw_input("Select an option: ")
        to_convert = raw_input("String to be converted: ")

        if mode == '-asc2hex':
            in_hex = ascToHex(to_convert)
            little_endian = toLittleEndian(in_hex)
            print 'Original:', to_convert, '\nHex:', '0x' + in_hex
            print 'Little-endian:', little_endian

        elif mode == '-2ascii':
            in_ascii = toAscii(to_convert)
            print 'Original:', to_convert, '\nAscii:', in_ascii
            
	elif mode == '-2dec':
		in_dec = toDecimal(to_convert)
		print 'Original:', to_convert, '\nDecimal:', in_dec

	elif mode == '-2oct':
		in_oct = toOctal(to_convert)
		print 'Original:', to_convert, '\nOctal:', in_oct, '\n\n[!] Note: Remove any extra leading zeroes.'

	elif mode == '-2le':
		inpt = toAscii(to_convert)
		in_hex = ascToHex(inpt)
		in_LE = toLittleEndian(in_hex)
		print 'Original:', '0x' + to_convert, '\nLittle-endian:', in_LE

	elif mode == '-hex2bin':
		in_bin = hexToBin(to_convert)
		print 'Originial:', to_convert, '\nBinary:', in_bin

	elif mode == '-bin2hex':
		in_hex = binToHex(to_convert)
		print in_hex

	elif mode == '-dec2hex':
		in_hex = decToHex(to_convert)
		print in_hex

	elif mode == '-hex2b64':
		in_b64 = hexToB64(to_convert)
		print in_b64

	else:
		print 'Improper format. Review and re-submit.\n'
		sys.exit(0)


    if option == "-2":
        to_convert = raw_input("First string: ")
        xor_against = raw_input("Second string: ")

        raw1 = Hex2Raw(to_convert)
        raw2 = Hex2Raw(xor_against)

        xor_result = xorHex(raw1, raw2)

        print "XOR combination:", xor_result

    
    if option == "-3":
        try:
            from caesar_cipher import getOption
            from caesar_cipher import getMessage
            from caesar_cipher import getKey
            from caesar_cipher import getConvertedMessage
            do = getOption()
            message = getMessage()
            key = getKey()

            print "Your converted text is: "
            print getConvertedMessage(do, message, key)

        except:
            sys.exit(0)


    if option == "-4":
        try:
            from caesar_bruteforce import caesar_bruteforce
            from caesar_bruteforce import getMessage
            message = getMessage
            print caesar_bruteforce(message)

        except:
            sys.exit(0)


    if option == "-5":
        to_convert = raw_input("Encrypted string: ")
        enc = Hex2Raw(to_convert)

        try: 
            key = max(range(256), key=lambda k: score(singleByteXORDecrypt(enc, k)))

            print "Key: ", key
            print "Decrypted message: ", singleByteXORDecrypt(enc, key)

        except Exception as e:
            print e
            sys.exit(0)


    if option == "-6":
        data = raw_input("Enter the filepath of the file to decrypt: ")
        with open(data, 'r') as f:
            data = f.read().split()
            data = [unhexlify(i) for i in data]

        decrypted = detect_SC_XOR(data)
        print "Decrypted: ", decrypted


    if option == "-7":

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
                key[i] = max(range(256), key=lambda k: score(singleByteXORDecrypt(d, k)))

            key = ''.join(map(chr,key))
            return key

        try:
            filename = raw_input("Enter the filepath of the file to decrypt: ")
            with open(filename, 'r') as f:
                enco = raw_input("Is the file hex-encoded or base64-encoded? Type h or b.\n: ")

                if enco == 'b':
                    data = f.read().decode('base64')
                elif enco == 'h':
                    inp = f.read().strip()
                    data = unhexlify(inp)
                else:
                    print "Please type either h or b."

        except Exception as e:
            print e
            sys.exit(0)

        # Using three different upper key ranges to improve chances of proper decryption
        range1 = int(raw_input("Enter the first upper key range: "))
        range2 = int(raw_input("Enter the second upper key range: "))
        range3 = int(raw_input("Enter the third upper key range: "))

        ranges = []
        ranges.append(range1)
        ranges.append(range2)
        ranges.append(range3)

        for key in ranges:
            print "[*] Using key range: ", key
            k = repeating_key(key)

            print "[*] Determined key =", repr(k)
            print

            decrypted = ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(data, cycle(k)))

            print decrypted


    if option == "-8":
        data = raw_input("Enter the filepath of the file to be decrypted: ")
        with open(data, 'r') as f:
            data = f.read().split()

            for i, d in enumerate(data):
                if is_ecb_encoded(d, 16):
                    print "Encrypted ciphertext: "
                    print i, d
                    print


    if option == "-9":
        try:
            data = raw_input("Enter the filepath of the file to be decrypted: ")
            with open(data, 'r') as f:
                enco = raw_input("Is the file hex-encoded or base64-encoded? Type 'h' or 'b'.\n")
                if enco == 'b':
                    data = f.read().decode('base64')
                elif enco == 'h':
                    inp = f.read().strip()
                    data = unhexlify(inp)
                else:
                    print "Please type either the letter h or b."

                key = raw_input("Enter the key: ")

                print AES_ECB_decrypt(data, key)

        except Exception as e:
            print e
            sys.exit(0)


    if option == "-10":
        data = raw_input("Enter the message you would like to pad:\n")
        block_size = int(raw_input("Enter your desired block size:\n"))

        print "\n[*] Padded message:"
        print repr(pad(data, block_size))
        print


    if option == "-11":
        try:
            data = raw_input("Enter the filepath of the file to decrypt: ")
            with open(data, 'r') as f:
                enco = raw_input("Is the file hex-encoded or base64-encoded? Type 'h' or 'b'.\n")
                if enco == 'b':
                    data = f.read().decode('base64')
                elif enco == 'h':
                    inp = f.read().strip()
                    data = unhexlify(inp)
                else:
                    print "Please type either the letter h or b."

                key = raw_input("Enter the key: ")
                iv = raw_input("Enter the initialization vector (IV): ")

                print AES_CBC_decrypt(data, key, iv)

        except Exception as e:
            print e
            sys.exit(0)


    if option == "-12":
        try:
            data = raw_input("Enter the filepath of the file to decrypt: ")
            with open(data, 'r') as f:
                data = f.read()

                # for loop to confirm it is working
                for i in range(20):
                    oracle = encrypt_ECB_or_CBC(data)
                    guess = detect_ECB_or_CBC(oracle)
                    print guess

        except Exception as e:
            print e
            sys.exit(0)



    if option == "-15":
        print "[*] Edit Cryptan and enter the string into the array, then run Cryptan again.\n"
        padded = ["ICE ICE BABY\x04\x04\x04\x04"]
        for s in padded:
            verify_pkcs7_padding(s)




main()


