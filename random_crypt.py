"""
RandomCrypt - XOR cypher with randomness sprinkled in
Copyright 2006 Seth Black

The purpose of this method is to allow encrypted data to be stored on
client storage while minimizing the probability of brute-force attack.
"""

from base64 import b64encode
import ctypes
import random
import string

class RandomCrypt():
    def __init__(self, key):
	self.key = key
	self.key_bytes = bytearray(self.key)
	self.key_length = len(self.key_bytes)

    def randomize(self, value):
	randomized_string = [value[i / 2] if i % 2 else random.choice(string.ascii_letters) for i in xrange(len(value) * 2)]
	return bytearray(randomized_string)

    def derandomize(self, value):
	normal_string = [value[(i * 2) + 1] for i in xrange(len(value) / 2)]
	return bytearray(normal_string)

    def encrypt(self, value):
	return self.digest(self.randomize(value))
	#return self.digest(value)

    def decrypt(self, value):
	return self.derandomize(self.digest(value, True))
	#return self.digest(value, True)

    def digest(self, value, decrypt = False):
	value_bytes = bytearray(value)
	value_length = len(value_bytes)
	outbytes = bytearray()
	salt = int(0)

	for i in xrange(value_length):
	    if decrypt == True and i >= 1:
		salt += int(value_bytes[i - 1])

	    b = value_bytes[i] ^ self.key_bytes[i % self.key_length] & salt

	    if decrypt == False:
		salt += int(b)

	    outbytes.append(b)

	return outbytes

def main():
    string = 'seth'
    key = 'key'

    e = RandomCrypt(key)

    encrypted = e.encrypt(string)
    decrypted = e.decrypt(encrypted)

    print("Original : %s" % (string))
    print("Encrypted: %s" % (b64encode(encrypted)))
    print("Decrypted: %s" % (decrypted))

if __name__ == '__main__':
    main()
