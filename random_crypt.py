"""
RandomCrypt - XOR cypher with randomness sprinkled in
Copyright 2006 Seth Black

The purpose of this method is to allow encrypted data to be stored on
client storage while minimizing the probability of brute-force attack.
"""

from base64 import b64encode
import random
import string

class RandomCrypt():
    def __init__(self, key):
	self.key = key
	self.key_bytes = bytearray(self.key)
	self.key_length = len(self.key_bytes)

    def randomize(self, value):
	random_string = [value[i / 2] if i % 2 else random.choice(string.ascii_letters) for i in xrange(len(value) * 2)]
	return bytearray(random_string)

    def derandomize(self, value):
	normal_string = [value[(i * 2) + 1] for i in xrange(len(value) / 2)]
	return bytearray(normal_string)

    def encrypt(self, value):
	return self.digest(self.randomize(value))

    def decrypt(self, value):
	return self.derandomize(self.digest(value))

    def digest(self, value):
	value_bytes = bytearray(value)
	value_length = len(value_bytes)

	return bytearray([value_bytes[i] ^ self.key_bytes[i % self.key_length] for i in xrange(value_length)])

def main():
    string = 'seth'
    key = 'key'

    e = RandomCrypt(key)

    #random = e.randomize('seth')
    #print e.derandomize(random)

    encrypted = e.encrypt(string)
    decrypted = e.decrypt(encrypted)

    print("Original : %s" % (string))
    print("Encrypted: %s" % (b64encode(encrypted)))
    print("Decrypted: %s" % (decrypted))

if __name__ == '__main__':
    main()
