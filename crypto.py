from steam_base import UniverseKeys
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import PKCS1_v1_5
from Crypto import Random

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[0:-ord(s[-1])]

class CryptoUtil:
	@staticmethod
	def create_session_key():
		random = Random.new()
		return random.read(32)
	
	@staticmethod
	def rsa_encrypt(input):
		rsa = RSA.importKey(UniverseKeys.Public)
		cipher = PKCS1_OAEP.new(rsa)
		return cipher.encrypt(input)

	@staticmethod
	def rsa_verify(input, signature):
		rsa = RSA.importKey(UniverseKeys.Public)
		verifier = PKCS1_v1_5.new(rsa)
		h = SHA.new()
		h.update(input)
		return verifier.verify(h, signature)
		
	@staticmethod
	def symmetric_encrypt(input, key):
		random = Random.new()
		iv = random.read(16)
		
		aes = AES.new(key, AES.MODE_ECB)
		crypted_iv = aes.encrypt(iv)
		
		aes = AES.new(key, AES.MODE_CBC, iv)
		encrypted = aes.encrypt(pad(input))
		return crypted_iv + encrypted
		
	@staticmethod
	def symmetric_decrypt(input, key):
		aes = AES.new(key, AES.MODE_ECB)
		decrypted_iv = aes.decrypt(input[:BS])

		aes = AES.new(key, AES.MODE_CBC, decrypted_iv)
		return unpad(aes.decrypt(input[BS:]))
