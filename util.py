import hashlib

class Util:
	@staticmethod
	def get_msg(emsg):
		return emsg & ~0x80000000
	@staticmethod
	def is_proto(emsg):
		return emsg & 0x80000000 == 0x80000000
	@staticmethod
	def sha1_hash(input):
		sha1 = hashlib.sha1()
		sha1.update(input)
		return sha1.digest()
	@staticmethod
	def lookup_enum(classtype, enum_value):
		for property, value in vars(classtype).iteritems():
			if value == enum_value:
				return property
		return enum_value