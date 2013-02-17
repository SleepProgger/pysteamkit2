import hashlib

class Util:
	@staticmethod
	def get_msg(emsg):
		return emsg & ~0x80000000
	@staticmethod
	def is_proto(emsg):
		return emsg & 0x80000000 == 0x80000000
	@staticmethod
	def sha1_hash(input, hex=False):
		sha1 = hashlib.sha1()
		sha1.update(input)
		return sha1.digest() if not hex else sha1.hexdigest()
	@staticmethod
	def lookup_enum(classtype, enum_value):
		for property, value in vars(classtype).iteritems():
			if value == enum_value:
				return property
		return enum_value
	@staticmethod
	def long2ip(l):
		return '%d.%d.%d.%d' % (l>>24 & 255, l>>16 & 255, l>>8 & 255, l & 255)