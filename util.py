class Util:
	@staticmethod
	def get_msg(emsg):
		return emsg & ~0x80000000
	@staticmethod
	def is_proto(emsg):
		return emsg & 0x80000000 == 0x80000000