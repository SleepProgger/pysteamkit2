from crypto import CryptoUtil
from protobuf import content_manifest_pb2
import struct, base64
import zipfile, StringIO

class DepotManifest(object):
	PROTOBUF_PAYLOAD_MAGIC = 0x71F617D0
	PROTOBUF_METADATA_MAGIC = 0x1F4812BE
	PROTOBUF_SIGNATURE_MAGIC = 0x1B81B817
	
	def __init__(self):
		self.metadata = None
		self.payload = None
		self.signature = None
		
	def decrypt_filenames(self, depot_key):
		if not self.metadata.filenames_encrypted:
			return True
			
		for mapping in self.payload.mappings:
			filename = base64.b64decode(mapping.filename)
			
			try:
				filename = CryptoUtil.symmetric_decrypt(filename, depot_key)
			except:
				print("Unable to decrypt filename for depot manifest")
				return False
			
			mapping.filename = filename.rstrip(' \t\r\n\0')

		self.metadata.filenames_encrypted = False
		return True
		
	def parse(self, input):
		zip_buffer = StringIO.StringIO(input)
		with zipfile.ZipFile(zip_buffer, 'r') as zip:
			payload = zip.read('z')
				
		magic, payload_len = struct.unpack_from('<II', payload)
		
		if magic != DepotManifest.PROTOBUF_PAYLOAD_MAGIC:
			raise Exception("Expecting protobuf payload")
			
		self.payload = content_manifest_pb2.ContentManifestPayload()
		self.payload.ParseFromString(payload[8:8+payload_len])

		pos_1 = 8+payload_len
		magic, meta_len = struct.unpack_from('<II', payload[pos_1:])

		if magic != DepotManifest.PROTOBUF_METADATA_MAGIC:
			raise Exception("Expecting protobuf metadata")
		
		self.metadata = content_manifest_pb2.ContentManifestMetadata()
		self.metadata.ParseFromString(payload[8+pos_1:8+pos_1+meta_len])
		
		pos_2 = 8+pos_1+meta_len
		magic, sig_len = struct.unpack_from('<II', payload[pos_2:])

		if magic != DepotManifest.PROTOBUF_SIGNATURE_MAGIC:
			raise Exception("Expecting protobuf signature")
		
		self.signature = content_manifest_pb2.ContentManifestSignature()
		self.signature.ParseFromString(payload[8+pos_2:8+pos_2+sig_len])
