import struct
import base64
import StringIO
import zipfile
from operator import attrgetter

from pysteamkit.crypto import CryptoUtil
from pysteamkit.protobuf import content_manifest_pb2


class DepotManifest(object):
	PROTOBUF_PAYLOAD_MAGIC = 0x71F617D0
	PROTOBUF_METADATA_MAGIC = 0x1F4812BE
	PROTOBUF_SIGNATURE_MAGIC = 0x1B81B817
	
	def __init__(self):
		self.metadata = content_manifest_pb2.ContentManifestMetadata()
		self.payload = content_manifest_pb2.ContentManifestPayload()
		self.signature = content_manifest_pb2.ContentManifestSignature()
		
	@property
	def files(self):
		return sorted(self.payload.mappings, key=attrgetter('filename'))
		
	def _files_dictionary(self):
		mapping = dict()
		for file in self.payload.mappings:
			mapping[file.filename] = file
		return mapping
		
	def get_files_changed(self, other):
		my_files = self._files_dictionary()
		other_files = other._files_dictionary()

		new_or_deleted = set(my_files.keys()) ^ set(other_files.keys())
		files_changed = [file.filename for file in other_files.values() if file.filename not in new_or_deleted and my_files[file.filename].sha_content != file.sha_content]
		
		return list(new_or_deleted) + files_changed
	
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

	def serialize(self):
		payload_body = self.payload.SerializeToString()

		payload = struct.pack('<II', DepotManifest.PROTOBUF_PAYLOAD_MAGIC, len(payload_body))
		payload += payload_body
		
		meta_body = self.metadata.SerializeToString()
		
		payload += struct.pack('<II', DepotManifest.PROTOBUF_METADATA_MAGIC, len(meta_body))
		payload += meta_body
		
		signature_body = self.signature.SerializeToString()
		
		payload += struct.pack('<II', DepotManifest.PROTOBUF_SIGNATURE_MAGIC, len(signature_body))
		payload += signature_body
		
		zip_buffer = StringIO.StringIO(input)
		with zipfile.ZipFile(zip_buffer, 'w') as zip:
			zip.writestr('z', payload)
			
		return zip_buffer.getvalue()
