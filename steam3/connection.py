from gevent import core
from crypto import CryptoUtil
from protobuf import steammessages_base_pb2, steammessages_clientserver_pb2
from steamid import SteamID
from steam_base import EMsg, EUniverse, EResult
from util import Util
import msg_base
import struct, binascii, StringIO, zipfile, socket

class ProtocolError(Exception):
	"""
	Raised when an error has occurred in the Steam protocol
	"""

class SocketException(Exception):
	"""
	Socket error occurred
	"""
	
class NetEncryption():
	def __init__(self, key):
		self.key = key
		
	def process_incoming(self, data):
		return CryptoUtil.symmetric_decrypt(data, self.key)
	
	def process_outgoing(self, data):
		return CryptoUtil.symmetric_encrypt(data, self.key)

class Connection(object):
	def __init__(self, client):
		self.client = client
		
		self.netfilter = None
		
		self.session_id = None
		self.steamid = None
		
	def connect(self, address):
		pass
	
	def disconnect(self):
		pass
		
	def write(self, message):
		pass
		
	def get_bound_address(self):
		pass
		
	def send_message(self, msg):
		if self.session_id:
			msg.header.session_id = self.session_id
		if self.steamid:
			msg.header.steamid = self.steamid
		
		msg = msg.serialize()
		if self.netfilter:
			msg = self.netfilter.process_outgoing(msg)
		buffer = struct.pack('I4s', len(msg), 'VT01') + msg
		self.write(buffer)
		
	def dispatch_message(self, msg):
		emsg_real, = struct.unpack_from('I', msg)
		emsg = Util.get_msg(emsg_real)
		print("dispatch_message", emsg, len(msg))
		
		if emsg == EMsg.ChannelEncryptRequest:
			self.channel_encrypt_request(msg)
		elif emsg == EMsg.ChannelEncryptResult:
			self.channel_encrypt_result(msg)
		elif emsg == EMsg.ClientLogOnResponse:
			self.logon_response(msg)
		elif emsg == EMsg.Multi:
			self.split_multi_message(msg)
			
		self.client.handle_message(emsg_real, msg)	
	
	
	def channel_encrypt_request(self, msg):
		message = msg_base.Message(msg_base.MsgHdr, msg_base.ChannelEncryptRequest)
		message.parse(msg)

		if message.body.protocol_version != 1:
			raise ProtocolError('Unexpected channel encryption protocol')
			
		if message.body.universe != EUniverse.Public:
			raise ProtocolError('Unexpected universe in encryption request')
			
		print("Channel encrypt request. Proto: ", message.body.protocol_version, "Universe: ", message.body.universe)
		
		self.session_key = CryptoUtil.create_session_key()
		crypted_key = CryptoUtil.rsa_encrypt(self.session_key)
		key_crc = binascii.crc32(crypted_key) & 0xFFFFFFFF
		
		response = msg_base.Message(msg_base.MsgHdr, msg_base.ChannelEncryptResponse, EMsg.ChannelEncryptResponse)
		response.body.protocol_version = 1
		response.body.key_size = len(crypted_key)
		response.payload = crypted_key + struct.pack('II', key_crc, 0)

		self.send_message(response)
		
	def channel_encrypt_result(self, msg):
		message = msg_base.Message(msg_base.MsgHdr, msg_base.ChannelEncryptResult)
		message.parse(msg)

		if message.body.result != EResult.OK:
			raise ProtocolError('Unable to negotiate channel encryption')
		
		self.netfilter = NetEncryption(self.session_key)
		self.client.handle_connected()
	
	def heartbeat(self):
		message = msg_base.ProtobufMessage(steammessages_clientserver_pb2.CMsgClientHeartBeat, EMsg.ClientHeartBeat)
		self.send_message(message)
		
	def logon_response(self, msg):
		message = msg_base.ProtobufMessage(steammessages_clientserver_pb2.CMsgClientLogonResponse)
		message.parse(msg)
		
		self.session_id = message.proto_header.client_sessionid
		self.steamid = SteamID(message.proto_header.steamid)
		
		delay = message.body.out_of_game_heartbeat_seconds
		self.heartbeat = core.timer(delay, self.heartbeat)

	def split_multi_message(self, msg):
		message = msg_base.ProtobufMessage(steammessages_base_pb2.CMsgMulti)
		message.parse(msg)
		
		payload = message.body.message_body
		
		if message.body.size_unzipped > 0:
			zip_buffer = StringIO.StringIO(message.body.message_body)
			with zipfile.ZipFile(zip_buffer, 'r') as zip:
				payload = zip.read('z')
		
		i = 0
		while i < len(payload):
			sub_size, = struct.unpack_from('I', payload, i)
			self.dispatch_message(payload[i+4:i+4+sub_size])
			i += sub_size + 4
		
class TCPConnection(Connection):
	def __init__(self, client):
		super(TCPConnection, self).__init__(client)
		self.socket = None
		self.write_buffer = ''
		self.read_buffer = ''
		self.read_event = None
		self.write_event = None
		
	def connect(self, address):
		self.socket = socket.socket()
		self.socket.connect(address)

		self.read_event = core.read_event(self.socket.fileno(), self.__read_data, persist=True)
		self.write_event = core.write_event(self.socket.fileno(), self.__write_data, persist=True)
	
	def disconnect(self):
		self.cleanup()
		
	def write(self, message):
		self.write_buffer = self.write_buffer + message
		
	def cleanup(self):
		self.write_buffer = ''
		self.read_buffer = ''
		if self.socket:
			self.socket.close()
			self.socket = None
		if self.read_event:
			self.read_event.cancel()
			self.read_event = None
		if self.write_event:
			self.write_event.cancel()
			self.write_event = None
			
		self.client.handle_disconnected(SocketException())
		
	def __write_data(self, event, _evtype):
		assert event is self.write_event
		
		if len(self.write_buffer) > 0:
			try:
				bytes_written = self.socket.send(self.write_buffer)
			except:
				self.cleanup()
				return
				
			self.write_buffer = self.write_buffer[bytes_written:]

	def __read_data(self, event, _evtype):
		assert event is self.read_event
		
		try:
			data = self.socket.recv(4096)
		except:
			self.cleanup()
			return
			
		if len(data) == 0:
			self.cleanup()
			return
			
		self.data_received(data)
	
	def data_received(self, data):
		self.read_buffer += data
		print("Got data length: ", len(data), "Buffer is length: ", len(self.read_buffer))
		
		while len(self.read_buffer) >= 8:
			length, magic = struct.unpack_from('I4s', self.read_buffer)
			
			if magic != 'VT01':
				raise ProtocolError('Invalid packet magic')
			if len(self.read_buffer) < length + 8:
				break
				
			buffer = self.read_buffer[8:length+8]
			if self.netfilter:
				buffer = self.netfilter.process_incoming(buffer)
				
			try:
				self.dispatch_message(buffer)
			except:
				self.disconnect()
				raise

			self.read_buffer = self.read_buffer[length+8:]
