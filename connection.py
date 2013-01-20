from twisted.internet import protocol
from steam_base import EMsg, EUniverse, EResult
from crypto import CryptoUtil
from protobuf import steammessages_base_pb2
import msg_base
import struct, binascii, StringIO, zipfile

class ProtocolError(Exception):
	"""
	Raised when an error has occurred in the Steam protocol
	"""

class NetEncryption():
	def __init__(self, key):
		self.key = key
		
	def process_incoming(self, data):
		return CryptoUtil.symmetricDecrypt(data, self.key)
	
	def process_outgoing(self, data):
		return CryptoUtil.symmetricEncrypt(data, self.key)

class SteamProtocol(protocol.Protocol):
	StateMagic = 0
	StateMessage = 1

	def connectionMade(self):
		self.session_key = None
		self.netfilter = None
		self.message_length = 0
		self.state = SteamProtocol.StateMagic
		self.buffer = ''
		
	def connectionLost(self, reason):
		self.factory.client.handleDisconnected(reason)
		
	def dataReceived(self, data):
		self.buffer += data
		
		print("Got data length: ", len(data), "Buffer is length: ", len(self.buffer))
		
		if self.state == SteamProtocol.StateMagic and len(self.buffer) >= 8:
			length, magic = struct.unpack_from('I4s', data)
			
			if magic != 'VT01':
				raise ProtocolError('Invalid packet magic')
			
			# Prepare the buffer for the message
			self.buffer = self.buffer[8:]
			self.message_length = length
			self.state = SteamProtocol.StateMessage
			
			print("Got magic: ", magic, "length: ", length)
		
		if self.state == SteamProtocol.StateMessage and len(self.buffer) >= self.message_length:
			buffer = self.buffer[:self.message_length]
			
			if self.netfilter:
				buffer = self.netfilter.process_incoming(buffer)
			
			try:
				self.dispatchMessage(buffer)
			except:
				self.transport.loseConnection()
				raise

			# Clear buffer, ready state for next message
			self.buffer = self.buffer[self.message_length:]
			self.state = SteamProtocol.StateMagic

	def sendMessage(self, msg):
		msg = msg.serialize()
		if self.netfilter:
			msg = self.netfilter.process_outgoing(msg)
		buffer = struct.pack('I4s', len(msg), 'VT01') + msg
		self.transport.write(buffer)
		
	def dispatchMessage(self, msg):
		emsg, = struct.unpack_from('I', msg)
		emsg = emsg & ~0x80000000
		print("message length: ", self.message_length, emsg, len(msg))
		
		self.factory.client.handleMessage(msg)
				
		if emsg == EMsg.ChannelEncryptRequest:
			self.channelEncryptRequest(msg)
		elif emsg == EMsg.ChannelEncryptResult:
			self.channelEncryptResult(msg)
		elif emsg == EMsg.Multi:
			self.splitMultiMessage(msg)
	
	
	def channelEncryptRequest(self, msg):
		message = msg_base.Message(msg_base.MsgHdr, msg_base.ChannelEncryptRequest)
		message.parse(msg)

		if message.body.protocol_version != 1:
			raise ProtocolError('Unexpected channel encryption protocol')
			
		if message.body.universe != EUniverse.Public:
			raise ProtocolError('Unexpected universe in encryption request')
			
		print("Channel encrypt request. Proto: ", message.body.protocol_version, "Universe: ", message.body.universe)
		
		self.session_key = CryptoUtil.createSessionKey()
		print("created key", len(self.session_key))
		crypted_key = CryptoUtil.rsaEncrypt(self.session_key)
		key_crc = binascii.crc32(crypted_key) & 0xFFFFFFFF
		
		response = msg_base.Message(msg_base.MsgHdr, msg_base.ChannelEncryptResponse, EMsg.ChannelEncryptResponse)
		response.body.protocol_version = 1
		response.body.key_size = len(crypted_key)
		response.payload = crypted_key + struct.pack('II', key_crc, 0)

		self.sendMessage(response)
		
	def channelEncryptResult(self, msg):
		message = msg_base.Message(msg_base.MsgHdr, msg_base.ChannelEncryptResult)
		message.parse(msg)
		
		print("Channel encrypt result: ", message.body.result)
		
		if message.body.result != EResult.OK:
			raise ProtocolError('Unable to negotiate channel encryption')
		
		self.netfilter = NetEncryption(self.session_key)
		self.factory.client.handleConnected()
	
	def splitMultiMessage(self, msg):
		message = msg_base.ProtobufMessage(steammessages_base_pb2.CMsgMulti)
		message.parse(msg)
		
		if message.body.size_unzipped <= 0:
			raise ProtocolError("Unexpected multi size: " + message.body.size_unzipped)
			
		zip_buffer = StringIO.StringIO(message.body.message_body)
		with zipfile.ZipFile(zip_buffer, 'r') as zip:
			z = zip.read('z')
		
		i = 0
		while i < len(z):
			sub_size, = struct.unpack_from('I', z, i)
			self.dispatchMessage(z[i:i+sub_size])
			i += sub_size + 4
			
		
class SteamFactory(protocol.ClientFactory):
	def __init__(self, client):
		self.client = client
		
	def buildProtocol(self, addr):
		print('Connected to: ', addr)
		p = SteamProtocol()
		p.factory = self
		return p
