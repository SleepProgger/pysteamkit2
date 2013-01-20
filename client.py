from twisted.internet import protocol, defer, task
from twisted.internet.endpoints import TCP4ClientEndpoint
from steam_base import EMsg, EUniverse, EResult
from crypto import CryptoUtil
import struct
import binascii

class SteamClient():
	
	def __init__(self, reactor, callback):
		self.reactor = reactor
		self.callback = callback
	
	@defer.inlineCallbacks
	def connect(self):
		endpoint = TCP4ClientEndpoint(self.reactor, 'cm0.steampowered.com', 27017)
		self.client = yield endpoint.connect(SteamFactory(self))
		self.deferredConnect = defer.Deferred()
		yield self.deferredConnect
	
	def handleConnected(self):
		print 'Connection established'
		
		if self.deferredConnect:
			self.deferredConnect.callback(None)
			self.deferredConnect = None
	
	def handleDisconnected(self, reason):
		print 'Disconnected'
		
		if self.deferredConnect:
			self.deferredConnect.errback(reason)
			self.deferredConnect = None
			
	def login_anonymous(self):
		pass
		
	def handleMessage(self, msg):
		print 'SteamClient got message: ', msg


class ProtocolError(Exception):
	"""
	Raised when an error has occurred in the Steam protocol
	"""

class NetEncryption():
	def __init__(self, key):
		self.key = key
		
	def process_incoming(data):
		return CryptoUtil.symmetricDecrypt(data, key)
	
	def process_outgoing(data):
		return CryptoUtil.symmetricEncrypt(data, key)

class SteamProtocol(protocol.Protocol):
	StateMagic = 0
	StateMessage = 1

	class MsgHdr:
		HeaderFmt = '=Iqq'
		HeaderLength = struct.calcsize(HeaderFmt)
		def __init__(self):
			self.emsg = None
			self.target_jobid = -1
			self.source_jobid = -1
		def parse(self, buffer):
			self.emsg, self.target_jobid, self.source_jobid = struct.unpack_from(SteamProtocol.MsgHdr.HeaderFmt, buffer)
			return SteamProtocol.MsgHdr.HeaderLength
		def serialize(self):
			return struct.pack(SteamProtocol.MsgHdr.HeaderFmt, self.emsg, self.target_jobid, self.source_jobid)
	
	class ProtobufMsgHdr:
		HeaderFmt = 'II'
		HeaderLength = struct.calcsize(HeaderFmt)
		def __init__(self):
			self.emsg = None
			self.proto = None #set me
		def parse(self, buffer):
			self.emsg, len = struct.unpack_from('II', buffer)
			return HeaderLength + len
			#deserialize proto
		def serialize(self):
			headerproto = self.proto.SerializeToString()
			return struct.pack(SteamProtocol.ProtobufMsgHdr.HeaderFmt, self.emsg, len(headerproto)) + headerproto
			
	class Message:
		def __init__(self, header, body, emsg=None):
			self.header = header()
			self.body = body()
			self.payload = None
			self.header.emsg = emsg
		def parse(self, buffer):
			header_length = self.header.parse(buffer)
			self.body.parse(buffer, header_length)
		def serialize(self):
			return self.header.serialize() + self.body.serialize() + self.payload
	
	class ChannelEncryptRequest:
		def __init__(self):
			self.protocol_version = 1
			self.universe = -1
		def parse(self, buffer, pos=0):
			self.protocol_version, self.universe = struct.unpack_from('II', buffer, pos)
		def serialize(self):
			return struct.pack('II', self.protocol_version, self.universe)
	
	class ChannelEncryptResponse:
		def __init__(self):
			self.protocol_version = 1
			self.key_size = -1
		def parse(self, buffer, pos=0):
			self.protocol_version, self.key_size = struct.unpack_from('II', buffer, pos)
		def serialize(self):
			return struct.pack('II', self.protocol_version, self.key_size)

	class ChannelEncryptResult:
		def __init__(self):
			self.result = EResult.Invalid
		def parse(self, buffer, pos=0):
			self.result, = struct.unpack_from('I', buffer, pos)
		def serialize(self):
			return struct.pack('I', self.result)


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
		
		print "Got data length: ", len(data), "Buffer is length: ", len(self.buffer)
		
		if self.state == SteamProtocol.StateMagic and len(self.buffer) >= 8:
			length, magic = struct.unpack_from('I4s', data)
			
			if magic != 'VT01':
				raise ProtocolError('Invalid packet magic')
			
			# Prepare the buffer for the message
			self.buffer = self.buffer[8:]
			self.message_length = length
			self.state = SteamProtocol.StateMessage
			
			print "Got magic: ", magic, "length: ", length
		
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
		buffer = struct.pack('I4s', len(msg), 'VT01') + msg
		if self.netfilter:
			buffer = self.netfilter.process_outgoing(buffer)
		self.transport.write(buffer)
		
	def dispatchMessage(self, msg):
		emsg, = struct.unpack_from('I', msg)
		print "message length: ", self.message_length, emsg, len(msg)
		
		self.factory.client.handleMessage(msg)
				
		if emsg == EMsg.ChannelEncryptRequest:
			self.channelEncryptRequest(msg)
		elif emsg == EMsg.ChannelEncryptResult:
			self.channelEncryptResult(msg)
	
	
	def channelEncryptRequest(self, msg):
		message = SteamProtocol.Message(SteamProtocol.MsgHdr, SteamProtocol.ChannelEncryptRequest)
		message.parse(msg)

		if message.body.protocol_version != 1:
			raise ProtocolError('Unexpected channel encryption protocol')
			
		if message.body.universe != EUniverse.Public:
			raise ProtocolError('Unexpected universe in encryption request')
			
		print "Channel encrypt request. Proto: ", message.body.protocol_version, "Universe: ", message.body.universe
		
		self.session_key = CryptoUtil.createSessionKey()
		crypted_key = CryptoUtil.rsaEncrypt(self.session_key)
		key_crc = binascii.crc32(crypted_key) & 0xFFFFFFFF
		
		response = SteamProtocol.Message(SteamProtocol.MsgHdr, SteamProtocol.ChannelEncryptResponse, EMsg.ChannelEncryptResponse)
		response.body.protocol_version = 1
		response.body.key_size = len(crypted_key)
		response.payload = crypted_key + struct.pack('II', key_crc, 0)

		self.sendMessage(response)
		
	def channelEncryptResult(self, msg):
		message = SteamProtocol.Message(SteamProtocol.MsgHdr, SteamProtocol.ChannelEncryptResult)
		message.parse(msg)
		
		print "Channel encrypt result: ", message.body.result
		
		if message.body.result != EResult.OK:
			raise ProtocolError('Unable to negotiate channel encryption')
		
		self.netfilter = NetEncryption(self.session_key)
		self.factory.client.handleConnected()
		
		
class SteamFactory(protocol.ClientFactory):
	def __init__(self, client):
		self.client = client
		
	def buildProtocol(self, addr):
		print 'Connected to: ', addr
		p = SteamProtocol()
		p.factory = self
		return p
