from twisted.internet import defer
from twisted.internet.endpoints import TCP4ClientEndpoint
from steam_base import EMsg, EResult, EUniverse, EAccountType
from protobuf import steammessages_clientserver_pb2
from connection import SteamFactory
from steamid import SteamID
import msg_base
import struct

class SteamClient():
	
	def __init__(self, reactor, callback):
		self.reactor = reactor
		self.callback = callback
		
		self.jobid = 0
		self.jobs = dict()
	
	@defer.inlineCallbacks
	def connect(self):
		endpoint = TCP4ClientEndpoint(self.reactor, 'cm0.steampowered.com', 27017)
		self.client = yield endpoint.connect(SteamFactory(self))
		
		self.deferredConnect = defer.Deferred()
		yield self.deferredConnect
	
	def handleConnected(self):
		print('Connection established')
		
		if self.deferredConnect:
			self.deferredConnect.callback(None)
			self.deferredConnect = None
	
	def handleDisconnected(self, reason):
		print('Disconnected')
		
		if self.deferredConnect:
			self.deferredConnect.errback(reason)
			self.deferredConnect = None
		if self.deferredLogin:
			self.deferredLogin.errback(reason)
			self.deferredLogin = None

	def __createJob(self, type, message):
		jobid = self.jobid
		self.jobid = self.jobid + 1
		
		deferred = defer.Deferred()
		self.jobs[jobid] = (type, deferred)
		
		message.header.source_jobid = jobid
		return deferred
		
	@defer.inlineCallbacks
	def login_anonymous(self):
		message = msg_base.ProtobufMessage(steammessages_clientserver_pb2.CMsgClientLogon, EMsg.ClientLogon)

		message.proto_header.client_sessionid = 0
		message.proto_header.steamid = SteamID.make_from(0, 0, EUniverse.Public, EAccountType.AnonUser).steamid
		message.body.protocol_version = 65575
		message.body.client_os_type = 10
		message.body.machine_id = "OK"

		self.client.sendMessage(message)
		
		# jobids aren't preserved for a logon
		self.deferredLogin = defer.Deferred()
		logonResponse = yield self.deferredLogin

		print("got logon response", logonResponse.body.eresult)
		
	def handleMessage(self, msg):
		emsg, = struct.unpack_from('I', msg)
		is_proto = emsg & 0x80000000 == 0x80000000
		emsg = emsg & ~0x80000000
		
		if emsg == EMsg.ClientLogOnResponse and self.deferredLogin:
			message = msg_base.ProtobufMessage(steammessages_clientserver_pb2.CMsgClientLogonResponse)
			message.parse(msg)
			
			self.deferredLogin.callback(message)
			self.deferredLogin = None

		print('SteamClient got message:', emsg, "is_proto: ", is_proto)
