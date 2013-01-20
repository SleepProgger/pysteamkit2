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
		
		self.client = None
		
		self.jobid = 0
		self.jobs = dict()
		
		self.steam2_ticket = None
		self.session_token = None
	
		self.deferredConnect = None
		self.deferredLogin = None
		self.deferredSessionToken = None
		
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
		if self.deferredSessionToken:
			self.deferredSessionToken.errback(reason)
			self.deferredSessionToken = None

	def __createJob(self, type, message):
		jobid = self.jobid
		self.jobid = self.jobid + 1
		
		deferred = defer.Deferred()
		self.jobs[jobid] = (type, deferred)
		
		message.header.source_jobid = jobid
		return deferred
		
	@property
	def steamid(self):
		return self.client.steamid
		
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
		return self.deferredLogin
		#logonResponse = yield self.deferredLogin
		#print("got logon response", logonResponse.body.eresult)

	def login(self, username=None, password=None):
		message = msg_base.ProtobufMessage(steammessages_clientserver_pb2.CMsgClientLogon, EMsg.ClientLogon)

		message.proto_header.client_sessionid = 0
		message.proto_header.steamid = SteamID.make_from(0, 0, EUniverse.Public, EAccountType.Individual).steamid
		message.body.protocol_version = 65575
		message.body.client_package_version = 1771
		message.body.client_os_type = 10
		message.body.client_language = "english"
		message.body.machine_id = "OK"
		
		message.body.account_name = username
		message.body.password = password
		
		localip = self.client.getBoundAddress()
		print(localip)
		message.body.obfustucated_private_ip = 1111

		self.client.sendMessage(message)
		
		# jobids aren't preserved for a logon
		self.deferredLogin = defer.Deferred()
		return self.deferredLogin
		
	def get_session_token(self):
		if self.session_token:
			return defer.succeed(self.session_token)

		# this also can't fit in a job because it's sent on login
		if self.client.steamid.accounttype == EAccountType.Individual:
			self.deferredSessionToken = defer.Deferred()
			return self.deferredSessionToken
		
		return defer.succeed(None)
		
		
	def handleMessage(self, msg):
		emsg, = struct.unpack_from('I', msg)
		is_proto = emsg & 0x80000000 == 0x80000000
		emsg = emsg & ~0x80000000
		
		if emsg == EMsg.ClientLogOnResponse and self.deferredLogin:
			message = msg_base.ProtobufMessage(steammessages_clientserver_pb2.CMsgClientLogonResponse)
			message.parse(msg)
			
			if message.body.steam2_ticket:
				self.steam2_ticket = message.body.steam2_ticket
			
			
			self.deferredLogin.callback(message.body.eresult)
			self.deferredLogin = None
		elif emsg == EMsg.ClientSessionToken:
			message = msg_base.ProtobufMessage(steammessages_clientserver_pb2.CMsgClientSessionToken)
			message.parse(msg)
			
			self.session_token = message.body.token
			
			if self.deferredSessionToken:
				self.deferredSessionToken.callback(self.session_token)
				self.deferredSessionToken = None
			
		print('SteamClient got message:', emsg, "is_proto: ", is_proto)
