from twisted.internet import defer
from twisted.internet.endpoints import TCP4ClientEndpoint
from steam_base import EMsg, EResult, EUniverse, EAccountType
from protobuf import steammessages_clientserver_pb2
from connection import SteamFactory
from steamid import SteamID
import msg_base

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
		print('Connection established')
		
		if self.deferredConnect:
			self.deferredConnect.callback(None)
			self.deferredConnect = None
	
	def handleDisconnected(self, reason):
		print('Disconnected')
		
		if self.deferredConnect:
			self.deferredConnect.errback(reason)
			self.deferredConnect = None

	def login_anonymous(self):
		message = msg_base.ProtobufMessage(steammessages_clientserver_pb2.CMsgClientLogon, EMsg.ClientLogon)
		
		message.proto_header.client_sessionid = 0
		message.proto_header.steamid = SteamID.make_from(0, 0, EUniverse.Public, EAccountType.AnonUser).steamid
		message.body.protocol_version = 65575
		message.body.client_os_type = 10
		message.body.machine_id = "OK"

		self.client.sendMessage(message)
		
	def handleMessage(self, msg):
		print('SteamClient got message')
