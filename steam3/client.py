from gevent.event import AsyncResult, Event
from steam_base import EMsg, EResult, EUniverse, EAccountType
from protobuf import steammessages_clientserver_pb2
from connection import TCPConnection
from steamid import SteamID
from util import Util
import msg_base
import struct

class SteamClient():
	def __init__(self, callback):
		self.callback = callback
		self.connection = TCPConnection(self)

		self.message_constructors = dict()
		self.message_events = dict()
		self.job_events = dict()
		
		self.steam2_ticket = None
		self.session_token = None
	
		self.deferredConnect = None
		self.deferredLogin = None
		self.deferredSessionToken = None
		
		self.connectionEvent = Event()
		self.registerMessage(EMsg.ClientLogOnResponse, msg_base.ProtobufMessage, steammessages_clientserver_pb2.CMsgClientLogonResponse)
		self.registerMessage(EMsg.ClientSessionToken, msg_base.ProtobufMessage, steammessages_clientserver_pb2.CMsgClientSessionToken)

	def connect(self, address):
		self.connection.connect(address)
		self.connectionEvent.wait()
	
	def handleConnected(self):
		self.connectionEvent.set()
		print('Connection established')
	
	def handleDisconnected(self, reason):
		self.connectionEvent.clear()
		print('Disconnected')
		# throw errors EVERYWHERE
		for k in self.message_events.keys():
			if self.message_events[k]:
				self.message_events[k].set_exception(reason)

	def registerMessage(self, emsg, container, header, body=None):
		self.message_constructors[emsg] = (container, header, body)
		self.message_events[emsg] = None
		
	def waitForMessage(self, emsg):
		if not emsg in self.message_events:
			return None
		
		if self.message_events[emsg]:
			async_result = self.message_events[emsg]
		else:
			async_result = self.message_events[emsg] = AsyncResult()
		
		return async_result.get()
	
	def registerJob(self, message, jobid):
		jobid = self.jobid
		self.jobid = self.jobid + 1
		
		message.header.source_jobid = jobid
		return jobid
		
	def waitForJob(self, jobid, container, header, body):
		pass

	@property
	def steamid(self):
		return self.connection.steamid
		
	def login_anonymous(self):
		message = msg_base.ProtobufMessage(steammessages_clientserver_pb2.CMsgClientLogon, EMsg.ClientLogon)

		message.proto_header.client_sessionid = 0
		message.proto_header.steamid = SteamID.make_from(0, 0, EUniverse.Public, EAccountType.AnonUser).steamid
		message.body.protocol_version = 65575
		message.body.client_os_type = 10
		message.body.machine_id = "OK"

		self.connection.sendMessage(message)

		if self.steamid:
			return EResult.OK
		else:
			logonResponse = self.waitForMessage(EMsg.ClientLogOnResponse)
			return logonResponse.body.eresult

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
		
		localip = self.connection.getBoundAddress()
		message.body.obfustucated_private_ip = 1111

		self.connection.sendMessage(message)

		if self.steamid:
			return EResult.OK
		else:
			logonResponse = self.waitForMessage(EMsg.ClientLogOnResponse)
			return logonResponse.body.eresult
		
	def get_session_token(self):
		if self.session_token:
			return self.session_token

		# this also can't fit in a job because it's sent on login
		if self.steamid and self.steamid.accounttype == EAccountType.Individual:
			self.waitForMessage(EMsg.ClientSessionToken)
			return self.session_token
			
		pass

	def handleMessage(self, emsg_real, msg):
		emsg = Util.get_msg(emsg_real)
		
		if emsg == EMsg.ClientLogOnResponse:
			self.handleClientLogon(msg)
		elif emsg == EMsg.ClientSessionToken:
			self.handleSessionToken(msg)
			
		if emsg in self.message_events and self.message_events[emsg]:
			constructor = self.message_constructors[emsg]
			if constructor[2]:
				message = constructor[0](constructor[1], constructor[2])
			else:
				message = constructor[0](constructor[1])
			message.parse(msg)
			
			self.message_events[emsg].set(message)
			self.message_events[emsg] = None
			
		self.callback.handleMessage(emsg_real, msg)

	def handleClientLogon(self, msg):
		message = msg_base.ProtobufMessage(steammessages_clientserver_pb2.CMsgClientLogonResponse)
		message.parse(msg)
			
		if message.body.steam2_ticket:
			self.steam2_ticket = message.body.steam2_ticket
			
	def handleSessionToken(self, msg):
		message = msg_base.ProtobufMessage(steammessages_clientserver_pb2.CMsgClientSessionToken)
		message.parse(msg)
		
		self.session_token = message.body.token