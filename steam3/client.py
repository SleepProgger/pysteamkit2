from gevent.event import AsyncResult, Event
from steam_base import EMsg, EResult, EUniverse, EAccountType
from protobuf import steammessages_clientserver_pb2
from connection import TCPConnection
from steamid import SteamID
from util import Util
from steamapps import SteamApps
import msg_base
import struct

class SteamClient():
	def __init__(self, callback):
		self.callback = callback
		self.listeners = []
		self.message_constructors = dict()
		self.message_events = dict()

		self.username = None
		self.jobid = 0
		self.steam2_ticket = None
		self.session_token = None
	
		self.connection = TCPConnection(self)
		self.connection_event = Event()
		
		self.register_listener(callback)
		self.steamapps = SteamApps(self)
		
		self.register_message(EMsg.ClientLogOnResponse, msg_base.ProtobufMessage, steammessages_clientserver_pb2.CMsgClientLogonResponse)
		self.register_message(EMsg.ClientSessionToken, msg_base.ProtobufMessage, steammessages_clientserver_pb2.CMsgClientSessionToken)

	def connect(self, address):
		self.connection.connect(address)
		self.connection_event.wait()
	
	def disconnect(self):
		self.connection.disconnect()
		
	def handle_connected(self):
		self.connection_event.set()
		print('Connection established')
	
	def handle_disconnected(self, reason):
		self.connection_event.clear()
		print('Disconnected')
		# throw errors EVERYWHERE
		for k in self.message_events.keys():
			if self.message_events[k]:
				self.message_events[k].set_exception(reason)
				self.message_events[k] = None
		
		self.username = None
		self.jobid = 0
		self.steam2_ticket = None
		self.session_token = None

	def register_listener(self, listener):
		self.listeners.append(listener)
		
	def register_message(self, emsg, container, header, body=None):
		self.message_constructors[emsg] = (container, header, body)
		self.message_events[emsg] = None
		
	def wait_for_message(self, emsg):
		if not emsg in self.message_events:
			return None
		
		if self.message_events[emsg]:
			async_result = self.message_events[emsg]
		else:
			async_result = self.message_events[emsg] = AsyncResult()
		
		return async_result.get()
	
	def wait_for_job(self, message, emsg):
		jobid = self.jobid
		self.jobid += 1
		message.header.source_jobid = jobid

		self.connection.send_message(message)
		
		jobid_parsed = -1
		while jobid_parsed != jobid:
			message = self.wait_for_message(emsg)
			jobid_parsed = message.header.target_jobid
			
		return message

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

		self.connection.send_message(message)

		if self.steamid:
			return EResult.OK
		else:
			logonResponse = self.wait_for_message(EMsg.ClientLogOnResponse)
			return logonResponse.body.eresult

	def login(self, username=None, password=None, login_key=None, auth_code=None):
		self.username = username
		
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
		if login_key:
			message.body.login_key = login_key
		if auth_code:
			message.body.auth_code = auth_code
		
		sentryfile = self.callback.get_sentry_file(username)
		if sentryfile:
			message.body.sha_sentryfile = Util.sha1_hash(sentryfile)
			message.body.eresult_sentryfile = EResult.OK 
		else:
			message.body.eresult_sentryfile = EResult.FileNotFound
				
		localip = self.connection.get_bound_address()
		message.body.obfustucated_private_ip = 1111

		self.connection.send_message(message)

		if self.steamid:
			return EResult.OK
		else:
			logonResponse = self.wait_for_message(EMsg.ClientLogOnResponse)
			return logonResponse.body.eresult
		
	def get_session_token(self):
		if self.session_token:
			return self.session_token

		# this also can't fit in a job because it's sent on login
		if self.steamid and self.steamid.accounttype == EAccountType.Individual:
			self.wait_for_message(EMsg.ClientSessionToken)
			return self.session_token
			
		return None

	def handle_message(self, emsg_real, msg):
		emsg = Util.get_msg(emsg_real)
		print("EMsg is ", Util.lookup_enum(EMsg, emsg))
		
		if emsg == EMsg.ClientLogOnResponse:
			self.handle_client_logon(msg)
		elif emsg == EMsg.ClientUpdateMachineAuth:
			self.handle_update_machine_auth(msg)
		elif emsg == EMsg.ClientSessionToken:
			self.handle_session_token(msg)
			
		for listener in self.listeners:
			listener.handle_message(emsg_real, msg)
			
		if emsg in self.message_events and self.message_events[emsg]:
			constructor = self.message_constructors[emsg]
			if constructor[2]:
				message = constructor[0](constructor[1], constructor[2])
			else:
				message = constructor[0](constructor[1])
			message.parse(msg)
			
			self.message_events[emsg].set(message)
			self.message_events[emsg] = None
		

	def handle_client_logon(self, msg):
		message = msg_base.ProtobufMessage(steammessages_clientserver_pb2.CMsgClientLogonResponse)
		message.parse(msg)
			
		if message.body.steam2_ticket:
			self.steam2_ticket = message.body.steam2_ticket
	
	def handle_update_machine_auth(self, msg):
		message = msg_base.ProtobufMessage(steammessages_clientserver_pb2.CMsgClientUpdateMachineAuth)
		message.parse(msg)
		
		sentryfile = message.body.bytes
		hash = Util.sha1_hash(sentryfile)
		
		self.callback.store_sentry_file(self.username, sentryfile)
		
		response = msg_base.ProtobufMessage(steammessages_clientserver_pb2.CMsgClientUpdateMachineAuthResponse, EMsg.ClientUpdateMachineAuthResponse)
		response.header.target_jobid = message.header.source_jobid
		
		response.body.cubwrote = message.body.cubtowrite
		response.body.eresult = EResult.OK
		response.body.filename = message.body.filename
		response.body.filesize = message.body.cubtowrite
		response.body.getlasterror = 0
		response.body.offset = message.body.offset
		response.body.sha_file = hash
		response.body.otp_identifier = message.body.otp_identifier
		response.body.otp_type = message.body.otp_type
		
		self.connection.send_message(response)
		
	def handle_session_token(self, msg):
		message = msg_base.ProtobufMessage(steammessages_clientserver_pb2.CMsgClientSessionToken)
		message.parse(msg)
		
		self.session_token = message.body.token