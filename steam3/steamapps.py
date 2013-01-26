from steam_base import EMsg, EResult, EUniverse, EAccountType
from protobuf import steammessages_clientserver_pb2
from util import Util
import msg_base

class SteamApps():
	def __init__(self, client):
		self.client = client
		
		self.licenses = None
		self.app_cache = dict()
		self.package_cache = dict()
		
		self.client.register_listener(self)
		self.client.register_message(EMsg.ClientLicenseList, msg_base.ProtobufMessage, steammessages_clientserver_pb2.CMsgClientLicenseList)
		self.client.register_message(EMsg.PICSProductInfoResponse, msg_base.ProtobufMessage, steammessages_clientserver_pb2.CMsgPICSProductInfoResponse)
		
	def get_licenses(self):
		if self.licenses:
			return self.licenses
			
		if self.client.steamid.accounttype == EAccountType.Individual:
			self.client.wait_for_message(EMsg.ClientLicenseList)
			return self.licenses
			
		return None
		
	def get_depot_key(self, depot_id, app_id=0):
		message = msg_base.ProtobufMessage(steammessages_clientserver_pb2.CMsgClientGetDepotDecryptionKey, EMsg.ClientGetDepotDecryptionKey)

		message.body.depot_id = depot_id
		message.body.app_id = app_id
		
		response = self.client.wait_for_job(message, EMsg.ClientGetDepotDecryptionKeyResponse)
		return response.body
		
		
	def get_product_info(self, app_ids=None, package_ids=None):
		message = msg_base.ProtobufMessage(steammessages_clientserver_pb2.CMsgPICSProductInfoRequest, EMsg.PICSProductInfoRequest)

		if app_ids:
			for app_id in app_ids:
				app_info = message.body.apps.add()
				app_info.appid = app_id
				app_info.only_public = False
	
		if package_ids:
			for package_id in package_ids:
				package_info = message.body.packages.add()
				package_info.packageid = package_id
		
		message.body.meta_data_only = False
		
		response = self.client.wait_for_job(message, EMsg.PICSProductInfoResponse)

		print(response, response.body)
		return response.body
		
	def handle_message(self, emsg_real, msg):
		emsg = Util.get_msg(emsg_real)
		
		if emsg == EMsg.ClientLicenseList:
			self.handle_license_list(msg)
			
	def handle_license_list(self, msg):
		message = msg_base.ProtobufMessage(steammessages_clientserver_pb2.CMsgClientLicenseList)
		message.parse(msg)

		self.licenses = message.body.licenses
		