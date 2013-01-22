import sys
from steam3.client import SteamClient
from steam_base import EResult, EMsg
from util import Util
import gevent

class SteamClientHandler:
	def handle_message(self, emsg, msg):
		emsg = Util.get_msg(emsg)

def main():
	client = SteamClient(SteamClientHandler())

	def xyz():
		print("Waiting for connect")
		client.connection_event.wait()
		print("Waiting for logon")
		message = client.wait_for_message(EMsg.ClientLogOnResponse)
		print("xyz ", message.body.eresult)
	gxyz = gevent.spawn(xyz)
				
	client.connect(('cm0.steampowered.com', 27017))
	logon_result = client.login_anonymous()

	if logon_result != EResult.OK:
		print("logon failed", logon_result)
		return

	print("logon", str(client.steamid))
	
	sessiontoken = client.get_session_token()
	print("session token: ", sessiontoken)		

	gxyz.join()
	
main()