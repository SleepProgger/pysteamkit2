import sys
from steam3.client import SteamClient
from steam_base import EResult
from util import Util

class SteamClientHandler:
	def handleMessage(self, emsg, msg):
		emsg = Util.get_msg(emsg)
		
def main():
	client = SteamClient(SteamClientHandler())

	client.connect(('cm0.steampowered.com', 27017))
	logon_result = client.login('heronsoft', 'gmtservices') #client.login_anonymous()

	if logon_result != EResult.OK:
		print("logon failed", logon_result)
		return
		
	print("logon", str(client.steamid))
		
	sessiontoken = client.get_session_token()
	print("session token: ", sessiontoken)		

main()