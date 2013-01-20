import sys

from twisted.internet import defer, task
from twisted.python import failure
from client import SteamClient
from steam_base import EResult

class SteamClientHandler:
	def handleMessage(self, msg):
		pass
		
@defer.inlineCallbacks
def main(reactor, username="", password=""):
	logon_result = EResult.Invalid
	
	#while logon_result != EResult.OK:
	try:
		client = SteamClient(reactor, SteamClientHandler())
		yield client.connect()
		logon_result = yield client.login_anonymous()
		if logon_result == EResult.OK:
			print("logon", str(client.steamid))
		else:
			print("logon failed", logon_result)
			
		sessiontoken = yield client.get_session_token()
		
		print('ok', sessiontoken)
		
		#get rid of me
		#holdOpen = defer.Deferred()
		#yield holdOpen
		
	except:
		print('not ok')
		failure.Failure().printTraceback()

task.react(main, sys.argv[1:])