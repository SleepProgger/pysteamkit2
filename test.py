import sys

from twisted.internet import defer, task
from twisted.python import failure
from client import SteamClient

class SteamClientHandler:
	def handleMessage(self, msg):
		pass
		
@defer.inlineCallbacks
def main(reactor, username="", password=""):
	client = SteamClient(reactor, SteamClientHandler())

	try:
		yield client.connect()
		yield client.login_anonymous()
		print('ok')
		
		#get rid of me
		holdOpen = defer.Deferred()
		yield holdOpen
		
	except:
		print('not ok')
		failure.Failure().printTraceback()

task.react(main, sys.argv[1:])