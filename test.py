import sys, argparse
from steam3.client import SteamClient
from steam_base import EResult, EMsg
from util import Util
import gevent

parser = argparse.ArgumentParser(description='DepotDownloader downloads depots.')
parser.add_argument('appid', type=int, help='AppID to download')
parser.add_argument('--branch', type=str, default='Public', help='Application branch to download')
parser.add_argument('--dir', type=str, help='Directory to operate within')
parser.add_argument('--depots', type=int, nargs='*', help='Specific depots to download')
parser.add_argument('--username', type=str, help='Username to sign in with')
parser.add_argument('--password', type=str, help='Account password')

args = parser.parse_args()

class SteamClientHandler:
	def handle_message(self, emsg, msg):
		emsg = Util.get_msg(emsg)

def main(args):
	client = SteamClient(SteamClientHandler())
				
	client.connect(('cm0.steampowered.com', 27017))

	while args.username and not args.password:
		args.password = raw_input('Please enter the password for "' + args.username + '": ')
	
	if args.username:
		logon_result = client.login(args.username, args.password)
	else:
		logon_result = client.login_anonymous()

	if logon_result != EResult.OK:
		print("logon failed", logon_result)
		return

	print("logon", str(client.steamid))
	
	sessiontoken = client.get_session_token()
	print("session token: ", sessiontoken)
	
	steamapps = client.steamapps
	
	licenses = steamapps.get_licenses()
	if licenses:
		licenses = [x.package_id for x in licenses]
	else:
		licenses = [0]

	print("Licenses: ", licenses)
	
	product_info = steamapps.get_product_info(app_ids = [args.appid], package_ids = licenses)
	print("Raw product info: ", product_info)
	print("Packages: ", [x.packageid for x in product_info.packages])

main(args)