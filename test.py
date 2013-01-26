import sys, argparse, os
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
	def get_sentry_file(self, username):
		filename = 'sentry_%s.bin' % (username,)
		if not os.path.exists(filename):
			return None
			
		with open(filename, 'r') as f:
			return f.read()

	def store_sentry_file(self, username, sentryfile):
		filename = 'sentry_%s.bin' % (username,)
		with open(filename, 'w') as f:
			f.write(sentryfile)
			
	def handle_message(self, emsg, msg):
		emsg = Util.get_msg(emsg)

def main(args):
	while args.username and not args.password:
		args.password = raw_input('Please enter the password for "' + args.username + '": ')
	
	client = SteamClient(SteamClientHandler())
	client.connect(('cm0.steampowered.com', 27017))

	if args.username:
		logon_result = client.login(args.username, args.password)
	else:
		logon_result = client.login_anonymous()

	if logon_result == EResult.AccountLogonDenied:
		client.disconnect()
		print("Steam Guard is enabled on this account. Please enter the authentication code sent to your email address.")
		code = raw_input('Auth code: ')
		client.connect(('cm0.steampowered.com', 27017))
		logon_result = client.login(args.username, args.password, auth_code = code)

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
	valid_apps = [x.appid for x in product_info.apps]
	valid_packages = [x.packageid for x in product_info.packages]
	
	if not args.appid in valid_apps:
		print("Could not find an app for id %d" % (args.appid,))
		return

	if not steamapps.has_license_for_app(args.appid):
		print("You do not have a license for app %d" % (args.appid,))

	
main(args)