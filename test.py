from gevent import monkey
monkey.patch_all()

import gevent, sys, argparse, os
from gevent.pool import Pool
from steam3.client import SteamClient
from steam3.cdn_client import CDNClient
from steam_base import EResult, EMsg, EServerType
from util import Util

parser = argparse.ArgumentParser(description='DepotDownloader downloads depots.')
parser.add_argument('appid', type=int, help='AppID to download')
parser.add_argument('--branch', type=str, default='public', help='Application branch to download')
parser.add_argument('--dir', type=str, help='Directory to operate within')
parser.add_argument('--depots', type=int, nargs='*', help='Specific depots to download')
parser.add_argument('--username', type=str, help='Username to sign in with')
parser.add_argument('--password', type=str, help='Account password')
parser.add_argument('--cellid', type=int, help='Cell ID to use for downloads')

args = parser.parse_args()
client = None
steamapps = None
content_client_pool = None

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

class CDNClientPool(object):
	def __init__(self, servers, app_ticket, steamid):
		self.clients = [CDNClient(ip, port, app_ticket, steamid) for (ip, port) in servers]
		self.client_pool = []
		
	def get_clients(self, num, depot):		
		while len(self.client_pool) < num and len(self.clients) > 0:
			client = self.clients.pop(0)
			
			if client.initialize():
				if client.app_ticket:
					client.auth_appticket()
					
				self.client_pool.append(client)
		
		num = min(num, len(self.client_pool))
		if num == 0:
			raise Exception("Exhausted CDN client pool")

		clients = []
		while len(clients) < num and len(self.client_pool) > 0:
			client = self.client_pool.pop(0)

			if client.app_ticket or client.depot == depot or client.auth_depotid(depot):
				clients.append(client)

		if len(clients) == 0:
			raise Exception("Unable to find any working CDN clients")
			
		return clients
		
	def return_clients(self, clients):
		for client in clients:
			self.client_pool.append(client)

def get_depots_for_app(appid, filter):
	return [int(key) for key,values in steamapps.app_cache[appid]['depots'].iteritems() if key.isdigit() and (not filter or int(key) in filter)]
	
def get_depot(appid, depotid):
	return steamapps.app_cache[appid]['depots'][str(depotid)]

def get_depot_key(appid, depotid):
	depot_key_result = steamapps.get_depot_key(depotid, args.appid)
	if depot_key_result.eresult != EResult.OK:
		return False

	return (depotid, depot_key_result.depot_encryption_key)
	
def get_depot_manifest(depotid, manifestid):
	clients = content_client_pool.get_clients(1, depotid)
	(status, manifest) = clients[0].download_depot_manifest(depotid, manifestid)
	if manifest:
		content_client_pool.return_clients(clients)
		return (depotid, manifest, status)
	return (depotid, None, status)
		
def main(args):
	global client, steamapps, content_client_pool
	
	while args.username and not args.password:
		args.password = raw_input('Please enter the password for "' + args.username + '": ')
	
	client = SteamClient(SteamClientHandler())
	if not client.connect(('cm0.steampowered.com', 27017)):
		print("Unable to connect")
		return

	if args.username:
		logon_result = client.login(args.username, args.password)
	else:
		logon_result = client.login_anonymous()

	if logon_result.eresult == EResult.AccountLogonDenied:
		client.disconnect()
		print("Steam Guard is enabled on this account. Please enter the authentication code sent to your email address.")
		code = raw_input('Auth code: ')
		if not client.connect(('cm0.steampowered.com', 27017)):
			print("Unable to connect")
			return
		logon_result = client.login(args.username, args.password, auth_code = code)

	if logon_result.eresult != EResult.OK:
		print("logon failed", logon_result.eresult)
		return

	print("logon", str(client.steamid))
	
	if args.cellid == None:
		print("No cell id specified, using Steam3 specified: %d" % (logon_result.cell_id,))
		args.cellid = logon_result.cell_id
		
	sessiontoken = client.get_session_token()
	print("session token: ", sessiontoken)
	
	steamapps = client.steamapps
	
	licenses = steamapps.get_licenses()
	licenses = [x.package_id for x in licenses] if licenses else [0]
	print("Licenses: ", licenses)
	
	product_info = steamapps.get_product_info(app_ids = [args.appid], package_ids = licenses)
	valid_apps = [x.appid for x in product_info.apps]
	valid_packages = [x.packageid for x in product_info.packages]
	
	if not args.appid in valid_apps:
		print("Could not find an app for id %d" % (args.appid,))
		return

	if not steamapps.has_license_for_app(args.appid):
		print("You do not have a license for app %d" % (args.appid,))
		return

	#TODO
	app_ticket = None
	
	depots = get_depots_for_app(args.appid, args.depots)
	
	if len(depots) == 0:
		print("No depots available for app %d given filter %s" % (args.appid, args.depots))
		return
	
	depot_keys = dict()
	depot_manifests = []
	
	print("Depots found:")
	for depotid in depots:
		depot = get_depot(args.appid, depotid)
		print("* %d %s" % (depotid, depot['name']))
				
		manifests = depot.get('manifests')
		encrypted_manifests = depot.get('encrypted_manifests')
		
		if manifests and manifests.get(args.branch):
			manifest = manifests[args.branch]
		elif encrypted_manifests and encrypted_manifests.get(args.branch):
			encrypted_gid = encrypted_manifests[args.branch]

		depot_manifests.append((depotid, manifest))

	if len(depot_manifests) == 0:
		print("Unable to find any downloadable depots for app %d branch %s" % (args.appid,args.branch))
		return
		
	print("Total %d manifests" % (len(depot_manifests),))
	
	print("Fetching decryption keys")
	pool = Pool(4)
	key_fetch = [pool.spawn(get_depot_key, args.appid, depotid) for (depotid, manifest) in depot_manifests]
	pool.join()
	
	for job in key_fetch:
		(depotid, depot_key) = job.value
		depot_keys[depotid] = depot_key
		
	print("Building CDN server list")
	base_server_list = client.server_list[EServerType.CS]
	
	if base_server_list == None or len(base_server_list) == 0:
		print("No content servers to bootstrap from")
	
	content_servers = None
	for (ip, port) in base_server_list:
		content_servers = CDNClient.fetch_server_list(ip, port, args.cellid)
		if content_servers:
			break
	
	if not content_servers:
		print("Unable to find any content servers for cell id %d" % (args.cellid,))
		return
		
	print("Found %d content servers" % (len(content_servers),))
	
	content_client_pool = CDNClientPool(content_servers, app_ticket, client.steamid)
	
	print("Downloading depot manifests")
	depot_manifests_retrieved = []
	num_tries = 0
	
	while len(depot_manifests_retrieved) < len(depot_manifests) and num_tries < 4:
		num_tries += 1
		pool = Pool(4)
		manifest_fetch = [pool.spawn(get_depot_manifest, depotid, manifestid) for (depotid, manifestid) in depot_manifests if not depotid in depot_manifests_retrieved]
		pool.join()
		
		for job in manifest_fetch:
			(depotid, manifest, status) = job.value
			if manifest:
				print("Got manifest for %d" % (depotid,))
				depot_manifests_retrieved.append(depotid)
			elif status == 401:
				print("Did not have sufficient access to download manifest for %d" % (depotid,))
				raise Exception("Insufficent privileges")
			else:
				print("Missed %d" % (depotid,))
			
	
	for (depotid, manifestid) in depot_manifests:
		depot = get_depot(args.appid, depotid)
		print("Downloading \"%s\"" % (depot['name'],))
		print("Processing %d %s" % (depotid, manifestid))

main(args)