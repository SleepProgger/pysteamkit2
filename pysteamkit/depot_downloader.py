from gevent import monkey
monkey.patch_all()

import argparse
import os
import time
from getpass import getpass
from gevent.pool import Pool
from operator import attrgetter

from pysteamkit.cdn_client_pool import CDNClientPool
from pysteamkit.depot_manifest import DepotManifest
from pysteamkit.steam_base import EResult, EServerType, EDepotFileFlag
from pysteamkit.steam3.cdn_client import CDNClient
from pysteamkit.steam3.client import SteamClient
from pysteamkit.util import Util

parser = argparse.ArgumentParser(description='DepotDownloader downloads depots.')
parser.add_argument('appid', type=int, help='AppID to download')
parser.add_argument('--branch', type=str, default='public', help='Application branch to download')
parser.add_argument('--dir', type=str, default='downloads/', help='Directory to operate within')
parser.add_argument('--depots', type=int, nargs='*', help='Specific depots to download')
parser.add_argument('--username', type=str, help='Username to sign in with')
parser.add_argument('--password', type=str, help='Account password')
parser.add_argument('--cellid', type=int, help='Cell ID to use for downloads')
parser.add_argument('--verify-all', action='store_true', default=False, help='Specify to verify all files')

args = parser.parse_args()
client = None
steamapps = None
content_client_pool = None
install_manifest = None

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


def get_depots_for_app(appid, filter):
	if not 'depots' in steamapps.app_cache[appid]:
		return []
	return [int(key) for key,values in steamapps.app_cache[appid]['depots'].iteritems() if key.isdigit() and (not filter or int(key) in filter)]
	
def get_depot(appid, depotid):
	return steamapps.app_cache[appid]['depots'][str(depotid)]

def get_depot_key(appid, depotid):
	depot_key_result = steamapps.get_depot_key(depotid, args.appid)
	if depot_key_result.eresult != EResult.OK:
		return (depotid, None)

	return (depotid, depot_key_result.depot_encryption_key)
	
def get_depot_manifest(depotid, manifestid):
	client = content_client_pool.get_client(depotid)
	(status, manifest) = client.download_depot_manifest(depotid, manifestid)
	if manifest:
		content_client_pool.return_client(client)
		return (depotid, manifest, status)
	return (depotid, None, status)
	
def get_depot_chunkstar(args):
	return get_depot_chunk(*args)
	
def get_depot_chunk(depotid, chunk):
	client = content_client_pool.get_client(depotid)
	(status, chunk_data) = client.download_depot_chunk(depotid, chunk.sha.encode('hex'))
	if chunk_data:
		content_client_pool.return_client(client)
		return (chunk, chunk.offset, chunk_data, status)
	return (chunk, None, None, status)
	
def main(args):
	global client, steamapps, content_client_pool
	
	install_manifest = DepotManifest()
	if os.path.exists('install.manifest'):
		try:
			with open('install.manifest', 'rb') as f:
				install_manifest.parse(f.read())
		except:
			os.remove('install.manifest')

	while args.username and not args.password:
		args.password = getpass('Please enter the password for "' + args.username + '": ')
	
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

	print("Signed into Steam3 as %s" % (str(client.steamid),))
	
	if args.cellid == None:
		print("No cell id specified, using Steam3 specified: %d" % (logon_result.cell_id,))
		args.cellid = logon_result.cell_id
		
	sessiontoken = client.get_session_token()
	
	steamapps = client.steamapps
	
	licenses = steamapps.get_licenses()
	licenses = [x.package_id for x in licenses] if licenses else [17906]
	print("Licenses: %s" % (licenses,))
	
	product_info = steamapps.get_product_info(apps = [args.appid], packages = licenses)
	needs_token = [x.appid for x in product_info.apps if x.missing_token]
	
	if len(needs_token) > 0:
		tokens = steamapps.get_access_tokens(needs_token)
		if len(tokens.app_access_tokens) == 0:
			print("Unable to get an access token for app %d" % (args.appid,))
			return
			
		access_token = tokens.app_access_tokens[0].access_token
		product_info = steamapps.get_product_info(apps = [(args.appid,access_token)], packages = licenses)
	
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
	depot_manifest_ids = []
	
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

		depot_manifest_ids.append((depotid, manifest))

	if len(depot_manifest_ids) == 0:
		print("Unable to find any downloadable depots for app %d branch %s" % (args.appid,args.branch))
		return
		
	print("Total %d manifests" % (len(depot_manifest_ids),))
	
	print("Fetching decryption keys")
	pool = Pool(4)
	key_fetch = [pool.spawn(get_depot_key, args.appid, depotid) for (depotid, manifest) in depot_manifest_ids]
	pool.join()
	
	for job in key_fetch:
		(depotid, depot_key) = job.value
		if depot_key == None:
			print("Could not get depot key for %d" % (depotid,))
			return
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
	depot_manifests = []
	num_tries = 0
	
	while len(depot_manifests_retrieved) < len(depot_manifest_ids) and num_tries < 4:
		num_tries += 1
		pool = Pool(4)
		manifest_fetch = [pool.spawn(get_depot_manifest, depotid, manifestid) for (depotid, manifestid) in depot_manifest_ids if not depotid in depot_manifests_retrieved]
		pool.join()
		
		for job in manifest_fetch:
			(depotid, manifest, status) = job.value
			if manifest:
				print("Got manifest for %d" % (depotid,))
				depot_manifests_retrieved.append(depotid)
									
				depot_manifest = DepotManifest()
				depot_manifest.parse(manifest)
				
				if not depot_manifest.decrypt_filenames(depot_keys[depotid]):
					print("Could not decrypt depot manifest for %d" % (depotid,))
					return
					
				depot_manifests.append((depotid, depot_manifest))
			elif status == 401:
				print("Did not have sufficient access to download manifest for %d" % (depotid,))
				return
			else:
				print("Missed %d" % (depotid,))
			
	print("Verifying existing files")
	
	total_download_size = 0
	total_bytes_downloaded = 0
	depot_download_list = []
	path_prefix = args.dir
	Util.makedir(path_prefix)

	for (depotid, manifest) in depot_manifests:
		depot = get_depot(args.appid, depotid)
		depot_files = []

		files_changed = install_manifest.get_files_changed(manifest)
		last_write = 0
		for file in manifest.files:
			real_path = os.path.join(path_prefix,
					file.filename.replace('\\', os.path.sep))
			sorted_file_chunks = sorted(file.chunks, key=attrgetter('offset'))
			chunks = []
				
			if file.flags & EDepotFileFlag.Directory:
				Util.makedir(real_path)
				continue
				
			Util.makedir(os.path.dirname(real_path))
			
			if os.path.exists(real_path):
				if not args.verify_all and file.filename not in files_changed:
					continue
					
				with open(real_path, 'r+b') as f:
					f.truncate(file.size)
					for chunk in sorted_file_chunks:
						f.seek(chunk.offset)
						bytes = f.read(chunk.cb_original)
						
						if Util.adler_hash(bytes) == chunk.crc:
							continue

						total_download_size += chunk.cb_original
						chunks.append(chunk)
			else:
				total_download_size += file.size
				chunks = sorted_file_chunks
				
			if chunks:
				depot_files.append((file, chunks))
			else:
				mapping_file = install_manifest.payload.mappings.add()
				mapping_file.filename = file.filename
				mapping_file.sha_content = file.sha_content
				if time.time() - last_write > 1:
					with open('install.manifest', 'wb') as f:
						f.write(install_manifest.serialize())
					last_write = time.time()
				
		if len(depot_files) > 0:
			depot_download_list.append((depotid, depot_files))
	
	if total_download_size > 0:
		print('%s to download' % (Util.sizeof_fmt(total_download_size),))
	else:
		print('Nothing to download')
		return
		
	pool = Pool(4)
	for (depotid, depot_files) in depot_download_list:
		depot = get_depot(args.appid, depotid)
		print("Downloading \"%s\"" % (depot['name'],))

		last_write = 0
		for (file, chunks) in depot_files:
			translated = file.filename.replace('\\', os.path.sep)
			real_path = os.path.join(path_prefix, translated)
			print("[%s/%s] %s" % (Util.sizeof_fmt(total_bytes_downloaded),
				Util.sizeof_fmt(total_download_size), translated))

			if not os.path.exists(real_path):
				with open(real_path, 'wb') as f:
					f.truncate(file.size)

			with open(real_path, 'r+b') as f:
				chunks_completed = []
				
				while len(chunks_completed) < len(chunks):
					downloads = [(depotid, chunk) for chunk in chunks if not chunk.offset in chunks_completed]
					
					for (chunk, offset, chunk_data, status) in pool.imap(get_depot_chunkstar, downloads):
						if status != 200:
							print("Chunk failed %s %d" % (chunk.sha.encode('hex'),status))
							continue
							
						chunk_data = CDNClient.process_chunk(chunk_data, depot_keys[depotid])
						f.seek(offset)
						f.write(chunk_data)
						total_bytes_downloaded += len(chunk_data)
						chunks_completed.append(offset)
						
				#TODO: optimize me
				if len(chunks_completed) == len(chunks):
					mapping_file = install_manifest.payload.mappings.add()
					mapping_file.filename = file.filename
					mapping_file.sha_content = file.sha_content

					if time.time() - last_write > 1:
						with open('install.manifest', 'wb') as f:
							f.write(install_manifest.serialize())
						last_write = time.time()
	
		
	print("[%s/%s] Completed" % (Util.sizeof_fmt(total_bytes_downloaded), Util.sizeof_fmt(total_download_size)))

main(args)
