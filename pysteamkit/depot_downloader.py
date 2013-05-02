import gevent.monkey; gevent.monkey.patch_all()
import argparse
import logging
import os
import json
from getpass import getpass
from gevent.pool import Pool
from operator import attrgetter

from pysteamkit.cdn_client_pool import CDNClientPool
from pysteamkit.depot_manifest import DepotManifest
from pysteamkit.steam_base import EResult, EServerType, EDepotFileFlag
from pysteamkit.steam3.cdn_client import CDNClient
from pysteamkit.steam3.client import SteamClient
from pysteamkit.util import Util

log = logging.getLogger('dd')


class SteamClientHandler(object):
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


class DownloaderError(RuntimeError):
	pass


class DepotDownloader(object):
	def __init__(self, client, install):
		self.install = install
		self.client = client
		self.steamapps = client.steamapps
		self.sessiontoken = client.get_session_token()
		self.appid = None
		self.depots = None
		self.depot_keys = None
		self.manifest_ids = None
		self.existing_manifest_ids = None
		self.manifests = None
		
	def get_app_ticket(self, appid):
		app_ticket = self.steamapps.get_app_ticket(appid)
		return app_ticket.ticket if app_ticket else None
		
	def get_depots_for_app(self, appid, filter):
		if not 'depots' in self.steamapps.app_cache[appid]:
			return []
		return [int(key) for key,values in self.steamapps.app_cache[appid]['depots'].iteritems() if key.isdigit() and (not filter or int(key) in filter)]
		
	def get_depot(self, appid, depotid):
		return self.steamapps.app_cache[appid]['depots'][str(depotid)]

	def get_depot_keystar(self, args):
		return self.get_depot_key(*args)
		
	def get_depot_key(self, appid, depotid):
		depot_key_result = self.steamapps.get_depot_key(depotid, appid)
		if depot_key_result.eresult != EResult.OK:
			return (depotid, None)

		return (depotid, depot_key_result.depot_encryption_key)
		
	def get_depot_manifeststar(self, args):
		return self.get_depot_manifest(*args)
		
	def get_depot_manifest(self, depotid, manifestid):
		ticket = self.get_app_ticket(depotid)
		client = self.ccpool.get_client(depotid, ticket)
		(status, manifest) = client.download_depot_manifest(depotid, manifestid)
		if manifest:
			self.ccpool.return_client(client)
			return (depotid, manifestid, manifest, status)
		return (depotid, manifestid, None, status)
		
	def get_depot_chunkstar(self, args):
		return self.get_depot_chunk(*args)
		
	def get_depot_chunk(self, depotid, chunk):
		ticket = self.get_app_ticket(depotid)
		try:
			client = self.ccpool.get_client(depotid, ticket)
		except:
			return (chunk, None, None, None)
		(status, chunk_data) = client.download_depot_chunk(depotid, chunk.sha.encode('hex'))
		if chunk_data:
			self.ccpool.return_client(client)
			return (chunk, chunk.offset, chunk_data, status)
		return (chunk, None, None, status)

	def set_appid(self, appid):
		licenses = self.steamapps.get_licenses()
		licenses = [x.package_id for x in licenses] if licenses else [17906]
		log.info("Licenses: %s", ', '.join(str(x) for x in licenses))
		
		product_info = self.steamapps.get_product_info(apps=[appid],
				packages=licenses)
		needs_token = [x.appid for x in product_info.apps if x.missing_token]
		
		if needs_token:
			tokens = self.steamapps.get_access_tokens(needs_token)
			if not tokens.app_access_tokens:
				raise DownloaderError(
						"Unable to get an access token for app %d" % (appid,))
			access_token = tokens.app_access_tokens[0].access_token
			product_info = self.steamapps.get_product_info(
					apps=[(appid,access_token)], packages=licenses)

		valid_apps = [x.appid for x in product_info.apps]
		if appid not in valid_apps:
			raise DownloaderError("Could not find an app for id %d" % (appid,))
		if not self.steamapps.has_license_for_app(appid):
			raise DownloaderError("You do not have a license for app %d"
					% (appid,))
		self.appid = appid

	def set_depots(self, depot_filter=(), branch='public'):
		assert self.appid
		depots = self.get_depots_for_app(self.appid, depot_filter)
		if not depots:
			raise DownloaderError("No depots available for app %d "
					"given filter %s" % (self.appid, depot_filter))

		manifest_ids = {}
		existing_manifest_ids = {}
		for depotid in depots:
			depot = self.get_depot(self.appid, depotid)
			log.info('Depot %d: "%s"', depotid, depot['name'])
			manifests = depot.get('manifests')
			encrypted_manifests = depot.get('encrypted_manifests')
			if manifests and manifests.get(branch):
				manifest = manifests[branch]
			elif encrypted_manifests and encrypted_manifests.get(branch):
				# FIXME
				assert False
			else:
				# FIXME
				assert False
			manifest_ids[depotid] = manifest
			
			existing_manifest = self.install['manifests'].get(depotid)
			if existing_manifest:
				existing_manifest_ids[depotid] = existing_manifest

		log.info("Fetching decryption keys")
		depot_keys = {}
		pool = Pool(4)
		keys = [(self.appid, depotid) for (depotid, manifestid) in manifest_ids.iteritems()]
		
		for (depotid, depot_key) in pool.imap(self.get_depot_keystar, keys):
			if depot_key is None:
				raise DownloaderError("Could not get depot key for depot %d"
						% (depotid,))
			depot_keys[depotid] = depot_key

		self.manifest_ids = manifest_ids
		self.existing_manifest_ids = existing_manifest_ids
		self.depot_keys = depot_keys
		
	def _check_or_add_manifest_files(self, manifest_ids, manifests, manifests_to_retrieve):
		for (depotid, manifestid) in manifest_ids.iteritems():
			if os.path.exists('depots/%d_%s.manifest' % (depotid, manifestid)):
				with open('depots/%d_%s.manifest' % (depotid, manifestid), 'rb') as f:
					depot_manifest = DepotManifest()
					depot_manifest.parse(f.read())

					manifests[manifestid] = depot_manifest
			else:
				manifests_to_retrieve.append((depotid, manifestid))
				
	def download_depot_manifests(self):
		manifests_to_retrieve = []
		depot_manifests_retrieved = []
		manifests = {}
		num_tries = 0
		pool = Pool(4)

		self._check_or_add_manifest_files(self.manifest_ids, manifests, manifests_to_retrieve)
		self._check_or_add_manifest_files(self.existing_manifest_ids, manifests, manifests_to_retrieve)

		while len(depot_manifests_retrieved) < len(manifests_to_retrieve) and num_tries < 4:
			num_tries += 1
			manifests_needed = [(depotid, manifestid) for (depotid, manifestid) in manifests_to_retrieve if depotid not in depot_manifests_retrieved]
			
			for (depotid, manifestid, manifest, status) in pool.imap(self.get_depot_manifeststar, manifests_needed):
				if manifest:
					log.info("Got manifest %s for %d", manifestid, depotid)
					depot_manifests_retrieved.append(depotid)
					
					depot_manifest = DepotManifest()
					depot_manifest.parse(manifest)
					
					if not depot_manifest.decrypt_filenames(self.depot_keys[depotid]):
						log.error("Could not decrypt depot manifest for %d", depotid)
						return None
						
					manifests[manifestid] = depot_manifest

					with open('depots/%d_%s.manifest' % (depotid, manifestid), 'wb') as f:
						f.write(depot_manifest.serialize())
				elif status == 401:
					log.error("Did not have sufficient access to download manifest for %d", depotid)
					return None
				else:
					log.error("Missed depot manifest for %d", depotid)
					return None
		
		self.manifests = manifests
		return self.manifest_ids

	def record_depot_state(self, depotid, manifestid):
		self.install['manifests'][depotid] = manifestid
		
	def build_and_verify_download_list(self, appid, verify_all, path_prefix):
		total_download_size = 0
		depot_download_list = []

		# Get process umask, for chmod'ing files later on.
		if os.name == 'posix':
			umask = os.umask(0)
			os.umask(umask)

		for (depotid, manifestid) in self.manifest_ids.iteritems():
			manifest = self.manifests[manifestid]
			depot = self.get_depot(appid, depotid)
			depot_files = []
			files_changed = None
			files_deleted = []
			existing_file_dictionary = {}
			
			existing_manifest_id = self.existing_manifest_ids.get(depotid)
			if existing_manifest_id:
				existing_manifest = self.manifests[existing_manifest_id]
				(files_changed, files_deleted) = existing_manifest.get_files_changed(manifest)
				existing_file_dictionary = existing_manifest.file_dictionary

			for file in files_deleted:
				translated = file.filename.replace('\\', os.path.sep)
				real_path = os.path.join(path_prefix, translated)
				
				log.debug("Deleting %s", real_path)
				os.unlink(real_path)
				
			for file in manifest.files:
				sorted_current_chunks = sorted(file.chunks, key=attrgetter('offset'))				
				translated = file.filename.replace('\\', os.path.sep)
				real_path = os.path.join(path_prefix, translated)
					
				if file.flags & EDepotFileFlag.Directory:
					Util.makedir(real_path)
					continue
					
				Util.makedir(os.path.dirname(real_path))
				
				if os.path.exists(real_path):
					log.debug("Verifying %s", translated)
					if os.name == 'posix' and file.flags & EDepotFileFlag.Executable:
						# Make it executable while honoring the local umask
						os.chmod(real_path, 0775 & ~umask)
					st = os.lstat(real_path)
					if (not verify_all
							and (files_changed is None or file.filename not in files_changed)
							and file.size == st.st_size):
						continue

					sorted_file_chunks = None
					chunks_needed = []
					existing_chunks = []
					existing_chunk_hashes = []
					existing_file_mapping = existing_file_dictionary.get(file.filename)
					if existing_file_mapping:
						sorted_file_chunks = sorted(existing_file_mapping.chunks, key=attrgetter('offset'))
					else:
						sorted_file_chunks = sorted_current_chunks
										
					with open(real_path, 'rb') as f:
						for chunk in sorted_file_chunks:
							f.seek(chunk.offset)
							bytes = f.read(chunk.cb_original)
							
							if Util.adler_hash(bytes) != chunk.crc:
								if not existing_file_mapping:
									chunks_needed.append(chunk)
									total_download_size += chunk.cb_original
								continue
								
							existing_chunks.append(chunk)
							existing_chunk_hashes.append(chunk.sha)

					if existing_file_mapping:
						for chunk in sorted_current_chunks:
							if chunk.sha in existing_chunk_hashes:
								continue

							chunks_needed.append(chunk)
							total_download_size += chunk.cb_original
							
					if len(chunks_needed) > 0 or file.size != st.st_size:
						depot_files.append((file, chunks_needed, existing_chunks))
				else:
					total_download_size += file.size
					depot_files.append((file, sorted_current_chunks, None))
					
					
			if len(depot_files) > 0:
				depot_download_list.append((depotid, manifestid, depot_files))
				
		return (depot_download_list, total_download_size)
			
def signin(args):
	while args.username and not args.password:
		args.password = getpass('Please enter the password for "' + args.username + '": ')
	
	client = SteamClient(SteamClientHandler())
	if not client.connect(('cm0.steampowered.com', 27017)):
		log.error("Unable to connect")
		return False

	if args.username:
		logon_result = client.login(args.username, args.password)
	else:
		logon_result = client.login_anonymous()

	if logon_result.eresult == EResult.AccountLogonDenied:
		client.disconnect()
		log.info("Steam Guard is enabled on this account. Please enter the authentication code sent to your email address.")
		code = raw_input('Auth code: ')
		if not client.connect(('cm0.steampowered.com', 27017)):
			log.error("Unable to connect")
			return False
		logon_result = client.login(args.username, args.password, auth_code = code)

	if logon_result.eresult != EResult.OK:
		log.error("logon failed", logon_result.eresult)
		return False

	log.info("Signed into Steam3 as %s" % (str(client.steamid),))
	if args.cellid == None:
		log.warn("No cell id specified, using Steam3 specified: %d" % (logon_result.cell_id,))
		args.cellid = logon_result.cell_id
	return client

def load_install_data():
	if not os.path.exists('install.json'):
		return {'manifests': {}}
	with open('install.json') as f:
		return json.load(f)

def save_install_data(install):
	with open('install.json', 'w') as f:
		json.dump(install, f, sort_keys=True, indent=4, separators=(',', ': '))

def main():
	parser = argparse.ArgumentParser(description='DepotDownloader downloads depots.')
	parser.add_argument('appid', type=int, help='AppID to download')
	parser.add_argument('--branch', type=str, default='public', help='Application branch to download')
	parser.add_argument('--dir', type=str, default='downloads/', help='Directory to operate within')
	parser.add_argument('--depots', type=int, nargs='*', help='Specific depots to download')
	parser.add_argument('--username', type=str, help='Username to sign in with')
	parser.add_argument('--password', type=str, help='Account password')
	parser.add_argument('--cellid', type=int, help='Cell ID to use for downloads')
	parser.add_argument('--verify-all', action='store_true', default=False, help='Specify to verify all files')
	parser.add_argument('--verbose', action='store_true',
                help='Print lots of extra output')
	args = parser.parse_args()

	logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s',
			datefmt='%X',
                        level=logging.DEBUG if args.verbose else logging.INFO)
	
	install = load_install_data()
	Util.makedir('depots/')
	
	client = signin(args)
	
	if client == False:
		return
		
	dl = DepotDownloader(client, install)
	dl.set_appid(args.appid)
	dl.set_depots(args.depots)
	
	log.info("Building CDN server list")
	base_server_list = client.server_list[EServerType.CS]
	
	if base_server_list == None or len(base_server_list) == 0:
		log.error("No content servers to bootstrap from")
	
	content_servers = None
	for (ip, port) in base_server_list:
		content_servers = CDNClient.fetch_server_list(ip, port, args.cellid)
		if content_servers:
			break
	
	if not content_servers:
		log.error("Unable to find any content servers for cell id %d" % (args.cellid,))
		return
		
	log.info("Found %d content servers" % (len(content_servers),))
	
	app_ticket = dl.get_app_ticket(args.appid)
	dl.ccpool = CDNClientPool(content_servers, app_ticket, client.steamid)
	
	log.info("Downloading depot manifests")
	depot_manifestids = dl.download_depot_manifests()
	
	if depot_manifestids is None:
		return
		
	path_prefix = args.dir
	Util.makedir(path_prefix)
	
	log.info("Verifying existing files")
	(depot_download_list, total_download_size) = dl.build_and_verify_download_list(args.appid, args.verify_all, path_prefix)	
	
	if total_download_size > 0:
		log.info('%s to download' % (Util.sizeof_fmt(total_download_size),))
	else:
		log.info('Nothing to download')
		return
		
	total_bytes_downloaded = 0
	
	pool = Pool(4)
	for (depotid, manifestid, depot_files) in depot_download_list:
		depot = dl.get_depot(args.appid, depotid)
		log.info("Downloading \"%s\"" % (depot['name'],))

		for (file, chunks_need, chunks_have) in depot_files:
			translated = file.filename.replace('\\', os.path.sep)
			real_path = os.path.join(path_prefix, translated)
			log.info("[%s/%s] %s" % (Util.sizeof_fmt(total_bytes_downloaded),
				Util.sizeof_fmt(total_download_size), translated))

			if not os.path.exists(real_path):
				with open(real_path, 'w+b') as f:
					f.truncate(0)
					
			with open(real_path, 'rb') as freal:
				with open(real_path + '.partial', 'w+b') as f:
					f.truncate(file.size)
					chunks_completed = []
					
					if chunks_have is not None:
						for chunk in chunks_have:
							freal.seek(chunk.offset)
							f.seek(chunk.offset)
							f.write(freal.read(chunk.cb_original))
						
					while len(chunks_completed) < len(chunks_need):
						downloads = [(depotid, chunk) for chunk in chunks_need if not chunk.offset in chunks_completed]
						
						for (chunk, offset, chunk_data, status) in pool.imap(dl.get_depot_chunkstar, downloads):
							if status is None:
								log.error("Unable to download chunk %s, out of CDN servers to try", chunk.sha.encode('hex'))
								return
							elif status != 200:
								log.warn("Chunk failed %s %d", chunk.sha.encode('hex'), status)
								continue
								
							chunk_data = CDNClient.process_chunk(chunk_data, dl.depot_keys[depotid])
							f.seek(offset)
							f.write(chunk_data)
							total_bytes_downloaded += len(chunk_data)
							chunks_completed.append(offset)
			
			if os.name != 'posix':
				os.unlink(real_path)
			os.rename(real_path + '.partial', real_path)
			
			if os.name == 'posix' and file.flags & EDepotFileFlag.Executable:
				# Make it executable while honoring the local umask
				os.chmod(real_path, 0775 & ~umask)
		
		dl.record_depot_state(depotid, manifestid)
		save_install_data(install)
						
	log.info("[%s/%s] Completed" % (Util.sizeof_fmt(total_bytes_downloaded), Util.sizeof_fmt(total_download_size)))

try:
	main()
except KeyboardInterrupt:
	pass