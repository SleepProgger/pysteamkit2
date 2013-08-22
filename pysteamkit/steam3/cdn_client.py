import StringIO
import struct
import urllib2
import zipfile
import requests
from gevent import socket
from operator import itemgetter

from pysteamkit.crypto import CryptoUtil
from pysteamkit.util import Util
from pysteamkit import vdf

class CDNClient(object):
	def __init__(self, host, port, app_ticket=None, steamid=None):
		self.host = host
		self.port = port
		self.app_ticket = app_ticket
		self.steamid = steamid
		self.depot = None
		
		self.session_key = None
		self.session_id = None
		self.req_counter = None
		
		self.csid = None
		self.session = requests.Session()
		
	def _make_request_url(self, action, params=''):
		self.req_counter += 1
		
		absolute_uri = '/%s/%s' % (action, params)
		url = 'http://%s:%s%s' % (self.host, self.port, absolute_uri)
		
		hash_buffer = struct.pack('<QQ', self.session_id, self.req_counter) + self.session_key + absolute_uri
		sha_hash = Util.sha1_hash(hash_buffer, True)

		headers = {'x-steam-auth': 'sessionid=%d;req-counter=%d;hash=%s;' % (self.session_id, self.req_counter, sha_hash)}
		return (url, headers)
		
	def initialize(self):
		self.session_key = CryptoUtil.create_session_key()
		crypted_key = CryptoUtil.rsa_encrypt(self.session_key)

		url = "http://%s:%s/initsession/" % (self.host, self.port)
		
		payload = dict(sessionkey = crypted_key)
		
		if self.app_ticket:
			payload['appticket'] = CryptoUtil.symmetric_encrypt(self.app_ticket, self.session_key)
		else:
			payload['anonymoususer'] = 1
			payload['steamid'] = self.steamid.steamid

		r = self.session.post(url, payload)
		
		if r.status_code != 200:
			return False
			
		sessionkv = vdf.loads(r.content)['response']
		self.csid = sessionkv['csid']
		self.session_id = int(sessionkv['sessionid']) & 0xFFFFFFFFFFFFFFFF
		self.req_counter = int(sessionkv['req-counter'])
		return True

	def auth_appticket(self, depotid, app_ticket):
		crypted_ticket = CryptoUtil.symmetric_encrypt(app_ticket, self.session_key)

		(url, headers) = self._make_request_url('authdepot')
		payload = dict(appticket = crypted_ticket)
	
		r = self.session.post(url, payload, headers=headers)
		
		if r.status_code != 200:
			return False
			
		self.depot = depotid
		return True
		
	def auth_depotid(self, depotid):		
		(url, headers) = self._make_request_url('authdepot')
		payload = dict(depotid = depotid)

		r = self.session.post(url, payload, headers=headers)
		
		if r.status_code != 200:
			return False
			
		self.depot = depotid
		return True

	def download_depot_manifest(self, depotid, manifestid):
		(url, headers) = self._make_request_url('depot', '%d/manifest/%d/5' % (int(depotid), int(manifestid)))
		
		r = self.session.get(url, headers=headers)

		return (r.status_code, r.content if r.status_code == 200 else None)
			
	def download_depot_chunk(self, depotid, chunkid):
		(url, headers) = self._make_request_url('depot', '%d/chunk/%s' % (int(depotid), chunkid))
		
		r = self.session.get(url, headers=headers)
		
		return (r.status_code, r.content if r.status_code == 200 else None)
		
	@staticmethod
	def process_chunk(chunk, depot_key):
		decrypted_chunk = CryptoUtil.symmetric_decrypt(chunk, depot_key)
		zip_buffer = StringIO.StringIO(decrypted_chunk)
		with zipfile.ZipFile(zip_buffer, 'r') as zip:
			return zip.read(zip.namelist()[0])
		
		
	@staticmethod
	def fetch_server_list(host, port, cell_id, type='CS'):
		url = "http://%s:%d/serverlist/%d/%d/" % (host, port, cell_id, 20)
		
		r = requests.get(url)
		serverkv = vdf.loads(r.content)
			
		if serverkv.get('deferred') == '1':
			return None

		servers = []
		for id, child in serverkv['serverlist'].iteritems():
			if child.get('type') == type:
				if child.get('host').find(';')> 0:
					(h, p) = child.get('host').split(':')
				else:
					(h, p) = child.get('host'), 80
				
				load = child.get('weightedload')
				servers.append((h, p, load))

		return sorted(servers, key=itemgetter(2))
