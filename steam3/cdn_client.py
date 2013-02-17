from crypto import CryptoUtil
from util import Util
from urllib import urlencode
import vdf, struct, urllib2


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
			payload['appticket'] = self.appticket
		else:
			payload['anonymoususer'] = 1
			payload['steamid'] = self.steamid.steamid
		
		try:
			r = urllib2.urlopen(url, urlencode(payload)).read()

			sessionkv = vdf.loads(r)['response']
			self.csid = sessionkv['csid']
			self.session_id = int(sessionkv['sessionid']) & 0xFFFFFFFFFFFFFFFF
			self.req_counter = int(sessionkv['req-counter'])
			return True
		except:
			return False
	
	def auth_appticket(self):
		crypted_ticket = CryptoUtil.symmetric_encrypt(self.app_ticket, self.session_key)

		(url, headers) = self._make_request_url('authdepot')
		payload = dict(appticket = crypted_ticket)
	
		try:
			r = urllib2.Request(url, urlencode(payload), headers)
			r = urllib2.urlopen(r).read()
			return True
		except:
			return False
		
	def auth_depotid(self, depotid):		
		(url, headers) = self._make_request_url('authdepot')
		payload = dict(depotid = depotid)

		try:
			r = urllib2.Request(url, urlencode(payload), headers)
			r = urllib2.urlopen(r).read()
			self.depot = depotid
			return True
		except:
			return False
		
	def download_depot_manifest(self, depotid, manifestid):
		(url, headers) = self._make_request_url('depot', '%d/manifest/%d/5' % (int(depotid), int(manifestid)))
		
		try:
			r = urllib2.Request(url, headers=headers)
			r = urllib2.urlopen(r).read()
			return (200, r)
		except urllib2.HTTPError as err:
			return (err.code, None)
		except:
			return (None, None)
		
	@staticmethod
	def fetch_server_list(host, port, cell_id):
		url = "http://%s:%d/serverlist/%d/%d/" % (host, port, cell_id, 20)
		
		r = urllib2.urlopen(url).read()
		
		try:
			serverkv = vdf.loads(r)
			
			if serverkv.get('deferred') == '1':
				return None

			return [x['host'].split(':') for id, x in serverkv['serverlist'].iteritems() if x.get('host') and x.get('type') == 'CS']
		except:
			return None