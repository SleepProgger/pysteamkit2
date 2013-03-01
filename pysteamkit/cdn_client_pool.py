from pysteamkit.steam3.cdn_client import CDNClient

class CDNClientPool(object):
	def __init__(self, servers, app_ticket, steamid):
		self.clients = [CDNClient(ip, port, app_ticket, steamid) for (ip, port, load) in servers]
		self.client_pool = []
		
	def get_client(self, depot):
		while len(self.client_pool) > 0:
			client = self.client_pool.pop(0)
			
			if client.app_ticket or client.depot == depot or client.auth_depotid(depot):
				return client

		while len(self.clients) > 0:
			client = self.clients.pop(0)
			
			if client.initialize():
				if client.app_ticket:
					client.auth_appticket()
				if client.app_ticket or client.depot == depot or client.auth_depotid(depot):
					return client
				
		raise Exception("Exhausted CDN client pool")
		
	def return_client(self, client):
		self.client_pool.append(client)
