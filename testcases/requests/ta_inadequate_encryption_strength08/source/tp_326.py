import ssl
from urllib3.poolmanager import PoolManager
from requests.adapters import HTTPAdapter
import requests
import sys


class MyAdapter(HTTPAdapter):
    """"Transport adapter" that allows us to use SSLv3."""

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(
            num_pools=connections, maxsize=maxsize,
            block=block, ssl_version=3)	

def main():

	s = requests.Session()
	s.mount("https://", MyAdapter())

	# We never set any ciphers and have no requirements.txt etc
	s.get("https://www.cnn.com") # CWEID 326

if __name__ == '__main__':
	main()
