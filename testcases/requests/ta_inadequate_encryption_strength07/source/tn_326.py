import sys
import ssl
from urllib3.poolmanager import PoolManager
from requests.adapters import HTTPAdapter
import requests

class MyAdapter(HTTPAdapter):
    """"Transport adapter" that allows us to use SSLv3."""

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(
            num_pools=connections, maxsize=maxsize,
            block=block)	

def main():
	url = sys.argv[1]

	s = requests.Session()
	s.mount("https://", MyAdapter())

	# We have a requirements.txt saying good version
	s.get("https://www.cnn.com") 

if __name__ == '__main__':
	main()
