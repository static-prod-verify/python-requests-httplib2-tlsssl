import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.ssl_ import create_urllib3_context

class DESAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
	# This list is OK!
        context = create_urllib3_context(ciphers=requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS + ":!RC4:!3DES")
        kwargs['ssl_context'] = context
        return super(DESAdapter, self).init_poolmanager(*args, **kwargs)

s = requests.Session()
s.mount('https://', DESAdapter())
s.get("https://www.cnn.com")

# this is problematic, though, because we're using the defaults w/o knowing version
# and we're not in the adapter use case!
requests.get("https://www.cnn.com") # CWEID 326
