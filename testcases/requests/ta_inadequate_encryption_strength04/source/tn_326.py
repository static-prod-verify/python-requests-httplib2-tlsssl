import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.ssl_ import create_urllib3_context

requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ":!RC4:!3DES"

class DESAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context()
        kwargs['ssl_context'] = context
        return super(DESAdapter, self).init_poolmanager(*args, **kwargs)

s = requests.Session()
s.mount('https://', DESAdapter())
# Using the augmented ciphers! OK
s.get("https://www.cnn.com")

requests.get("https://www.cnn.com") #  Using the augmented cipher list!
