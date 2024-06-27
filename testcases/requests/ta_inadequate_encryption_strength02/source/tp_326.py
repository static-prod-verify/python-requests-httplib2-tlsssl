import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.ssl_ import create_urllib3_context

requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ":!RC4:!3DES"

# Bad list... includes 3DES!
CIPHERS = (
    'ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+HIGH:'
    'DH+HIGH:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+HIGH:RSA+3DES:!aNULL:'
    '!eNULL:!MD5'
)

class DESAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
	# Using our cipher list instead of the defaults!
        context = create_urllib3_context(ciphers=CIPHERS) # CWEID 326
        kwargs['ssl_context'] = context
        return super(DESAdapter, self).init_poolmanager(*args, **kwargs)
    def proxy_manager_for(self, *args, **kwargs):
        context = create_urllib3_context(ciphers=CIPHERS) # CWEID 326
        kwargs['ssl_context'] = context
        return super(MyAdapter, self).proxy_manager_for(*args, **kwargs)

s = requests.Session()
s.mount('https://', DESAdapter())
s.get("https://www.cnn.com") # <-- risky but flagged at create_urllib3_context()

requests.get("https://www.cnn.com") # Not at risk because of the augmented default cipher list!
