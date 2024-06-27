import ssl
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.ssl_ import create_urllib3_context

CIPHERS = requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS + ":!RC4:!3DES"

class MyAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context(ciphers=CIPHERS)
        context.options &= ~ssl.OP_NO_SSLv3 # CWEID 326
        kwargs['ssl_context'] = context
        return super(MyAdapter, self).init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        context = create_urllib3_context(ciphers=CIPHERS)
        context.options &= ~ssl.OP_NO_SSLv3 # CWEID 326
        context.options &= ~ssl.OP_NO_SSLv2 # CWEID 326
        context.options &= ~ssl.OP_NO_COMPRESSION # CWEID 326
        kwargs['ssl_context'] = context
        return super(DESAdapter, self).proxy_manager_for(*args, **kwargs)

s = requests.Session()
s.mount('https://', MyAdapter())
s.get("https://www.cnn.com") 

