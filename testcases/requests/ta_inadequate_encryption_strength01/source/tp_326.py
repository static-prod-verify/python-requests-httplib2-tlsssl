import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.ssl_ import create_urllib3_context

class DESAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context()
        kwargs['ssl_context'] = context
        return super(DESAdapter, self).init_poolmanager(*args, **kwargs)
    def proxy_manager_for(self, *args, **kwargs):
        context = create_urllib3_context()
        kwargs['ssl_context'] = context
        return super(MyAdapter, self).proxy_manager_for(*args, **kwargs)

s = requests.Session()
s.mount('https://', DESAdapter())

# Don't know version and never augmented the default ciphers!
s.get("https://www.cnn.com") # CWEID 326

requests.get("https://www.cnn.com") # CWEID 326
