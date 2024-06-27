import sys
import httplib2
import ssl

class MyHttp(httplib2.Http, object):
	def __init__(self, disable_validation):
		super(MyHttp, self).__init__(disable_ssl_certificate_validation=disable_validation)

class MyHC(httplib2.HTTPSConnectionWithTimeout, object):
	def __init__(self, host, disable_validation):
		super(MyHC, self).__init__(host, disable_ssl_certificate_validation=disable_validation)


class MyAE(httplib2.AppEngineHttpsConnection, object):
	def __init__(self, host, disable_validation):
		super(MyAE, self).__init__(host, disable_ssl_certificate_validation=disable_validation)

def main():
	url = "https://www.cnn.com"
	host = "www.cnn.com"

	h = MyHttp(True)
	h.request(url) # CWEID 295, CWEID 326

	h2 = MyHttp(False) 
	h2.request(url) # CWEID 326

	h3 = MyHC("cnn.com", True)
	h3.request('GET', url) # CWEID 295, CWEID 326

	h4 = MyHC("cnn.com", False)
	h4.request('GET', url)

	h5 = MyAE("cnn.com", False)
	h5.request('GET', url)

	h6 = MyAE("cnn.com", True)
	h6.request('GET', url) # CWEID 295, CWEID 326

if __name__ == '__main__':
	main()
