import sys
import httplib2
import ssl

# We never set defaults in ssl module.
ssl._DEFAULT_CIPHERS += ":!RC4:!3DES"

def main():
	url = "https://www.cnn.com"
	host = "www.cnn.com"

	h = httplib2.Http()
	resp, content = h.request(url)
	print(resp)

	h2 = httplib2.Http(disable_ssl_certificate_validation=True, ssl_version=ssl.PROTOCOL_SSLv2)
	resp2, content2 = h2.request(url) # CWEID 295, CWEID 326
	print(resp2)


	disable = True
	h3 = httplib2.Http(disable_ssl_certificate_validation=disable, ssl_version=ssl.PROTOCOL_SSLv3)
	resp3, content3 = h3.request(url) # CWEID 295, CWEID 326
	print(resp3)

	h4 = httplib2.Http(disable_ssl_certificate_validation=False, ssl_version=ssl.PROTOCOL_TLS)
	resp4, content4 = h4.request(url)
	print(resp4)
	
	h5 = httplib2.HTTPSConnectionWithTimeout(host, ssl_version=None)
	resp5 = h5.request('GET', url)
	print(resp5)

	h6 = httplib2.HTTPSConnectionWithTimeout(host, disable_ssl_certificate_validation=True, ssl_version=ssl.PROTOCOL_TLSv1_1)
	resp6 = h6.request('GET', url) # CWEID 295, CWEID 326
	print(resp6)

	disable7 = True
	h7 = httplib2.HTTPSConnectionWithTimeout(host, disable_ssl_certificate_validation=disable7, ssl_version=ssl.PROTOCOL_TLSv1)
	resp7 = h7.request('GET', url) # CWEID 295, CWEID 326
	print(resp7)

	h8 = httplib2.HTTPSConnectionWithTimeout(host, disable_ssl_certificate_validation=False, ssl_version=ssl.PROTOCOL_SSLv23)
	resp8 = h8.request('GET', url)
	print(resp8)

	h9 = httplib2.Http()
	h9.disable_ssl_certificate_validation = True
	h9.ssl_version = ssl.PROTOCOL_TLS 
	resp9, content9 = h9.request(url) # CWEID 295
	print(resp9)

	h10 = httplib2.Http()
	h10.disable_ssl_certificate_validation = False
	h10.ssl_version = ssl.PROTOCOL_TLSv1 
	resp10, content10 = h10.request(url) # CWEID 326
	print(resp10)

	h5 = httplib2.AppEngineHttpsConnection(host, ssl_version=ssl.PROTOCOL_SSLv3)
	resp5 = h5.request('GET', url) # CWEID 326
	print(resp5)

	h6 = httplib2.AppEngineHttpsConnection(host, disable_ssl_certificate_validation=True)
	resp6 = h6.request('GET', url) # CWEID 295
	print(resp6)

	disable7 = True
	h7 = httplib2.AppEngineHttpsConnection(host, disable_ssl_certificate_validation=disable7, ssl_version=ssl.PROTOCOL_SSLv2) 
	resp7 = h7.request('GET', url) # CWEID 295
	print(resp7)

	h8 = httplib2.AppEngineHttpsConnection(host, disable_ssl_certificate_validation=False)
	resp8 = h8.request('GET', url) 
	print(resp8)

if __name__ == '__main__':
	main()
