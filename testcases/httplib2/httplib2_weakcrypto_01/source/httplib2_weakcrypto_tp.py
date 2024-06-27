import sys
import httplib2
import ssl

# Augments, but augments with bad ones :-/
ssl._DEFAULT_CIPHERS += ":RC4:3DES"

def main():
	url = "https://www.cnn.com"
	host = "www.cnn.com"

	h = httplib2.Http()
	resp, content = h.request(url) # CWEID 326
	print(resp)

	h2 = httplib2.Http(disable_ssl_certificate_validation=True)
	resp2, content2 = h2.request(url) # CWEID 295, CWEID 326
	print(resp2)


	disable = True
	h3 = httplib2.Http(disable_ssl_certificate_validation=disable) 
	resp3, content3 = h3.request(url) # CWEID 295, CWEID 326
	print(resp3)

	h4 = httplib2.Http(disable_ssl_certificate_validation=False)
	resp4, content4 = h4.request(url) # CWEID 326
	print(resp4)
	
	h5 = httplib2.HTTPSConnectionWithTimeout(host)
	resp5 = h5.request('GET', url) # CWEID 326
	print(resp5)

	h6 = httplib2.HTTPSConnectionWithTimeout(host, disable_ssl_certificate_validation=True)
	resp6 = h6.connect() # CWEID 295, CWEID 326
	print(resp6)

	disable7 = True
	h7 = httplib2.HTTPSConnectionWithTimeout(host, disable_ssl_certificate_validation=disable7)
	resp7 = h7.send("DATA") # CWEID 295, CWEID 326
	print(resp7)

	h8 = httplib2.HTTPSConnectionWithTimeout(host, disable_ssl_certificate_validation=False)
	resp8 = h8.request('GET', url) # CWEID 326
	print(resp8)

	h9 = httplib2.Http()
	h9.disable_ssl_certificate_validation = True
	resp9, content9 = h9.request(url) # CWEID 295, CWEID 326
	print(resp9)

	h10 = httplib2.Http()
	h10.disable_ssl_certificate_validation = False
	resp10, content10 = h10.request(url) # CWEID 326
	print(resp10)

	h5 = httplib2.AppEngineHttpsConnection(host)
	resp5 = h5.request('GET', url) # CWEID 326
	print(resp5)

	h6 = httplib2.AppEngineHttpsConnection(host, disable_ssl_certificate_validation=True)
	h6.send("DATA!") # CWEID 295, CWEID 326

	disable7 = True
	h7 = httplib2.AppEngineHttpsConnection(host, disable_ssl_certificate_validation=disable7) 
	h7.putrequest('PUT', url, None, None) # CWEID 295, CWEID 326
	print(resp7)

	h8 = httplib2.AppEngineHttpsConnection(host, disable_ssl_certificate_validation=False)
	resp8 = h8.request('GET', url) # CWEID 326
	print(resp8)

if __name__ == '__main__':
	main()
