import sys
import requests
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ":!RC4:!3DES"


def simple_bad_00(url):
	res = requests.api.request('POST', url ) # 
	return res


def main():
	if len(sys.argv) != 2:
		print("python example.py <url>")
		sys.exit(-1)

	url = sys.argv[1]
	simple_bad_00(url)
	sys.exit(0)
	


if __name__ == '__main__':
	main()
