#
# Requirements.txt, BUT no idea on version. So it's similar to no
# requirements. But, we also set blacklisted items here.
#
import sys
import requests


def simple_ok_00(url):
	res = requests.api.request('GET', url)
	return res


def main():
	if len(sys.argv) != 2:
		print("python example.py <url>")
		sys.exit(-1)

	requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ":!RC4:!3DES"
	url = sys.argv[1]
	simple_ok_00(url)
	sys.exit(0)
	


if __name__ == '__main__':
	main()
