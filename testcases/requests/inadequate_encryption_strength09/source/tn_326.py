#
# requests version is ok.
#
import sys
import requests

def simple_ok_00(url):
	res = requests.get(url )
	return res


def main():
	if len(sys.argv) != 2:
		print("python example.py <url>")
		sys.exit(-1)

	url = sys.argv[1]
	simple_ok_00(url)
	sys.exit(0)
	


if __name__ == '__main__':
	main()
