import sys
import requests

def simple_bad_00(url):
	s = requests.Session()
	res = s.delete(url) # 
	res = s.patch(url) # 
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
