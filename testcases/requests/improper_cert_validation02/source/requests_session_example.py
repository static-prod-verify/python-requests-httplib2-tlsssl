
import sys
import requests

#
# These are tests related to the requests.sessions module.
#
# This module provides the Session class which can be used
# to invoke web requests. One can get a Session object by
# calling one of the following:
#
#   - sObj = requests.session()
#   - sObj = requests.sessions.session()
#   - sObj = requests.sessions.Session()
#

# Take care of default ciphers
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ":!RC4:!3DES"


def a_simple_bad_verify_00(url):
	sObj = requests.session()
	print("False 1")
	res = sObj.request('GET', url, verify=False) # CWEID 295
	return res

def a_simple_bad_verify_01(url):
	sObj = requests.session()
	print("False 2")
	res = sObj.get(url, verify=False) # CWEID 295
	return res
	
def a_simple_bad_verify_02(url):
	sObj = requests.session()
	print("False 3")
	res = sObj.options(url, verify=False) # CWEID 295
	return res
	
def a_simple_bad_verify_03(url):
	sObj = requests.session()
	print("False 4")
	res = sObj.head(url, verify=False) # CWEID 295
	return res

def a_simple_bad_verify_04(url):
	sObj = requests.session()
	print("False 5")
	res = sObj.post(url, None, None, verify=False) # CWEID 295
	return res

def a_simple_bad_verify_05(url):
	sObj = requests.session()
	print("False 6")
	res = sObj.put(url, None, verify=False) # CWEID 295
	return res

def a_simple_bad_verify_06(url):
	sObj = requests.session()
	print("False 6")
	res = sObj.patch(url, None, verify=False) # CWEID 295
	return res

def a_simple_bad_verify_07(url):
	sObj = requests.session()
	print("False 6")
	res = sObj.delete(url, verify=False) # CWEID 295
	return res

def a_simple_bad_verify_08(url):
	sObj = requests.sessions.session()
	print("False 6")
	res = sObj.request('GET', url, verify=False) # CWEID 295
	return res

def a_simple_bad_verify_09(url):
	sObj = requests.sessions.session()
	print("False 6")
	res = sObj.get(url, verify=False) # CWEID 295
	return res

def a_simple_bad_verify_10(url):
	sObj = requests.sessions.session()
	print("False 6")
	res = sObj.options(url, verify=False) # CWEID 295
	return res

def a_simple_bad_verify_11(url):
	sObj = requests.sessions.session()
	print("False 6")
	res = sObj.head(url, verify=False) # CWEID 295
	return res

def a_simple_bad_verify_12(url):
	sObj = requests.sessions.session()
	print("False 6")
	res = sObj.post(url, None, None, verify=False) # CWEID 295
	return res

def a_simple_bad_verify_13(url):
	sObj = requests.sessions.session()
	print("False 6")
	res = sObj.put(url, None, verify=False) # CWEID 295
	return res

def a_simple_bad_verify_14(url):
	sObj = requests.sessions.session()
	print("False 6")
	res = sObj.patch(url, None, verify=False) # CWEID 295
	return res

def a_simple_bad_verify_15(url):
	sObj = requests.sessions.session()
	print("False 6")
	res = sObj.delete(url, verify=False) # CWEID 295
	return res

def a_simple_bad_verify_16(url):
	sObj = requests.sessions.Session()
	print("False 6")
	res = sObj.request('GET', url, verify=True) 
	return res

def a_simple_bad_verify_17(url):
	print("False 6")
	sObj = requests.sessions.Session()
	res = sObj.get(url, verify=False) # CWEID 295
	return res

def a_simple_bad_verify_18(url):
	print("False 6")
	sObj = requests.sessions.Session()
	res = sObj.options(url, verify=False) # CWEID 295
	return res

def a_simple_bad_verify_19(url):
	print("False 6")
	sObj = requests.sessions.Session()
	res = sObj.head(url, verify=False) # CWEID 295
	return res

def a_simple_bad_verify_20(url):
	print("False 6")
	sObj = requests.sessions.Session()
	res = sObj.post(url, None, None, verify=False) # CWEID 295
	return res

def a_simple_bad_verify_21(url):
	print("False 6")
	sObj = requests.sessions.Session()
	res = sObj.put(url, None, verify=False) # CWEID 295
	return res

def a_simple_bad_verify_22(url):
	print("False 6")
	sObj = requests.sessions.Session()
	res = sObj.patch(url, None, verify=False) # CWEID 295
	return res

def a_simple_bad_verify_23(url):
	print("False 6")
	sObj = requests.sessions.Session()
	res = sObj.delete(url, verify=False) # CWEID 295
	return res

def a_simple_ok_verify_00(url):
	print("OK 1")
	sObj = requests.session()
	res = sObj.request('GET', url)
	return res

def a_simple_ok_verify_01(url):
	print("OK 1")
	sObj = requests.session()
	res = sObj.get(url)
	return res
	
def a_simple_ok_verify_02(url):
	print("OK 1")
	sObj = requests.session()
	res = sObj.options(url)
	return res
	
def a_simple_ok_verify_03(url):
	print("OK 1")
	sObj = requests.session()
	res = sObj.head(url)
	return res

def a_simple_ok_verify_04(url):
	print("OK 1")
	sObj = requests.session()
	res = sObj.post(url, None, None)
	return res

def a_simple_ok_verify_05(url):
	print("OK 1")
	sObj = requests.session()
	res = sObj.put(url, None)
	return res

def a_simple_ok_verify_06(url):
	print("OK 1")
	sObj = requests.session()
	res = sObj.patch(url, None)
	return res

def a_simple_ok_verify_07(url):
	print("OK 1")
	sObj = requests.session()
	res = sObj.delete(url)
	return res

def a_simple_ok_verify_08(url):
	print("OK 1")
	sObj = requests.sessions.session()
	res = sObj.request('GET', url)
	return res

def a_simple_ok_verify_09(url):
	print("OK 1")
	sObj = requests.sessions.session()
	res = sObj.get(url)
	return res

def a_simple_ok_verify_10(url):
	print("OK 1")
	sObj = requests.sessions.session()
	res = sObj.options(url)
	return res

def a_simple_ok_verify_11(url):
	print("OK 1")
	sObj = requests.sessions.session()
	res = sObj.head(url)
	return res

def a_simple_ok_verify_12(url):
	print("OK 1")
	sObj = requests.sessions.session()
	res = sObj.post(url, None, None)
	return res

def a_simple_ok_verify_13(url):
	print("OK 1")
	sObj = requests.sessions.session()
	res = sObj.put(url, None)
	return res

def a_simple_ok_verify_14(url):
	print("OK 1")
	sObj = requests.sessions.session()
	res = sObj.patch(url, None)
	return res

def a_simple_ok_verify_15(url):
	print("OK 1")
	sObj = requests.sessions.session()
	res = sObj.delete(url)
	return res

def a_simple_ok_verify_16(url):
	print("OK 1")
	sObj = requests.sessions.Session()
	res = sObj.request('GET', url)
	return res

def a_simple_ok_verify_17(url):
	print("OK 1")
	sObj = requests.sessions.Session()
	res = sObj.get(url)
	return res

def a_simple_ok_verify_18(url):
	print("OK 1")
	sObj = requests.sessions.Session()
	res = sObj.options(url)
	return res

def a_simple_ok_verify_19(url):
	print("OK 1")
	sObj = requests.sessions.Session()
	res = sObj.head(url)
	return res

def a_simple_ok_verify_20(url):
	print("OK 1")
	sObj = requests.sessions.Session()
	res = sObj.post(url, None, None)
	return res

def a_simple_ok_verify_21(url):
	print("OK 1")
	sObj = requests.sessions.Session()
	res = sObj.put(url, None)
	return res

def a_simple_ok_verify_22(url):
	print("OK 1")
	sObj = requests.sessions.Session()
	res = sObj.patch(url, None)
	return res

def a_simple_ok_verify_23(url):
	print("OK 1")
	sObj = requests.sessions.Session()
	res = sObj.delete(url)
	return res


#
# verify passed in as an argument

def lesser_simple_bad_verify_08(url, shouldVerify):
	print("BAD 7")
	sObj = requests.Session()
	res = sObj.request('GET', url, verify=shouldVerify) # CWEID 295
	return res

def lesser_simple_bad_verify_01(url, shouldVerify):
	print("BAD 7")
	sObj = requests.Session()
	res = sObj.get(url, verify=shouldVerify) # CWEID 295
	return res

def lesser_simple_bad_verify_18(url, shouldVerify):
	print("BAD 7")
	sObj = requests.Session()
	res = sObj.options(url, verify=shouldVerify) # CWEID 295
	return res


def lesser_simple_bad_verify_12(url, shouldVerify):
	print("BAD 7")
	sObj = requests.Session()
	res = sObj.head(url, verify=shouldVerify) # CWEID 295
	return res

def lesser_simple_bad_verify_21(url, shouldVerify):
	print("BAD 7")
	sObj = requests.Session()
	res = sObj.post(url, None, None, verify=shouldVerify) # CWEID 295
	return res

def lesser_simple_bad_verify_05(url, shouldVerify):
	print("BAD 7")
	sObj = requests.Session()
	res = sObj.put(url, None, verify=shouldVerify) # CWEID 295
	return res


def lesser_simple_bad_verify_22(url, shouldVerify):
	print("BAD 7")
	sObj = requests.Session()
	res = sObj.delete(url, verify=shouldVerify) # CWEID 295
	return res

def lesser_simple_bad_verify_25(url, shouldVerify):
	print("BAD 7")
	sObj = requests.Session()
	res = sObj.patch(url, None, verify=shouldVerify) # CWEID 295
	return res

def lesser_simple_bad_verify_00(url, shouldVerify):
	print("BAD 7")
	sObj = requests.session()
	res = sObj.request('GET', url, verify=shouldVerify) # CWEID 295
	return res

def lesser_simple_bad_verify_07(url, shouldVerify):
	print("BAD 7")
	sObj = requests.session()
	res = sObj.get(url, verify=shouldVerify) # CWEID 295
	return res

def lesser_simple_bad_verify_23(url, shouldVerify):
	print("BAD 7")
	sObj = requests.session()
	res = sObj.options(url, verify=shouldVerify) # CWEID 295
	return res
	
def lesser_simple_bad_verify_04(url, shouldVerify):
	print("BAD 7")
	sObj = requests.session()
	res = sObj.post(url, None, None, verify=shouldVerify) # CWEID 295
	return res

def lesser_simple_bad_verify_24(url, shouldVerify):
	print("BAD 7")
	sObj = requests.session()
	res = sObj.put(url, None, verify=shouldVerify) # CWEID 295
	return res

def lesser_simple_bad_verify_11(url, shouldVerify):
	print("BAD 7")
	sObj = requests.session()
	res = sObj.head(url, verify=shouldVerify) # CWEID 295
	return res

def lesser_simple_bad_verify_22(url, shouldVerify):
	print("BAD 7")
	sObj = requests.session()
	res = sObj.patch(url, verify=shouldVerify) # CWEID 295
	return res

def lesser_simple_bad_verify_15(url, shouldVerify):
	print("BAD 7")
	sObj = requests.session()
	res = sObj.delete(url, verify=shouldVerify) # CWEID 295
	return res


	
def lesser_simple_bad_verify_16(url, shouldVerify):
	print("BAD 7")
	sObj = requests.sessions.session()
	res = sObj.request('GET', url, verify=shouldVerify) # CWEID 295
	return res

def lesser_simple_bad_verify_09(url, shouldVerify):
	print("BAD 7")
	sObj = requests.sessions.session()
	res = sObj.get(url, verify=shouldVerify) # CWEID 295
	return res

def lesser_simple_bad_verify_13(url, shouldVerify):
	print("BAD 7")
	sObj = requests.sessions.session()
	res = sObj.put(url, None, verify=shouldVerify) # CWEID 295
	return res

def lesser_simple_bad_verify_26(url, shouldVerify):
	print("BAD 7")
	sObj = requests.sessions.session()
	res = sObj.post(url, None, None, verify=shouldVerify) # CWEID 295
	return res

def lesser_simple_bad_verify_25(url, shouldVerify):
	print("BAD 7")
	sObj = requests.sessions.session()
	res = sObj.patch(url, None, verify=shouldVerify) # CWEID 295
	return res

def lesser_simple_bad_verify_02(url, shouldVerify):
	print(">>>BAD 7")
	sObj = requests.sessions.session()
	res = sObj.options(url, verify=shouldVerify) # CWEID 295
	return res

def lesser_simple_bad_verify_19(url, shouldVerify):
	print("BAD 7")
	sObj = requests.sessions.session()
	res = sObj.head(url, verify=shouldVerify)
	return res

def lesser_simple_bad_verify_27(url, shouldVerify):
	print("BAD 7")
	sObj = requests.sessions.session()
	res = sObj.delete(url, verify=shouldVerify)
	return res

def lesser_simple_bad_verify_26(url, shouldVerify):
	print("BAD 7")
	sObj = requests.sessions.Session()
	res = sObj.request('GET', url, verify=shouldVerify) # CWEID 295
	return res
	
def lesser_simple_bad_verify_03(url, shouldVerify):
	print("BAD 7")
	sObj = requests.sessions.Session()
	res = sObj.head(url, verify=shouldVerify) # CWEID 295
	return res

def lesser_simple_bad_verify_17(url, shouldVerify):
	print("BAD 7")
	sObj = requests.sessions.Session()
	res = sObj.get(url, verify=shouldVerify) # CWEID 295
	return res

def lesser_simple_bad_verify_06(url, shouldVerify):
	print("BAD 7")
	sObj = requests.sessions.Session()
	res = sObj.patch(url, None, verify=shouldVerify) # CWEID 295
	return res

def lesser_simple_bad_verify_10(url, shouldVerify):
	print("BAD 7")
	sObj = requests.sessions.Session()
	res = sObj.options(url, verify=shouldVerify) # CWEID 295
	return res

def lesser_simple_bad_verify_14(url, shouldVerify):
	print("BAD 7")
	sObj = requests.sessions.Session()
	res = sObj.put(url, None, verify=shouldVerify) # CWEID 295
	return res


def lesser_simple_bad_verify_20(url, shouldVerify):
	print("BAD 7")
	sObj = requests.sessions.Session()
	res = sObj.post(url, None, None, verify=shouldVerify) # CWEID 295
	return res

#-----------------#
def lesser_simple_ok_verify_00(url, shouldVerify):
	print("OK 7")
	sObj = requests.session()
	res = sObj.request('GET', url, verify=shouldVerify)
	return res

def lesser_simple_ok_verify_01(url, shouldVerify):
	print("OK 7")
	sObj = requests.Session()
	res = sObj.get(url, verify=shouldVerify)
	return res

def lesser_simple_ok_verify_02(url, shouldVerify):
	print("OK 7")
	sObj = requests.sessions.session()
	res = sObj.options(url, verify=shouldVerify) 
	return res
	
def lesser_simple_ok_verify_03(url, shouldVerify):
	print("OK 7")
	sObj = requests.sessions.Session()
	res = sObj.head(url, verify=shouldVerify)
	return res

def lesser_simple_ok_verify_04(url, shouldVerify):
	print("OK 7")
	sObj = requests.session()
	res = sObj.post(url, None, None, verify=shouldVerify)
	return res

def lesser_simple_ok_verify_05(url, shouldVerify):
	print("OK 7")
	sObj = requests.Session()
	res = sObj.put(url, None, verify=shouldVerify)
	return res

def lesser_simple_ok_verify_06(url, shouldVerify):
	print("OK 7")
	sObj = requests.sessions.Session()
	res = sObj.patch(url, None, verify=shouldVerify)
	return res

def lesser_simple_ok_verify_07(url, shouldVerify):
	print("OK 7")
	sObj = requests.session()
	res = sObj.delete(url, verify=shouldVerify)
	return res

def lesser_simple_ok_verify_08(url, shouldVerify):
	print("OK 7")
	sObj = requests.Session()
	res = sObj.request('GET', url, verify=shouldVerify)
	return res

def lesser_simple_ok_verify_09(url, shouldVerify):
	print("OK 7")
	sObj = requests.sessions.session()
	res = sObj.get(url, verify=shouldVerify)
	return res

def lesser_simple_ok_verify_10(url, shouldVerify):
	print("OK 7")
	sObj = requests.sessions.Session()
	res = sObj.options(url, verify=shouldVerify)
	return res

def lesser_simple_ok_verify_11(url, shouldVerify):
	print("OK 7")
	sObj = requests.session()
	res = sObj.head(url, verify=shouldVerify)
	return res

def lesser_simple_ok_verify_12(url, shouldVerify):
	print("OK 7")
	sObj = requests.Session()
	res = sObj.post(url, None, None, verify=shouldVerify)
	return res

def lesser_simple_ok_verify_13(url, shouldVerify):
	print("OK 7")
	sObj = requests.sessions.session()
	res = sObj.put(url, None, verify=shouldVerify)
	return res

def lesser_simple_ok_verify_14(url, shouldVerify):
	print("OK 7")
	sObj = requests.sessions.Session()
	res = sObj.patch(url, None, verify=shouldVerify)
	return res

def lesser_simple_ok_verify_15(url, shouldVerify):
	print("OK 7")
	sObj = requests.session()
	res = sObj.delete(url, verify=shouldVerify)
	return res

def lesser_simple_ok_verify_16(url, shouldVerify):
	print("OK 7")
	sObj = requests.sessions.session()
	res = sObj.request('GET', url, verify=shouldVerify)
	return res

def lesser_simple_ok_verify_17(url, shouldVerify):
	print("OK 7")
	sObj = requests.sessions.Session()
	res = sObj.get(url, verify=shouldVerify)
	return res

def lesser_simple_ok_verify_18(url, shouldVerify):
	print("OK 7")
	sObj = requests.Session()
	res = sObj.options(url, verify=shouldVerify)
	return res

def lesser_simple_ok_verify_19(url, shouldVerify):
	print("OK 7")
	sObj = requests.sessions.session()
	res = sObj.head(url, verify=shouldVerify) 
	return res

def lesser_simple_ok_verify_20(url, shouldVerify):
	print("OK 7")
	sObj = requests.sessions.Session()
	res = sObj.post(url, None, None, verify=shouldVerify) 
	return res


def send_bad_01(url):
	print("BADSEND 7")
	## We turn verification off and use the send() call of Session class
	req = requests.Request('GET', 'https://www.google.com')
	p = req.prepare()
	sObj = requests.sessions.Session()
	sObj.verify = False
	sObj.send(p) # CWEID 295
	return

def send_bad_02(url, shouldVerify):
	print("BADSEND 7")
	## We turn verification off and use the send() call of Session class
	req = requests.Request('GET', 'https://www.google.com')
	prep = req.prepare()
	sObj = requests.sessions.Session()
	sObj.verify = shouldVerify 
	sObj.send(prep) # CWEID 295
	return

def send_bad_03(url):
	print("OKSEND 7")
	## We turn verification off and use the send() call of Session class
	req = requests.Request('GET', 'https://www.google.com')
	prep = req.prepare()
	sObj = requests.sessions.Session()
	sObj.verify = None 
	sObj.send(prep) # CWE 295
	return



def send_ok_02(url):
	print("OKSEND 7")
	## We turn verification off and use the send() call of Session class
	req = requests.Request('GET', 'https://www.google.com')
	prep = req.prepare()
	sObj = requests.sessions.Session()
	sObj.verify = True 
	sObj.send(prep)
	return

def b_simple_ok_verify_00(url):
	print("OKSEND 00")
	sObj = requests.session()
	res = sObj.request('GET', url, verify=None) 
	return res

def b_simple_ok_verify_01(url):
	print("OKSEND 01")
	sObj = requests.session()
	res = sObj.get(url, verify=None) 
	return res
	
def b_simple_ok_verify_02(url):
	print("OKSEND 02")
	sObj = requests.session()
	res = sObj.options(url, verify=None) 
	return res
	
def b_simple_ok_verify_03(url):
	sObj = requests.session()
	res = sObj.head(url, verify=None) 
	return res

def b_simple_ok_verify_04(url):
	sObj = requests.session()
	res = sObj.post(url, None, None, verify=None) 
	return res

def b_simple_ok_verify_05(url):
	sObj = requests.session()
	res = sObj.put(url, None, verify=None) 
	return res

def b_simple_ok_verify_06(url):
	sObj = requests.session()
	res = sObj.patch(url, None, verify=None) 
	return res

def b_simple_ok_verify_07(url):
	sObj = requests.session()
	res = sObj.delete(url, verify=None) 
	return res

def b_simple_ok_verify_08(url):
	print("b_siple ok\n")
	sObj = requests.sessions.session()
	res = sObj.request('GET', url, verify=None) 
	return res

def b_simple_ok_verify_09(url):
	sObj = requests.sessions.session()
	res = sObj.get(url, verify=None) 
	return res

def b_simple_ok_verify_10(url):
	sObj = requests.sessions.session()
	res = sObj.options(url, verify=None) 
	return res

def b_simple_ok_verify_11(url):
	sObj = requests.sessions.session()
	res = sObj.head(url, verify=None)
	return res

def b_simple_ok_verify_12(url):
	sObj = requests.sessions.session()
	res = sObj.post(url, None, None, verify=None)
	return res

def b_simple_ok_verify_13(url):
	sObj = requests.sessions.session()
	res = sObj.put(url, None, verify=None)
	return res

def b_simple_ok_verify_14(url):
	sObj = requests.sessions.session()
	res = sObj.patch(url, None, verify=None)
	return res

def b_simple_ok_verify_15(url):
	sObj = requests.sessions.session()
	res = sObj.delete(url, verify=None)
	return res

def b_simple_ok_verify_16(url):
	sObj = requests.sessions.Session()
	res = sObj.request('GET', url, verify=None)
	return res

def b_simple_ok_verify_17(url):
	sObj = requests.sessions.Session()
	res = sObj.get(url, verify=None)
	return res

def b_simple_ok_verify_18(url):
	sObj = requests.sessions.Session()
	res = sObj.options(url, verify=None)
	return res

def b_simple_ok_verify_19(url):
	sObj = requests.sessions.Session()
	res = sObj.head(url, verify=None)
	return res

def b_simple_ok_verify_20(url):
	sObj = requests.sessions.Session()
	res = sObj.post(url, None, None, verify=None)
	return res

def b_simple_ok_verify_21(url):
	sObj = requests.sessions.Session()
	res = sObj.put(url, None, verify=None)
	return res

def b_simple_ok_verify_22(url):
	sObj = requests.sessions.Session()
	res = sObj.patch(url, None, verify=None)
	return res

def b_simple_ok_verify_23(url):
	sObj = requests.sessions.Session()
	res = sObj.delete(url, verify=None)
	return res

def c_simple_ok_verify_00(url):
	sObj = requests.session()
	res = sObj.request('GET', url, verify=True) 
	return res

def c_simple_ok_verify_01(url):
	sObj = requests.session()
	res = sObj.get(url, verify=True) 
	return res
	
def c_simple_ok_verify_02(url):
	sObj = requests.session()
	res = sObj.options(url, verify=True) 
	return res
	
def c_simple_ok_verify_03(url):
	sObj = requests.session()
	res = sObj.head(url, verify=True) 
	return res

def c_simple_ok_verify_04(url):
	sObj = requests.session()
	res = sObj.post(url, None, None, verify=True) 
	return res

def c_simple_ok_verify_05(url):
	sObj = requests.session()
	res = sObj.put(url, None, verify=True) 
	return res

def c_simple_ok_verify_06(url):
	sObj = requests.session()
	res = sObj.patch(url, None, verify=True) 
	return res

def c_simple_ok_verify_07(url):
	sObj = requests.session()
	res = sObj.delete(url, verify=True) 
	return res

def c_simple_ok_verify_08(url):
	sObj = requests.sessions.session()
	res = sObj.request('GET', url, verify=True) 
	return res

def c_simple_ok_verify_09(url):
	sObj = requests.sessions.session()
	res = sObj.get(url, verify=True) 
	return res

def c_simple_ok_verify_10(url):
	sObj = requests.sessions.session()
	res = sObj.options(url, verify=True) 
	return res

def c_simple_ok_verify_11(url):
	sObj = requests.sessions.session()
	res = sObj.head(url, verify=True)
	return res

def c_simple_ok_verify_12(url):
	sObj = requests.sessions.session()
	res = sObj.post(url, None, None, verify=True)
	return res

def c_simple_ok_verify_13(url):
	sObj = requests.sessions.session()
	res = sObj.put(url, None, verify=True)
	return res

def c_simple_ok_verify_14(url):
	sObj = requests.sessions.session()
	res = sObj.patch(url, None, verify=True)
	return res

def c_simple_ok_verify_15(url):
	sObj = requests.sessions.session()
	res = sObj.delete(url, verify=True)
	return res

def c_simple_ok_verify_16(url):
	sObj = requests.sessions.Session()
	res = sObj.request('GET', url, verify=True)
	return res

def c_simple_ok_verify_17(url):
	sObj = requests.sessions.Session()
	res = sObj.get(url, verify=True)
	return res

def c_simple_ok_verify_18(url):
	sObj = requests.sessions.Session()
	res = sObj.options(url, verify=True)
	return res

def c_simple_ok_verify_19(url):
	sObj = requests.sessions.Session()
	res = sObj.head(url, verify=True)
	return res

def c_simple_ok_verify_20(url):
	sObj = requests.sessions.Session()
	res = sObj.post(url, None, None, verify=True)
	return res

def c_simple_ok_verify_21(url):
	sObj = requests.sessions.Session()
	res = sObj.put(url, None, verify=True)
	return res

def c_simple_ok_verify_22(url):
	sObj = requests.sessions.Session()
	res = sObj.patch(url, None, verify=True)
	return res

def c_simple_ok_verify_23(url):
	sObj = requests.sessions.Session()
	res = sObj.delete(url, verify=True)
	return res

def TEST_00(url):
	print("TEST_00")
	sObj = requests.sessions.Session()
	sObj.verify=False
	res = sObj.delete(url) # CWEID 295
	print("TEST_00 done")
	return res

def TEST_01(url):
	print("TEST_01")
	req = requests.Request('GET', url)
	prep = req.prepare()
	sObj = requests.sessions.Session()
	sObj.verify = False 
	sObj.send(prep, verify=True)
	print("TEST_01 done")
	return

def TEST_02(url):
	print("TEST_02")
	sObj = requests.sessions.Session()
	sObj.verify=False
	res = sObj.delete(url, verify=True) # CWEID 295
	print("TEST_02 done")
	return res

def TEST_03(url):
	print("TEST_03")
	sObj = requests.sessions.Session()
	sObj.verify=False
	res = sObj.delete(url, verify=None) # CWEID 295
	print("TEST_03 done")
	return res

def TEST_04(url):
	print("TEST_04")
	sObj = requests.sessions.Session()
	sObj.verify= True
	res = sObj.delete(url, verify=False) # CWEID 295
	print("TEST_04 done")
	return res

def TEST_05(url):
	print("TEST_05")
	req = requests.Request('GET', 'https://www.google.com')
	prep = req.prepare()
	sObj = requests.sessions.Session()
	sObj.send(prep, verify=False) # CWEID 295
	print("TEST_05 done")
	return

def TEST_06(url):
	print("TEST_06")
	req = requests.Request('GET', 'https://www.google.com')
	prep = req.prepare()
	sObj = requests.sessions.Session()
	sObj.verify = True
	sObj.send(prep, verify=False) # CWEID 295
	print("TEST_06 done")
	return

def TEST_00a(url):
	print("TEST_00")
	sObj = requests.sessions.Session()
	sObj.verify=False
	res = sObj.post(url) # CWEID 295
	print("TEST_00 done")
	return res

def TEST_01a(url):
	print("TEST_01")
	req = requests.Request('GET', url)
	prep = req.prepare()
	sObj = requests.sessions.Session()
	sObj.verify = False 
	sObj.send(prep, verify=True)
	print("TEST_01 done")
	return

def TEST_02a(url):
	print("TEST_02")
	sObj = requests.sessions.Session()
	sObj.verify=False
	res = sObj.put(url, verify=True) # CWEID 295
	print("TEST_02 done")
	return res

def TEST_03a(url):
	print("TEST_03")
	sObj = requests.sessions.Session()
	sObj.verify=False
	res = sObj.post(url, verify=None) # CWEID 295
	print("TEST_03 done")
	return res

def TEST_04a(url):
	print("TEST_04")
	sObj = requests.sessions.Session()
	sObj.verify= True
	res = sObj.put(url, verify=False) # CWEID 295
	print("TEST_04 done")
	return res

def TEST_05a(url):
	print("TEST_05")
	req = requests.Request('GET', 'https://www.google.com')
	prep = req.prepare()
	sObj = requests.sessions.Session()
	sObj.send(prep, verify=False) # CWEID 295
	print("TEST_05 done")
	return

def TEST_06a(url):
	print("TEST_06")
	req = requests.Request('GET', 'https://www.google.com')
	prep = req.prepare()
	sObj = requests.sessions.Session()
	sObj.verify = True
	sObj.send(prep, verify=False) # CWEID 295
	print("TEST_06 done")
	return

def others3(url):

	# All these session objects can be assumed to be from
	# any of the few source of them.
	print("s01 get")
	s01 = requests.sessions.Session()
	s01.post(url)
	print("s01 done")
	print("s02 get")
	s02 = requests.sessions.Session()
	s02.post(url, verify=True)
	print("s02 done")
	print("s03 get")
	s03 = requests.sessions.Session()
	s03.post(url, verify=False) # CWEID 295
	print("s03 done")
	print("s03a get")
	s03a = requests.sessions.Session()
	s03a.post(url, verify=None)
	print("s03a done")
	print("s04 get")
	s04 = requests.sessions.Session()
	s04.verify=True
	s04.post(url)
	print("s04 done")
	print("s05 get")
	s05 = requests.sessions.Session()
	s05.verify=True
	s05.post(url, verify=True)
	print("s05 done")
	print("s06 get")
	s06 = requests.sessions.Session()
	s06.verify=True
	s06.post(url, verify=False) # CWEID 295
	print("s06 done")
	print("s07 get")
	s07 = requests.sessions.Session()
	s07.verify=True
	s07.post(url, verify=None)
	print("s07 done")
	print("s08 get")
	s08 = requests.sessions.Session()
	s08.verify=False
	s08.post(url) # CWEID 295
	print("s08 done")
	print("s09 get")
	s09 = requests.sessions.Session()
	s09.verify=False
	s09.post(url, verify=True) # CWEID 295
	print("s09 done")
	print("s10 get")
	
	s10 = requests.sessions.Session()
	s10.verify=False
	s10.post(url, verify=False) # CWEID 295
	print("s10 done")
	print("s11 get")
	
	s11 = requests.sessions.Session()
	s11.verify=False
	s11.post(url, verify=None) # CWEID 295
	print("s11 done")
	print("s12 get")

	s12 = requests.sessions.Session()
	s12.verify=None
	s12.post(url) # CWEID 295
	print("s12 done")
	print("s13 get")
	s13 = requests.sessions.Session()
	s13.verify=None
	s13.post(url, verify=True) # CWEID 295
	print("s13 done")
	print("s14 get")
	s14 = requests.sessions.Session()
	s14.verify=None
	s14.post(url, verify=False) # CWEID 295
	print("s14 done")
	print("s15 get")
	s15 = requests.sessions.Session()
	s15.verify=None
	s15.post(url, verify=None) # CWEID 295
	print("s15 done")

def others2(url):

	# All these session objects can be assumed to be from
	# any of the few source of them.
	print("s01 get")
	s01 = requests.sessions.Session()
	s01.put(url)
	print("s01 done")
	print("s02 get")
	s02 = requests.sessions.Session()
	s02.put(url, verify=True)
	print("s02 done")
	print("s03 get")
	s03 = requests.sessions.Session()
	s03.put(url, verify=False) # CWEID 295
	print("s03 done")
	print("s03a get")
	s03a = requests.sessions.Session()
	s03a.put(url, verify=None)
	print("s03a done")
	print("s04 get")
	s04 = requests.sessions.Session()
	s04.verify=True
	s04.put(url)
	print("s04 done")
	print("s05 get")
	s05 = requests.sessions.Session()
	s05.verify=True
	s05.put(url, verify=True)
	print("s05 done")
	print("s06 get")
	s06 = requests.sessions.Session()
	s06.verify=True
	s06.put(url, verify=False) # CWEID 295
	print("s06 done")
	print("s07 get")
	s07 = requests.sessions.Session()
	s07.verify=True
	s07.put(url, verify=None)
	print("s07 done")
	print("s08 get")
	s08 = requests.sessions.Session()
	s08.verify=False
	s08.put(url) # CWEID 295
	print("s08 done")
	print("s09 get")
	s09 = requests.sessions.Session()
	s09.verify=False
	s09.put(url, verify=True) # CWEID 295
	print("s09 done")
	print("s10 get")
	
	s10 = requests.sessions.Session()
	s10.verify=False
	s10.put(url, verify=False) # CWEID 295
	print("s10 done")
	print("s11 get")
	
	s11 = requests.sessions.Session()
	s11.verify=False
	s11.put(url, verify=None) # CWEID 295
	print("s11 done")
	print("s12 get")

	s12 = requests.sessions.Session()
	s12.verify=None
	s12.put(url) # CWEID 295
	print("s12 done")
	print("s13 get")
	s13 = requests.sessions.Session()
	s13.verify=None
	s13.put(url, verify=True) # CWEID 295
	print("s13 done")
	print("s14 get")
	s14 = requests.sessions.Session()
	s14.verify=None
	s14.put(url, verify=False) # CWEID 295
	print("s14 done")
	print("s15 get")
	s15 = requests.sessions.Session()
	s15.verify=None
	s15.put(url, verify=None) # CWEID 295
	print("s15 done")

def others(url):

	# All these session objects can be assumed to be from
	# any of the few source of them.
	print("s01 get")
	s01 = requests.sessions.Session()
	s01.get(url)
	print("s01 done")
	print("s02 get")
	s02 = requests.sessions.Session()
	s02.get(url, verify=True)
	print("s02 done")
	print("s03 get")
	s03 = requests.sessions.Session()
	s03.get(url, verify=False) # CWEID 295
	print("s03 done")
	print("s03a get")
	s03a = requests.sessions.Session()
	s03a.get(url, verify=None)
	print("s03a done")
	print("s04 get")
	s04 = requests.sessions.Session()
	s04.verify=True
	s04.get(url)
	print("s04 done")
	print("s05 get")
	s05 = requests.sessions.Session()
	s05.verify=True
	s05.get(url, verify=True)
	print("s05 done")
	print("s06 get")
	s06 = requests.sessions.Session()
	s06.verify=True
	s06.get(url, verify=False) # CWEID 295
	print("s06 done")
	print("s07 get")
	s07 = requests.sessions.Session()
	s07.verify=True
	s07.get(url, verify=None)
	print("s07 done")
	print("s08 get")
	s08 = requests.sessions.Session()
	s08.verify=False
	s08.get(url) # CWEID 295
	print("s08 done")
	print("s09 get")
	s09 = requests.sessions.Session()
	s09.verify=False
	s09.get(url, verify=True) # CWEID 295
	print("s09 done")
	print("s10 get")
	
	s10 = requests.sessions.Session()
	s10.verify=False
	s10.get(url, verify=False) # CWEID 295
	print("s10 done")
	print("s11 get")
	
	s11 = requests.sessions.Session()
	s11.verify=False
	s11.get(url, verify=None) # CWEID 295
	print("s11 done")
	print("s12 get")

	s12 = requests.sessions.Session()
	s12.verify=None
	s12.get(url) # CWEID 295
	print("s12 done")
	print("s13 get")
	s13 = requests.sessions.Session()
	s13.verify=None
	s13.get(url, verify=True) # CWEID 295
	print("s13 done")
	print("s14 get")
	s14 = requests.sessions.Session()
	s14.verify=None
	s14.get(url, verify=False) # CWEID 295
	print("s14 done")
	print("s15 get")
	s15 = requests.sessions.Session()
	s15.verify=None
	s15.get(url, verify=None) # CWEID 295
	print("s15 done")

def main():
	if len(sys.argv) != 2:
		print("python example.py <url>")
		sys.exit(-1)

	url = sys.argv[1]
	
	others3(url)
	others2(url)
	TEST_00a(url)
	TEST_01a(url)
	TEST_02a(url)
	TEST_03a(url)
	TEST_04a(url)
	TEST_05a(url)
	TEST_06a(url)

	a = requests.session()
	b = requests.sessions.session()
	c = requests.sessions.Session()

	others(url)	
	TEST_00(url)
	TEST_01(url)
	TEST_02(url)
	TEST_03(url)
	TEST_04(url)
	TEST_05(url)
	TEST_06(url)

	# most basic where verify=False
	a_simple_bad_verify_00(url)
	a_simple_bad_verify_01(url)
	a_simple_bad_verify_02(url)
	a_simple_bad_verify_03(url)
	a_simple_bad_verify_04(url)
	a_simple_bad_verify_05(url)
	a_simple_bad_verify_06(url)
	a_simple_bad_verify_07(url)
	a_simple_bad_verify_08(url)
	a_simple_bad_verify_09(url)
	a_simple_bad_verify_10(url)
	a_simple_bad_verify_11(url)
	a_simple_bad_verify_12(url)
	a_simple_bad_verify_13(url)
	a_simple_bad_verify_14(url)
	a_simple_bad_verify_15(url)
	a_simple_bad_verify_16(url)
	a_simple_bad_verify_17(url)
	a_simple_bad_verify_18(url)
	a_simple_bad_verify_19(url)
	a_simple_bad_verify_20(url)
	a_simple_bad_verify_21(url)
	a_simple_bad_verify_22(url)
	a_simple_bad_verify_23(url)

	a_simple_ok_verify_00(url)
	a_simple_ok_verify_01(url)
	a_simple_ok_verify_02(url)
	a_simple_ok_verify_03(url)
	a_simple_ok_verify_04(url)
	a_simple_ok_verify_05(url)
	a_simple_ok_verify_06(url)
	a_simple_ok_verify_07(url)
	a_simple_ok_verify_08(url)
	a_simple_ok_verify_09(url)
	a_simple_ok_verify_10(url)
	a_simple_ok_verify_11(url)
	a_simple_ok_verify_12(url)
	a_simple_ok_verify_13(url)
	a_simple_ok_verify_14(url)
	a_simple_ok_verify_15(url)
	a_simple_ok_verify_16(url)
	a_simple_ok_verify_17(url)
	a_simple_ok_verify_18(url)
	a_simple_ok_verify_19(url)
	a_simple_ok_verify_20(url)
	a_simple_ok_verify_21(url)
	a_simple_ok_verify_22(url)
	a_simple_ok_verify_23(url)
	b_simple_ok_verify_00(url)
	b_simple_ok_verify_01(url)
	b_simple_ok_verify_02(url)
	b_simple_ok_verify_03(url)
	b_simple_ok_verify_04(url)
	b_simple_ok_verify_05(url)
	b_simple_ok_verify_06(url)
	b_simple_ok_verify_07(url)
	b_simple_ok_verify_08(url)
	b_simple_ok_verify_09(url)
	b_simple_ok_verify_10(url)
	b_simple_ok_verify_11(url)
	b_simple_ok_verify_12(url)
	b_simple_ok_verify_13(url)
	b_simple_ok_verify_14(url)
	b_simple_ok_verify_15(url)
	b_simple_ok_verify_16(url)
	b_simple_ok_verify_17(url)
	b_simple_ok_verify_18(url)
	b_simple_ok_verify_19(url)
	b_simple_ok_verify_20(url)
	b_simple_ok_verify_21(url)
	b_simple_ok_verify_22(url)
	b_simple_ok_verify_23(url)

	c_simple_ok_verify_00(url)
	c_simple_ok_verify_01(url)
	c_simple_ok_verify_02(url)
	c_simple_ok_verify_03(url)
	c_simple_ok_verify_04(url)
	c_simple_ok_verify_05(url)
	c_simple_ok_verify_06(url)
	c_simple_ok_verify_07(url)
	c_simple_ok_verify_08(url)
	c_simple_ok_verify_09(url)
	c_simple_ok_verify_10(url)
	c_simple_ok_verify_11(url)
	c_simple_ok_verify_12(url)
	c_simple_ok_verify_13(url)
	c_simple_ok_verify_14(url)
	c_simple_ok_verify_15(url)
	c_simple_ok_verify_16(url)
	c_simple_ok_verify_17(url)
	c_simple_ok_verify_18(url)
	c_simple_ok_verify_19(url)
	c_simple_ok_verify_20(url)
	c_simple_ok_verify_21(url)
	c_simple_ok_verify_22(url)
	c_simple_ok_verify_23(url)

	# Hand over False via a function argument
	# mostly testing to see the py-sc capabilities
	lesser_simple_bad_verify_00(url, False)
	lesser_simple_bad_verify_01(url, False)
	lesser_simple_bad_verify_02(url, False)
	lesser_simple_bad_verify_03(url, False)
	lesser_simple_bad_verify_04(url, False)
	lesser_simple_bad_verify_05(url, False)
	lesser_simple_bad_verify_06(url, False)
	lesser_simple_bad_verify_07(url, False)
	lesser_simple_bad_verify_08(url, False)
	lesser_simple_bad_verify_09(url, False)
	lesser_simple_bad_verify_10(url, False)
	lesser_simple_bad_verify_11(url, False)
	lesser_simple_bad_verify_12(url, False)
	lesser_simple_bad_verify_13(url, False)
	lesser_simple_bad_verify_14(url, False)
	lesser_simple_bad_verify_15(url, False)
	lesser_simple_bad_verify_16(url, False)
	lesser_simple_bad_verify_17(url, False)
	lesser_simple_bad_verify_18(url, False)
	lesser_simple_bad_verify_19(url, False)
	lesser_simple_bad_verify_20(url, False)
	lesser_simple_bad_verify_21(url, False)
	lesser_simple_bad_verify_22(url, False)
	lesser_simple_bad_verify_23(url, False)
	lesser_simple_bad_verify_24(url, False)
	lesser_simple_bad_verify_25(url, False)
	lesser_simple_bad_verify_26(url, False)

	lesser_simple_ok_verify_00(url, True)
	lesser_simple_ok_verify_01(url, True)
	lesser_simple_ok_verify_02(url, True)
	lesser_simple_ok_verify_03(url, True)
	lesser_simple_ok_verify_04(url, True)
	lesser_simple_ok_verify_05(url, True)
	lesser_simple_ok_verify_06(url, True)
	lesser_simple_ok_verify_07(url, True)
	lesser_simple_ok_verify_08(url, True)
	lesser_simple_ok_verify_09(url, True)
	lesser_simple_ok_verify_10(url, True)
	lesser_simple_ok_verify_11(url, True)
	lesser_simple_ok_verify_12(url, True)
	lesser_simple_ok_verify_13(url, True)
	lesser_simple_ok_verify_14(url, True)
	lesser_simple_ok_verify_15(url, True)
	lesser_simple_ok_verify_16(url, True)
	lesser_simple_ok_verify_17(url, True)
	lesser_simple_ok_verify_18(url, True)
	lesser_simple_ok_verify_19(url, True)
	lesser_simple_ok_verify_20(url, True)

	send_bad_01(url)
	send_bad_02(url, False)
	send_bad_03(url)
	send_ok_02(url)

	others(url)
	sys.exit(0)
	


if __name__ == '__main__':
	main()
