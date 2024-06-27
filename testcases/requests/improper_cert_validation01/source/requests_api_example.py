
import sys
import requests

#
# These are tests related to the requests.api module.
#
# If any of the below are passed 'verify=<bool>' where <bool> 
# is constant False or a variable with value False, then we
# should flag CWE 295 as this disables certification
# validation. 
#
# requests.api.request(method, url, **kwargs)
# requests.api.get(url, Params, **kwargs)
# requests.api.options(url, **kwargs)
# requests.api.head(url, **kwargs)
# requests.api.post(url, data=None, json=None, **kwargs)
# requests.api.put(url, data=None, **kwargs)
# requests.api.patch(url, data=None, **kwargs)
# requests.api.delete(url, **kwargs)
# requests.request(method, url, **kwargs)
# requests.get(url, Params, **kwargs)
# requests.options(url, **kwargs)
# requests.head(url, **kwargs)
# requests.post(url, data=None, json=None, **kwargs)
# requests.put(url, data=None, **kwargs)
# requests.patch(url, data=None, **kwargs)
# requests.delete(url, **kwargs)
#
#

requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ":!RC4:!3DES"

def simple_bad_verify_00(url):
	res = requests.api.request('GET', url, verify=False) # CWEID 295
	return res

def simple_bad_verify_01(url):
	res = requests.api.get(url, None, verify=False) # CWEID 295
	return res
	
def simple_bad_verify_02(url):
	res = requests.api.options(url, verify=False) # CWEID 295
	return res
	
def simple_bad_verify_03(url):
	res = requests.api.head(url, verify=False) # CWEID 295
	return res

def simple_bad_verify_04(url):
	res = requests.api.post(url, None, None, verify=False) # CWEID 295
	return res

def simple_bad_verify_05(url):
	res = requests.api.put(url, None, verify=False) # CWEID 295
	return res

def simple_bad_verify_06(url):
	res = requests.api.patch(url, None, verify=False) # CWEID 295
	return res

def simple_bad_verify_07(url):
	res = requests.api.delete(url, verify=False) # CWEID 295
	return res

def simple_bad_verify_08(url):
	res = requests.request('GET', url, verify=False) # CWEID 295
	return res

def simple_bad_verify_09(url):
	res = requests.get(url, None, verify=False) # CWEID 295
	return res

def simple_bad_verify_10(url):
	res = requests.options(url, verify=False) # CWEID 295
	return res

def simple_bad_verify_11(url):
	res = requests.head(url, verify=False) # CWEID 295
	return res

def simple_bad_verify_12(url):
	res = requests.post(url, None, None, verify=False) # CWEID 295
	return res

def simple_bad_verify_13(url):
	res = requests.put(url, None, verify=False) # CWEID 295
	return res

def simple_bad_verify_14(url):
	res = requests.patch(url, None, verify=False) # CWEID 295
	return res

def simple_bad_verify_15(url):
	res = requests.delete(url, verify=False) # CWEID 295
	return res

def simpleVARYARG_bad_verify_00(url):
	res = requests.api.request('GET', url, allow_redirects=False, verify=False) # CWEID 295
	return res

def simpleVARYARG_bad_verify_01(url):
	res = requests.api.get(url, None, allow_redirects=False,verify=False) # CWEID 295
	return res
	
def simpleVARYARG_bad_verify_02(url):
	res = requests.api.options(url, allow_redirects=False,verify=False) # CWEID 295
	return res
	
def simpleVARYARG_bad_verify_03(url):
	res = requests.api.head(url, allow_redirects=False,verify=False) # CWEID 295
	return res

def simpleVARYARG_bad_verify_04(url):
	res = requests.api.post(url, None, None,allow_redirects=False, verify=False) # CWEID 295
	return res

def simpleVARYARG_bad_verify_05(url):
	res = requests.api.put(url, None,allow_redirects=False, verify=False) # CWEID 295
	return res

def simpleVARYARG_bad_verify_06(url):
	res = requests.api.patch(url, None,allow_redirects=False, verify=False) # CWEID 295
	return res

def simpleVARYARG_bad_verify_07(url):
	res = requests.api.delete(url,allow_redirects=False, verify=False) # CWEID 295
	return res

def simpleVARYARG_bad_verify_08(url):
	res = requests.request('GET', url,allow_redirects=False, verify=False) # CWEID 295
	return res

def simpleVARYARG_bad_verify_09(url):
	res = requests.get(url, None,allow_redirects=False, verify=False) # CWEID 295
	return res

def simpleVARYARG_bad_verify_10(url):
	res = requests.options(url,allow_redirects=False, verify=False) # CWEID 295
	return res

def simpleVARYARG_bad_verify_11(url):
	res = requests.head(url,allow_redirects=False, verify=False) # CWEID 295
	return res

def simpleVARYARG_bad_verify_12(url):
	res = requests.post(url, None, None,allow_redirects=False, verify=False) # CWEID 295
	return res

def simpleVARYARG_bad_verify_13(url):
	res = requests.put(url, None, allow_redirects=False,verify=False) # CWEID 295
	return res

def simpleVARYARG_bad_verify_14(url):
	res = requests.patch(url, None,allow_redirects=False, verify=False) # CWEID 295
	return res

def simpleVARYARG_bad_verify_15(url):
	res = requests.delete(url,allow_redirects=False, verify=False) # CWEID 295
	return res


#
# Have a boolean variable set to False
#
def less_simple_bad_verify_00(url):
	shouldVerify = False
	res = requests.api.request('GET', url, verify=shouldVerify) # CWEID 295
	return res

def less_simple_bad_verify_01(url):
	shouldVerify = False
	res = requests.api.get(url, None, verify=shouldVerify) # CWEID 295
	return res
	
def less_simple_bad_verify_02(url):
	shouldVerify = False
	res = requests.api.options(url, verify=shouldVerify) # CWEID 295
	return res
	
def less_simple_bad_verify_03(url):
	shouldVerify = False
	res = requests.api.head(url, verify=shouldVerify) # CWEID 295
	return res

def less_simple_bad_verify_04(url):
	shouldVerify = False
	res = requests.api.post(url, None, None, verify=shouldVerify) # CWEID 295
	return res

def less_simple_bad_verify_05(url):
	shouldVerify = False
	res = requests.api.put(url, None, verify=shouldVerify) # CWEID 295
	return res

def less_simple_bad_verify_06(url):
	shouldVerify = False
	res = requests.api.patch(url, None, verify=shouldVerify) # CWEID 295
	return res

def less_simple_bad_verify_07(url):
	shouldVerify = False
	res = requests.api.delete(url, verify=shouldVerify) # CWEID 295
	return res

def less_simple_bad_verify_08(url):
	shouldVerify = False
	res = requests.request('GET', url, verify=shouldVerify) # CWEID 295
	return res

def less_simple_bad_verify_09(url):
	shouldVerify = False
	res = requests.get(url, None, verify=shouldVerify) # CWEID 295
	return res

def less_simple_bad_verify_10(url):
	shouldVerify = False
	res = requests.options(url, verify=shouldVerify) # CWEID 295
	return res

def less_simple_bad_verify_11(url):
	shouldVerify = False
	res = requests.head(url, verify=shouldVerify) # CWEID 295
	return res

def less_simple_bad_verify_12(url):
	shouldVerify = False
	res = requests.post(url, None, None, verify=shouldVerify) # CWEID 295
	return res

def less_simple_bad_verify_13(url):
	shouldVerify = False
	res = requests.put(url, None, verify=shouldVerify) # CWEID 295
	return res

def less_simple_bad_verify_14(url):
	shouldVerify = False
	res = requests.patch(url, None, verify=shouldVerify) # CWEID 295
	return res

def less_simple_bad_verify_15(url):
	shouldVerify = False
	res = requests.delete(url, verify=shouldVerify) # CWEID 295
	return res

#
# verify passed in as an argument
def lesser_simple_bad_verify_00(url, shouldVerify):
	res = requests.api.request('GET', url, verify=shouldVerify) # CWEID 295
	return res

def lesser_simple_bad_verify_01(url, shouldVerify):
	res = requests.api.get(url, None, verify=shouldVerify) # CWEID 295
	return res
	
def lesser_simple_bad_verify_02(url, shouldVerify):
	res = requests.api.options(url, verify=shouldVerify) # CWEID 295
	return res
	
def lesser_simple_bad_verify_03(url, shouldVerify):
	res = requests.api.head(url, verify=shouldVerify) # CWEID 295
	return res

def lesser_simple_bad_verify_04(url, shouldVerify):
	res = requests.api.post(url, None, None, verify=shouldVerify) # CWEID 295
	return res

def lesser_simple_bad_verify_05(url, shouldVerify):
	res = requests.api.put(url, None, verify=shouldVerify) # CWEID 295
	return res

def lesser_simple_bad_verify_06(url, shouldVerify):
	res = requests.api.patch(url, None, verify=shouldVerify) # CWEID 295
	return res

def lesser_simple_bad_verify_07(url, shouldVerify):
	res = requests.api.delete(url, verify=shouldVerify) # CWEID 295
	return res

def lesser_simple_bad_verify_08(url, shouldVerify):
	res = requests.request('GET', url, verify=shouldVerify) # CWEID 295
	return res

def lesser_simple_bad_verify_09(url, shouldVerify):
	res = requests.get(url, None, verify=shouldVerify) # CWEID 295
	return res

def lesser_simple_bad_verify_10(url, shouldVerify):
	res = requests.options(url, verify=shouldVerify) # CWEID 295
	return res

def lesser_simple_bad_verify_11(url, shouldVerify):
	res = requests.head(url, verify=shouldVerify) # CWEID 295
	return res

def lesser_simple_bad_verify_12(url, shouldVerify):
	res = requests.post(url, None, None, verify=shouldVerify) # CWEID 295
	return res

def lesser_simple_bad_verify_13(url, shouldVerify):
	res = requests.put(url, None, verify=shouldVerify) # CWEID 295
	return res

def lesser_simple_bad_verify_14(url, shouldVerify):
	res = requests.patch(url, None, verify=shouldVerify) # CWEID 295
	return res

def lesser_simple_bad_verify_15(url, shouldVerify):
	res = requests.delete(url, verify=shouldVerify) # CWEID 295
	return res

#
# verify argument comes from argv, flag it because ok.
#
def lesserARGV_simple_bad_verify_00(url, shouldVerify):
	res = requests.api.request('GET', url, verify=shouldVerify) # CWEID 295
	return res

def lesserARGV_simple_bad_verify_01(url, shouldVerify):
	res = requests.api.get(url, None, verify=shouldVerify) # CWEID 295
	return res
	
def lesserARGV_simple_bad_verify_02(url, shouldVerify):
	res = requests.api.options(url, verify=shouldVerify) # CWEID 295
	return res
	
def lesserARGV_simple_bad_verify_03(url, shouldVerify):
	res = requests.api.head(url, verify=shouldVerify) # CWEID 295
	return res

def lesserARGV_simple_bad_verify_04(url, shouldVerify):
	res = requests.api.post(url, None, None, verify=shouldVerify) # CWEID 295
	return res

def lesserARGV_simple_bad_verify_05(url, shouldVerify):
	res = requests.api.put(url, None, verify=shouldVerify) # CWEID 295
	return res

def lesserARGV_simple_bad_verify_06(url, shouldVerify):
	res = requests.api.patch(url, None, verify=shouldVerify) # CWEID 295
	return res

def lesserARGV_simple_bad_verify_07(url, shouldVerify):
	res = requests.api.delete(url, verify=shouldVerify) # CWEID 295
	return res

def lesserARGV_simple_bad_verify_08(url, shouldVerify):
	res = requests.request('GET', url, verify=shouldVerify) # CWEID 295
	return res

def lesserARGV_simple_bad_verify_09(url, shouldVerify):
	res = requests.get(url, None, verify=shouldVerify) # CWEID 295
	return res

def lesserARGV_simple_bad_verify_10(url, shouldVerify):
	res = requests.options(url, verify=shouldVerify) # CWEID 295
	return res

def lesserARGV_simple_bad_verify_11(url, shouldVerify):
	res = requests.head(url, verify=shouldVerify) # CWEID 295
	return res

def lesserARGV_simple_bad_verify_12(url, shouldVerify):
	res = requests.post(url, None, None, verify=shouldVerify) # CWEID 295
	return res

def lesserARGV_simple_bad_verify_13(url, shouldVerify):
	res = requests.put(url, None, verify=shouldVerify) # CWEID 295
	return res

def lesserARGV_simple_bad_verify_14(url, shouldVerify):
	res = requests.patch(url, None, verify=shouldVerify) # CWEID 295
	return res

def lesserARGV_simple_bad_verify_15(url, shouldVerify):
	res = requests.delete(url, verify=shouldVerify) # CWEID 295
	return res

def simple_ok_verify_00(url):
	res = requests.api.request('GET', url)
	return res

def simple_ok_verify_01(url):
	res = requests.api.get(url, None)
	return res
	
def simple_ok_verify_02(url):
	res = requests.api.options(url)
	return res
	
def simple_ok_verify_03(url):
	res = requests.api.head(url)
	return res

def simple_ok_verify_04(url):
	res = requests.api.post(url, None, None)
	return res

def simple_ok_verify_05(url):
	res = requests.api.put(url, None)
	return res

def simple_ok_verify_06(url):
	res = requests.api.patch(url, None)
	return res

def simple_ok_verify_07(url):
	res = requests.api.delete(url)
	return res

def simple_ok_verify_08(url):
	res = requests.request('GET', url)
	return res

def simple_ok_verify_09(url):
	res = requests.get(url, None)
	return res

def simple_ok_verify_10(url):
	res = requests.options(url)
	return res

def simple_ok_verify_11(url):
	res = requests.head(url)
	return res

def simple_ok_verify_12(url):
	res = requests.post(url, None, None)
	return res

def simple_ok_verify_13(url):
	res = requests.put(url, None)
	return res

def simple_ok_verify_14(url):
	res = requests.patch(url, None)
	return res

def simple_ok_verify_15(url):
	res = requests.delete(url)
	return res

#
def simpleARG_ok_verify_00(url):
	res = requests.api.request('GET', url, verify=True)
	return res

def simpleARG_ok_verify_01(url):
	res = requests.api.get(url, None, verify=True)
	return res
	
def simpleARG_ok_verify_02(url):
	res = requests.api.options(url, verify=True)
	return res
	
def simpleARG_ok_verify_03(url):
	res = requests.api.head(url, verify=True)
	return res

def simpleARG_ok_verify_04(url):
	res = requests.api.post(url, None, None, verify=True)
	return res

def simpleARG_ok_verify_05(url):
	res = requests.api.put(url, None, verify=True)
	return res

def simpleARG_ok_verify_06(url):
	res = requests.api.patch(url, None, verify=True)
	return res

def simpleARG_ok_verify_07(url):
	res = requests.api.delete(url, verify=True)
	return res

def simpleARG_ok_verify_08(url, verify=True):
	res = requests.request('GET', url)
	return res

def simpleARG_ok_verify_09(url, verify=True):
	res = requests.get(url, None)
	return res

def simpleARG_ok_verify_10(url):
	res = requests.options(url, verify=True)
	return res

def simpleARG_ok_verify_11(url):
	res = requests.head(url, verify=True)
	return res

def simpleARG_ok_verify_12(url):
	res = requests.post(url, None, None, verify=True)
	return res

def simpleARG_ok_verify_13(url):
	res = requests.put(url, None, verify=True)
	return res

def simpleARG_ok_verify_14(url):
	res = requests.patch(url, None, verify=True)
	return res

def simpleARG_ok_verify_15(url):
	res = requests.delete(url, verify=True)
	return res

def simpleEXARG_ok_verify_00(url, shouldVerify):
	res = requests.api.request('GET', url, verify=shouldVerify)
	return res

def simpleEXARG_ok_verify_01(url, shouldVerify):
	res = requests.api.get(url, None, verify=shouldVerify)
	return res
	
def simpleEXARG_ok_verify_02(url, shouldVerify):
	res = requests.api.options(url, verify=shouldVerify)
	return res
	
def simpleEXARG_ok_verify_03(url, shouldVerify):
	res = requests.api.head(url, verify=shouldVerify)
	return res

def simpleEXARG_ok_verify_04(url, shouldVerify):
	res = requests.api.post(url, None, None, verify=shouldVerify)
	return res

def simpleEXARG_ok_verify_05(url, shouldVerify):
	res = requests.api.put(url, None, verify=shouldVerify)
	return res

def simpleEXARG_ok_verify_06(url, shouldVerify):
	res = requests.api.patch(url, None, verify=shouldVerify)
	return res

def simpleEXARG_ok_verify_07(url, shouldVerify):
	res = requests.api.delete(url, verify=shouldVerify) 
	return res

def simpleEXARG_ok_verify_08(url, shouldVerify):
	res = requests.request('GET', url, verify=shouldVerify)
	return res

def simpleEXARG_ok_verify_09(url, shouldVerify):
	res = requests.get(url, None, verify=shouldVerify)
	return res

def simpleEXARG_ok_verify_10(url, shouldVerify):
	res = requests.options(url, verify=shouldVerify)
	return res

def simpleEXARG_ok_verify_11(url, shouldVerify):
	res = requests.head(url, verify=shouldVerify)
	return res

def simpleEXARG_ok_verify_12(url, shouldVerify):
	res = requests.post(url, None, None, verify=shouldVerify)
	return res

def simpleEXARG_ok_verify_13(url, shouldVerify):
	res = requests.put(url, None, verify=shouldVerify)
	return res

def simpleEXARG_ok_verify_14(url, shouldVerify):
	res = requests.patch(url, None, verify=shouldVerify)
	return res

def simpleEXARG_ok_verify_15(url, shouldVerify):
	res = requests.delete(url, verify=shouldVerify)
	return res

def kwarg_simple_bad_verify_00(url):
	args = { 'verify' : False }
	res = requests.api.request('GET', url, **args) # CWEID 295
	return res

def kwarg_simple_bad_verify_01(url):
	args = { 'verify' : False }
	res = requests.api.get(url, None, **args) # CWEID 295
	return res
	
def kwarg_simple_bad_verify_02(url):
	args = { 'verify' : False }
	res = requests.api.options(url, **args) # CWEID 295
	return res
	
def kwarg_simple_bad_verify_03(url):
	args = { 'verify' : False }
	res = requests.api.head(url, **args) # CWEID 295
	return res

def kwarg_simple_bad_verify_04(url):
	args = { 'verify' : False }
	res = requests.api.post(url, None, None, **args) # CWEID 295
	return res

def kwarg_simple_bad_verify_05(url):
	args = { 'verify' : False }
	res = requests.api.put(url, None, **args) # CWEID 295
	return res

def kwarg_simple_bad_verify_06(url):
	args = { 'verify' : False }
	res = requests.api.patch(url, None, **args) # CWEID 295
	return res

def kwarg_simple_bad_verify_07(url):
	args = { 'verify' : False }
	res = requests.api.delete(url, **args) # CWEID 295
	return res

def kwarg_simple_bad_verify_08(url):
	args = { 'verify' : False }
	res = requests.request('GET', url, **args) # CWEID 295
	return res

def kwarg_simple_bad_verify_09(url):
	args = { 'verify' : False }
	res = requests.get(url, None, **args) # CWEID 295
	return res

def kwarg_simple_bad_verify_10(url):
	args = { 'verify' : False }
	res = requests.options(url, **args) # CWEID 295
	return res

def kwarg_simple_bad_verify_11(url):
	args = { 'verify' : False }
	res = requests.head(url, **args) # CWEID 295
	return res

def kwarg_simple_bad_verify_12(url):
	args = { 'verify' : False }
	res = requests.post(url, None, None, **args) # CWEID 295
	return res

def kwarg_simple_bad_verify_13(url):
	args = { 'verify' : False }
	res = requests.put(url, None, **args) # CWEID 295
	return res

def kwarg_simple_bad_verify_14(url):
	args = { 'verify' : False }
	res = requests.patch(url, None, **args) # CWEID 295
	return res

def kwarg_simple_bad_verify_15(url):
	args = { 'verify' : False }
	res = requests.delete(url, **args) # CWEID 295
	return res

def b_simpleARG_ok_verify_00(url):
	res = requests.api.request('GET', url, verify=None)
	return res

def b_simpleARG_ok_verify_01(url):
	res = requests.api.get(url, None, verify=None)
	return res
	
def b_simpleARG_ok_verify_02(url):
	res = requests.api.options(url, verify=None)
	return res
	
def b_simpleARG_ok_verify_03(url):
	res = requests.api.head(url, verify=None)
	return res

def b_simpleARG_ok_verify_04(url):
	res = requests.api.post(url, None, None, verify=None)
	return res

def b_simpleARG_ok_verify_05(url):
	res = requests.api.put(url, None, verify=None)
	return res

def b_simpleARG_ok_verify_06(url):
	res = requests.api.patch(url, None, verify=None)
	return res

def b_simpleARG_ok_verify_07(url):
	res = requests.api.delete(url, verify=None)
	return res

def b_simpleARG_ok_verify_08(url, verify=None):
	res = requests.request('GET', url)
	return res

def b_simpleARG_ok_verify_09(url, verify=None):
	res = requests.get(url, None)
	return res

def b_simpleARG_ok_verify_10(url):
	res = requests.options(url, verify=None)
	return res

def b_simpleARG_ok_verify_11(url):
	res = requests.head(url, verify=None)
	return res

def b_simpleARG_ok_verify_12(url):
	res = requests.post(url, None, None, verify=None)
	return res

def b_simpleARG_ok_verify_13(url):
	res = requests.put(url, None, verify=None)
	return res

def b_simpleARG_ok_verify_14(url):
	res = requests.patch(url, None, verify=None)
	return res

def b_simpleARG_ok_verify_15(url):
	res = requests.delete(url, verify=None)
	return res

def main():
	if len(sys.argv) != 3:
		print("python example.py <url> <yes|no>")
		print("   yes => verify, no => don't verify")
		sys.exit(-1)

	url = sys.argv[1]

	# most basic where verify=False
	simple_bad_verify_00(url)
	simple_bad_verify_01(url)
	simple_bad_verify_02(url)
	simple_bad_verify_03(url)
	simple_bad_verify_04(url)
	simple_bad_verify_05(url)
	simple_bad_verify_06(url)
	simple_bad_verify_07(url)
	simple_bad_verify_08(url)
	simple_bad_verify_09(url)
	simple_bad_verify_10(url)
	simple_bad_verify_11(url)
	simple_bad_verify_12(url)
	simple_bad_verify_13(url)
	simple_bad_verify_14(url)
	simple_bad_verify_15(url)

	simpleVARYARG_bad_verify_00(url)
	simpleVARYARG_bad_verify_01(url)
	simpleVARYARG_bad_verify_02(url)
	simpleVARYARG_bad_verify_03(url)
	simpleVARYARG_bad_verify_04(url)
	simpleVARYARG_bad_verify_05(url)
	simpleVARYARG_bad_verify_06(url)
	simpleVARYARG_bad_verify_07(url)
	simpleVARYARG_bad_verify_08(url)
	simpleVARYARG_bad_verify_09(url)
	simpleVARYARG_bad_verify_10(url)
	simpleVARYARG_bad_verify_11(url)
	simpleVARYARG_bad_verify_12(url)
	simpleVARYARG_bad_verify_13(url)
	simpleVARYARG_bad_verify_14(url)
	simpleVARYARG_bad_verify_15(url)

	# basic where verify=shouldVerify and
	# shouldVerify = False
	less_simple_bad_verify_00(url)
	less_simple_bad_verify_01(url)
	less_simple_bad_verify_02(url)
	less_simple_bad_verify_03(url)
	less_simple_bad_verify_04(url)
	less_simple_bad_verify_05(url)
	less_simple_bad_verify_06(url)
	less_simple_bad_verify_07(url)
	less_simple_bad_verify_08(url)
	less_simple_bad_verify_09(url)
	less_simple_bad_verify_10(url)
	less_simple_bad_verify_11(url)
	less_simple_bad_verify_12(url)
	less_simple_bad_verify_13(url)
	less_simple_bad_verify_14(url)
	less_simple_bad_verify_15(url)

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


	shouldVerify00 = True
	if sys.argv[2] == 'no':
		shouldVerify00 = False
	lesserARGV_simple_bad_verify_00(url, shouldVerify00)

	shouldVerify01 = True
	if sys.argv[2] == 'no':
		shouldVerify01 = False
	lesserARGV_simple_bad_verify_01(url, shouldVerify01)

	shouldVerify02 = True
	if sys.argv[2] == 'no':
		shouldVerify02 = False
	lesserARGV_simple_bad_verify_02(url, shouldVerify02)

	shouldVerify03 = True
	if sys.argv[2] == 'no':
		shouldVerify03 = False
	lesserARGV_simple_bad_verify_03(url, shouldVerify03)

	shouldVerify04 = True
	if sys.argv[2] == 'no':
		shouldVerify04 = False
	lesserARGV_simple_bad_verify_04(url, shouldVerify04)

	shouldVerify05 = True
	if sys.argv[2] == 'no':
		shouldVerify05 = False
	lesserARGV_simple_bad_verify_05(url, shouldVerify05)

	shouldVerify06 = True
	if sys.argv[2] == 'no':
		shouldVerify06 = False
	lesserARGV_simple_bad_verify_06(url, shouldVerify06)

	shouldVerify07 = True
	if sys.argv[2] == 'no':
		shouldVerify07 = False
	lesserARGV_simple_bad_verify_07(url, shouldVerify07)

	shouldVerify08 = True
	if sys.argv[2] == 'no':
		shouldVerify08 = False
	lesserARGV_simple_bad_verify_08(url, shouldVerify08)

	shouldVerify09 = True
	if sys.argv[2] == 'no':
		shouldVerify09 = False
	lesserARGV_simple_bad_verify_09(url, shouldVerify09)

	shouldVerify10 = True
	if sys.argv[2] == 'no':
		shouldVerify10 = False
	lesserARGV_simple_bad_verify_10(url, shouldVerify10)

	shouldVerify11 = True
	if sys.argv[2] == 'no':
		shouldVerify11 = False
	lesserARGV_simple_bad_verify_11(url, shouldVerify11)

	shouldVerify12 = True
	if sys.argv[2] == 'no':
		shouldVerify12 = False
	lesserARGV_simple_bad_verify_12(url, shouldVerify12)

	shouldVerify13 = True
	if sys.argv[2] == 'no':
		shouldVerify13 = False
	lesserARGV_simple_bad_verify_13(url, shouldVerify13)

	shouldVerify14 = True
	if sys.argv[2] == 'no':
		shouldVerify14 = False
	lesserARGV_simple_bad_verify_14(url, shouldVerify14)

	shouldVerify15 = True
	if sys.argv[2] == 'no':
		shouldVerify15 = False
	lesserARGV_simple_bad_verify_15(url, shouldVerify15)

	simple_ok_verify_00(url)
	simple_ok_verify_01(url)
	simple_ok_verify_02(url)
	simple_ok_verify_03(url)
	simple_ok_verify_04(url)
	simple_ok_verify_05(url)
	simple_ok_verify_06(url)
	simple_ok_verify_07(url)
	simple_ok_verify_08(url)
	simple_ok_verify_09(url)
	simple_ok_verify_10(url)
	simple_ok_verify_11(url)
	simple_ok_verify_12(url)
	simple_ok_verify_13(url)
	simple_ok_verify_14(url)
	simple_ok_verify_15(url)

	simpleARG_ok_verify_00(url)
	simpleARG_ok_verify_01(url)
	simpleARG_ok_verify_02(url)
	simpleARG_ok_verify_03(url)
	simpleARG_ok_verify_04(url)
	simpleARG_ok_verify_05(url)
	simpleARG_ok_verify_06(url)
	simpleARG_ok_verify_07(url)
	simpleARG_ok_verify_08(url)
	simpleARG_ok_verify_09(url)
	simpleARG_ok_verify_10(url)
	simpleARG_ok_verify_11(url)
	simpleARG_ok_verify_12(url)
	simpleARG_ok_verify_13(url)
	simpleARG_ok_verify_14(url)
	simpleARG_ok_verify_15(url)

	b_simpleARG_ok_verify_00(url)
	b_simpleARG_ok_verify_01(url)
	b_simpleARG_ok_verify_02(url)
	b_simpleARG_ok_verify_03(url)
	b_simpleARG_ok_verify_04(url)
	b_simpleARG_ok_verify_05(url)
	b_simpleARG_ok_verify_06(url)
	b_simpleARG_ok_verify_07(url)
	b_simpleARG_ok_verify_08(url)
	b_simpleARG_ok_verify_09(url)
	b_simpleARG_ok_verify_10(url)
	b_simpleARG_ok_verify_11(url)
	b_simpleARG_ok_verify_12(url)
	b_simpleARG_ok_verify_13(url)
	b_simpleARG_ok_verify_14(url)
	b_simpleARG_ok_verify_15(url)
	simpleEXARG_ok_verify_00(url, True)
	simpleEXARG_ok_verify_01(url, True)
	simpleEXARG_ok_verify_02(url, True)
	simpleEXARG_ok_verify_03(url, True)
	simpleEXARG_ok_verify_04(url, True)
	simpleEXARG_ok_verify_05(url, True)
	simpleEXARG_ok_verify_06(url, True)
	simpleEXARG_ok_verify_07(url, True)
	simpleEXARG_ok_verify_08(url, True)
	simpleEXARG_ok_verify_09(url, True)
	simpleEXARG_ok_verify_10(url, True)
	simpleEXARG_ok_verify_11(url, True)
	simpleEXARG_ok_verify_12(url, True)
	simpleEXARG_ok_verify_13(url, True)
	simpleEXARG_ok_verify_14(url, True)
	simpleEXARG_ok_verify_15(url, True)

	kwarg_simple_bad_verify_00(url)
	kwarg_simple_bad_verify_01(url)
	kwarg_simple_bad_verify_02(url)
	kwarg_simple_bad_verify_03(url)
	kwarg_simple_bad_verify_04(url)
	kwarg_simple_bad_verify_05(url)
	kwarg_simple_bad_verify_06(url)
	kwarg_simple_bad_verify_07(url)
	kwarg_simple_bad_verify_08(url)
	kwarg_simple_bad_verify_09(url)
	kwarg_simple_bad_verify_10(url)
	kwarg_simple_bad_verify_11(url)
	kwarg_simple_bad_verify_12(url)
	kwarg_simple_bad_verify_13(url)
	kwarg_simple_bad_verify_14(url)
	kwarg_simple_bad_verify_15(url)
	sys.exit(0)
	


if __name__ == '__main__':
	main()
