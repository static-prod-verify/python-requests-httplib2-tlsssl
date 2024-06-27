
# Python httplib2 and requests SSL/TLS scans

## httplib2


Based on 0.9.2 and with assumption of Python 2.7.9 or 3.4, falling in line with
the existing Python stdlib ssl support targeting the same versions.

- [GitHub Repo](https://github.com/httplib2/httplib2)
- [ReadTheDocs](https://httplib2.readthedocs.io/en/latest/)



### CWE 295


We want to find **CWEID 295** in the cases where *certificate validation* is *disabled*.
Certificate validation is default enabled and must be disabled to have an issue. For each
of the cases we should look for, there will be a flag set for enable/disable, but ideally
we will flag only when the object is used for connection/request etc.


#### httplib2.Http case


If the following initializer is used with ```disable_ssl_certificate_validation``` set to ```True```
either by the construtor, or setting the property's value after initialization, and then the
object's method ```request()``` is invoked, then we should flag **CWEID 295**
So, the ```disable_ssl_certificate_validation``` value is
default *False*. It is when the developer sets this value to *True* is there a problem.


- httplib2.Http(cache=None, timeout=None, proxy_info=proxy_info_from_environment, ca_certs=None, disable_ssl_certificate_validation=False)

It would look something like:

```
h = httplib2.Http(disable_ssl_certificate_validation=True)
resp2, content2 = h2.request(some_url) # CWEID 295

-- OR...perhaps like --

h = httplib2.Http()
h.disable_ssl_certificate_validation=True
resp2, content2 = h2.request(some_url) # CWEID 295
```


#### httplib2.HTTPSConnectionWithTimeout and httplib2.AppEngineHttpsConnection cases


The following are similar as they use similar super classes. Like the ```Http``` case above, the 
```disable_ssl_certificate_validation``` property is the one of interest. Default it is False.
It is a problem  if it is set to ```True``` and then used to make connections and should flag **CWEID 295**.

- httplib2.HTTPSConnectionWithTimeout(host, port=None, key_file=None, cert_file=None, strict=None, timeout=None, proxy_info=None, ca_certs=None, disable_ssl_certificate_validation=False)
- httplib2.AppEngineHttpsConnection(host, port=None, key_file=None, cert_file=None, strict=None, timeout=None, proxy_info=None, ca_certs=None, disable_ssl_certificate_validation=False)

The flag can be set by either the initializer argument or setting the property directly after initialization.
Similar to the Http case, we would like to flag only upon use of the weakly setup object. We determine
use if they invoke any one of the following methods on the object:

- connect()
- putrequest()
- request()
- send()

To illustrate:

```
disable7 = True
h7 = httplib2.HTTPSConnectionWithTimeout(host, disable_ssl_certificate_validation=disable7)
resp7 = h7.request('GET', url) # CWEID 295

-- OR...perhaps like --

h7 = httplib2.HTTPSConnectionWithTimeout(host)
h7.disable_ssl_certificate_validation = True
resp7 = h7.request('GET', url) # CWEID 295
```

See the test case **httplib2_cert_validation_01** and **httplib2_cert_validation_02**.


### CWE 326


There are two things to look for in 326... in one case, if the developer does not augment the 
global default ciphers to blacklist some weak ones, then we should flag. Further, if the SSL
version specified is weak, then flag.


#### Default Ciphers 



When using this library, one should ensure to set the ```ssl``` default ciphers to blacklist RC4 and 3DES.
If the developer uses the httplib2.HTTPSConnectionWithTimeout, httplib2.Http, or httplib2.AppEngineHttpsConnection
and does not blacklist these, then flag **CWEID 326**. 

To black list them, one should append ":!RC4:!3DES" to the ```ssl._DEFAULT_CIPHERS``` variable in either a 
global setting, or prior to httplib2 use... something like:

```
import httplib2
import ssl
ssl._DEFAULT_CIPHERS += ":!RC4:!3DES"

def main():
	h = httplib2.Http()
	h.request("GET", "https://foo.com")	


OR

import httplib2
import ssl

def main():
	ssl._DEFAULT_CIPHERS += ":!RC4:!3DES"
	h = httplib2.Http()
	h.request("GET", "https://foo.com")	
```

So, if the above is **not** done, we should flag the 326.

We should note that, similar to the existing rules related to set_ciphers() for the python ```ssl``` module,
there could be FP/FN here... so we should be aware and possibly look to improve the scan in the future.

See the test cases **httplib2_weakcrypto_01**, **httplib2_weakcrypto_02**, **httplib2_weakcrypto_03**,
**httplib2_weakcrypto_01_TN**, **httplib2_weakcrypto_02_TN**, **httplib2_weakcrypto_03_TN**


#### SSL version



Similar to the cases for disabling of certificate validation, there is another flag that will allow a
developer to specify the SSL/TLS version to use. Like the validation flag, this can be set by initializer for
Http, HTTPSConnectionWithTimeout, and AppEngineHttpsConnection classes or directly by setting the property
```ssl_version```.  If the developer specifies one of the following versions and then uses the object, then
we should flag **CWEID 326**:

- ssl.PROTOCOL_SSLv2
- ssl.PROTOCOL_SSLv3
- ssl.PROTOCOL_TLSv1
- ssl.PROTOCOL_TLSv1_1

If they set no value or specify another value such as:

- ssl.PROTOCOL_TLS
- ssl.PROTOCOL_SSLv23
- ssl.PROTOCOL_TLSv1_2
- ...no v1_3 is available and is forced by other options we don't have available in this class

then do **not** flag.

See testcase **httplib2_weakcrypto_04** for examples.


## Requests

[requests documentation](http://docs.python-requests.org/en/master/)


### Versioning

We officially support 2.x and the current latest version (as of April 2, 2019)
is 2.21.0. The research will be based on 2.21.0 down to 2.11 (August 2016)

- < 2.20.0 CVE-2018-18074 (CWE-255?)
- >= 2.20.0 no longer supports python 2.6
- 2.5.2:   Disable the built-in hostname verification.
    ([shazow/urllib3\#526](https://github.com/shazow/urllib3/pull/526))
- < 2.5.2  has RC4: -   Drop RC4 from the default cipher list.
    ([shazow/urllib3\#551](https://github.com/shazow/urllib3/pull/551))
- 2.4.1 adds requests[security] ?? What is that?


- As of 0.9.0 (way older than we care for) has 'verify ssl is default'.

The latest is using urllib3 1.21, however, we will assume >= 1.17 (released in
2016).

### Common to requests

Much of the code in requests are part of different sub-modules but then
they import those features as use-simplification. For example, the
methods in requests/api.py are accessible via requests.api.<function, class, etc>
But due to the requests module __init__.py, most functions and classes
are available just off the root of the module namespace. That is:


- requests.api.get() --> requests.get()
- requests.sessions.Session() --> requests.Session()
- requests.sessions.session() returns a Session



### CWE 295

In the following functions, the optional ```verify``` argument indicates 
whether certificate validation will occur. By default, verify is None and
validation happens. If verify=True, then this validation occurs as well. 
 But
if we see verify=False, then we should flag **CWEID 295** as they are
turning off cert validation. Note that in all of the below, *verify*
can be a boolean or a string. We only wish to flag on the case of =False!.

The .api namespace functions of interest are also imported by the ```__init__.py```
file so requests.api.FUNCTION() is often seen as requests.FUNCTION(). I list
them separately below as I am uncertain of how well we resolve those types
of things.

- requests.api.request(method, url, **kwargs)
- requests.api.get(url, Params, **kwargs)
- requests.api.options(url, **kwargs)
- requests.api.head(url, **kwargs)
- requests.api.post(url, data=None, json=None, **kwargs)
- requests.api.put(url, data=None, **kwargs)
- requests.api.patch(url, data=None, **kwargs) 
- requests.api.delete(url, **kwargs)
- requests.request(method, url, **kwargs)
- requests.get(url, Params, **kwargs)
- requests.options(url, **kwargs)
- requests.head(url, **kwargs)
- requests.post(url, data=None, json=None, **kwargs)
- requests.put(url, data=None, **kwargs)
- requests.patch(url, data=None, **kwargs) 
- requests.delete(url, **kwargs)

So, if we see something like:

```
  requests.api.head("https://www.cnn.com", verify=False)
```

Then we would want to flag that as **295**. For examples of these, see the **improper_cert_validation01**
test case for TN and TP.



**S**imilarly, the ```requests.sessions``` code provides the Session and SessionRedirectMixin
classes. These have similar instance methods to the above. We only model Session and not it's
super class SessionRedirectMixin.
So, the Session class may be accessed by requests.sessions.Session and requests.Session because of the importing
in ```__init__.py```. Further, note that the requests.sessions.session() (thus
requests.session()) returns a Session() object. Also, one can do requests.Session(), as well.

Like the above, there is the *verify* option that is default enabled, but can be disabled, causing a **CWE 295**.
However, given that this is a *class*, there are a few ways to do this..some of which take precedence over
others. I describe them below. Note that we should try to flag only on *use* of the object to connect/send request.

Once one has a Session object, they may use it in a few ways to send HTTP requests. They are the following:

- sessionObj.request(method, url, params=None, data=None, headers=None, cookies=None, files=None, auth=None, timeout=None, allow_redirects=True, proxies=None, hooks=None, stream=None, verify=None, cert=None, json=None)
- sessionObj.get(url, **kwargs)
- sessionObj.options(url, **kwargs)
- sessionObj.head(url, **kwargs)
- sessionObj.post(url, data=None, json=None, **kwargs)
- sessionObj.put(url, data=None, **kwargs)
- sessionObj.patch(url, data=None, **kwargs)
- sessionObj.delete(url, **kwargs)
- sessionObj.send(request, **kwargs)


Just to note, the request() method requires a method as the first argument, e.g. "GET", and send() requires that
the *request* argument is a Request object, in addition to the URL and possible payload.

One may disable the default-enabled cert verification by:

- Setting value on the session object: ```sessionObj.verify = False``` or
- Setting the value via instance method: ```sessionObj.<requestmethod>(..., verify=False, ...)```

The following is a table that represents the rules

```

Session object verify setting | Session obj instance method setting | issue?
-----------------------------------------------------------------------------
 default setting (no toggle)  | default setting                     | Safe
 default " "                  | verify=True                         | Safe
 default " "                  | verify=False                        | CWE 295
 default " "                  | verify=None                         | Safe
 True                         | default setting                     | Safe
 True                         | verify=True                         | Safe
 True                         | verify=False                        | CWE 295
 True                         | verify=None                         | Safe
 False                        | default setting                     | CWE 295
 False                        | verify=True                         | CWE 295 except for send() which is Safe in this case
 False                        | verify=False                        | CWE 295
 False                        | verify=None                         | CWE 295
 None                         | default setting                     | CWE 295
 None                         | verify=True                         | CWE 295
 None                         | verify=False                        | CWE 295
 None                         | verify=None                         | CWE 295


Each row is a rule with the rightmost column indicating whether the rule, if matched,
would result in a CWE 295 or not. The first two columns are logically AND’d to
determine the 3rd column. So, row 1 reads as “IF the Session object verify field is
the default value AND the Session object instance-method uses default verify, THEN the
usage is Safe” (i.e., no CWE). While the second to last row would read “IF the Session
object has the verify field set to None AND the Session object instance-method passes
in verify=False, THEN flag for CWE 295”.  For example look at the following code:

   sObj = requests.session()
   res = sObj.request('GET', url, verify=False) # CWEID 295

This would match rule 3 because we do not see 'sObj.verify = ...', so it is the default.
And the sObj request instance-method passes in verify=False.


```

See the test case **improper_cert_validation02** for the Session object sink cases for *CWEID 295*.
In particular, perhaps checkout the others() method of that test case which should map to the 
table above.


### CWE 326

#### urllib3 default ciphers and older requests

The *requests* module uses the [urllib3](https://urllib3.readthedocs.io/en/latest/) module to
implement it's querying. The default cipher lists are found in the *urllib3* code (see 
src/urllib3/util/ssl_.py around line 97 for the list). It seems that the *urllib3* code does
call the set_ciphers() with that value (or, optionally for some fn's, an argument passed in), so we should
be able to rely on what the default ciphers are as listed in ssl_.py (or custom ones we see
added in).

Since *requests* version 2.12.0, the urllib3 used has a good cipher list is for a SSL client.
However, prior to  that version, so <= 2.11.1, had various urllib3 versions with bad ciphers
in the default list. If the package uploaded has a requirements.txt, then we could get the
requests version range (or exact version). Otherwise, we should assume the worst and that the
code shipped to us is using <= 2.11.1. 

**If** the *requirements.txt* exists and it either (a) does not have requests listed despite the app using it, or (b) has
requests listed and it's version range allows for <= 2.11.1, then we scan and show any findings
to the user.

**If** the *requirements.txt* exists and it has *requests* listed and it's version range is 
equivalent to >= 2.12.0, then we should disable the scan or suppress the result.

**If** the *requirements.txt* does not exist and the app uses *requests*, then we should 
use the following scan and show any findings to the user.

The scan is as follows:

- Flag if we **do not** see the appending of the string ```":!RC4:!3DES"``` to the string variable
```requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS``` prior to using the requests library query
routines. Ideally, they can do this globally as the following:

```
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ":!RC4:!3DES"
```

And if we do not see this, then flag **CWEID 326**. The messaging should be slightly more 
subtle stating that if they are using requests version >= 2.12, then they can ignore this
message, but that if they wish to encourage non-use of RC4 and 3DES, then keep it in.

**NOTE ABOUT FP** (for ASC/OPS): setting the `DEFAULT_CIPHERS` value in one function prior to 
using `requests` API in another function that results in 326. The setting of 
DEFAULT_CIPHERS in another function won't be taken into context by the scanner
and so may result in 326. Ideally the customer sets it globally, but if they must
do it inside a function, then it is reasonable to mitigate the resulting FPs.

Realize that the scan also applies to Session object function calls, like send(), request(), get(), etc.
However, in the section below, it is mentioned about another means of setting ciphers.

Note the entry about setting this here: [https://stackoverflow.com/questions/40373115/how-to-select-specific-the-cipher-while-sending-request-via-python-request-modul](https://stackoverflow.com/questions/40373115/how-to-select-specific-the-cipher-while-sending-request-via-python-request-modul)


#### Transport Adapters: ciphers

The *requests* module for many people is used just with the requests.get()-like functions or 
with using the Session class. However, one is able to have a bit more control over the
options / configs if they use extend and make their own Transport Adapter class. They will
use this class by getting a Session object and invoking the ```mount()``` function that
will have a URL as argument 1 and an instance of the Transport Adapter as the second argument.
This will associate that adapter to any time that Session object queries a URL with the base of it
matching the URL of argument 1. So something like:

```
class MyAdapter(HTTPAdapter):
  def init_poolmanager(self, *args, **kwargs):
    ...

s = requests.Session()
s.mount('https://github.com/', MyAdapter())
r0 = s.get("https://github.com/index.html")  # Does use MyAdapter!
r1 = s.get("https://www.cnn.com") # Does *NOT* use MyAdapter!
```

In the above, there is the allusion to a sub-classed adapter and the use of it. If the s.get()
line was to another URL than one starting with that of the 1st argument of mount() (e.g. "https://www.cnn.com"),
then it would use the normal adapter.

**Realize** that we will have similar concerns about default ciphers here that we had in the prior section. But
I should explain about another way to set these ciphers, specific to a Transport Adapter (TA), and then we
can realize how that fits into the default ciphers scan.

When one subclasses HTTPAdapter, they will typically implement the *init_poolmanager* function.
When they do this, in the init_poolmanager function, they will typically either:

- Set some options and invoke the super-class's init_poolmanager() *_or_*
- Create the urllib3.poolmanager.PoolManager object themself 

Which is done just depends on the developer's use case/style. Further, they will sometimes implement the
*proxy_manager_for* method, in addition to the init_poolmanager().

In the case of calling the super-class's init_poolmanager(), typically what we might see is something like:

```
class MyAdapter(HTTPAdapter):
  def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context()
        kwargs['ssl_context'] = context
        return super(MyAdapter, self).init_poolmanager(*args, **kwargs)
  def proxy_manager_for(self, *args, **kwargs):
        context = create_urllib3_context()
        kwargs['ssl_context'] = context
        return super(MyAdapter, self).proxy_manager_for(*args, **kwargs)
```

This above would use the default cipher set that we have seen in the previous section.  However,
the function *requests.packages.urllib3.util.ssl_.create_urllib3_context()* can be passed the argument
*ciphers* which will then, if not None, determines the ciphers to be used when this adapter is
applied (recall the above where mount() determines application of adapter). A typical case is something
like the following where they set a cipher list with a weak cipher included:

```
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.ssl_ import create_urllib3_context

requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ":!RC4:!3DES"

## Bad, this contains 3DES.. also no !RC4.
CIPHERS = (
    'ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+HIGH:'
    'DH+HIGH:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+HIGH:RSA+3DES:!aNULL:'
    '!eNULL:!MD5'
)

class DESAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context(ciphers=CIPHERS) # CWEID 326
        kwargs['ssl_context'] = context
        return super(DESAdapter, self).init_poolmanager(*args, **kwargs)
  def proxy_manager_for(self, *args, **kwargs):
        context = create_urllib3_context(ciphers=CIPHERS) # CWEID 326
        kwargs['ssl_context'] = context
        return super(MyAdapter, self).proxy_manager_for(*args, **kwargs)

s = requests.Session()
s.mount('https://', DESAdapter())
s.get("https://www.cnn.com")  # <--- risky, but we flag the create_urllib3_context()

requests.get("https://www.cnn.com") # Not at risk because augmented default ciphers and not using
					# the bad adapter
```

For the case of using a PoolManager, one would not set ciphers with that, so more concerned about
the global defaults.

See test cases **ta_inadequate_encryptionstrengthNN** for some examples of these and the PoolManager.


#### Transport Adapters: re-enable SSLv2 and/or v3 or compression

Another **CWEID 326** to look for is the re-enablement of SSLv2, SSLv3, or compression. This is done when
a user-developed Transport Adapter is created and they either enable via PoolManager() or
via the SSLContext returned from *create_urllib3_context()*. We won't assume versions for this
scan, only just look for these being enabled in the code.

For the case in which the developer uses the SSLContxt to set these, they might look like:

```
class MyAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context(ciphers=CIPHERS)
        context.options &= ~ssl.OP_NO_SSLv3 # CWEID 326
        context.options &= ~ssl.OP_NO_SSLv2 # CWEID 326
        context.options &= ~ssl.OP_NO_COMPRESSION # CWEID 326
        kwargs['ssl_context'] = context
        return super(DESAdapter, self).init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        context = create_urllib3_context(ciphers=CIPHERS)
        context.options &= ~ssl.OP_NO_SSLv3 # CWEID 326
        context.options &= ~ssl.OP_NO_SSLv2 # CWEID 326
        context.options &= ~ssl.OP_NO_COMPRESSION # CWEID 326
        kwargs['ssl_context'] = context
        return super(DESAdapter, self).proxy_manager_for(*args, **kwargs)

s = requests.Session()
s.mount('https://some-3des-only-host.com', DESAdapter())
r = s.get('https://some-3des-only-host.com/some-path')
```

So, that is... if we see the SSLContext object having the options re-enabling as above, we will flag **326**. The
options to look for enabling are:

- ssl.OP_NO_SSLv3
- ssl.OP_NO_SSLv2
- ssl.OP_NO_COMPRESSION

Realize, that by default these are disabled... so it's all about re-enabling for the issue to arise.

Alternatively, they can specify the version with the PoolManager() constructor's ssl_version option:

```
class MyAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(
            num_pools=connections, maxsize=maxsize,
            block=block, ssl_version=ssl.PROTOCOL_SSLv2) # CWEID 326
```

So, if we see urllib3.poolmanager.PoolManager construtor called with ssl_version set to one of the following:

- "SSLv2"
- "SSLv3"
- ssl.PROTOCOL_SSLv2
- ssl.PROTOCOL_SSLv3
- ssl.PROTOCOL_TLSv1
- ssl.PROTOCOL_TLSv1_1

Then flag **CWEID 326**

See the test cases in **opt_inadequate_encryption_strengthNN**.

