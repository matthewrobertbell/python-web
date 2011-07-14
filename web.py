import re
import random
import time
import cookielib
import urllib2
import urllib
import socket
import os
import httplib
import mimetypes
import base64
import os
import imp
import gzip
import StringIO

from lxml import etree

class HeadRequest(urllib2.Request):
	def get_method(self):
		return 'HEAD'

def useragent():
	agents = ('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.6) Gecko/20070725 Firefox/2.0.0.6','Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)','Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)','Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)','Mozilla/5.0 (X11; Arch Linux i686; rv:2.0) Gecko/20110321 Firefox/4.0','Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)','Mozilla/5.0 (Windows NT 6.1; rv:2.0) Gecko/20110319 Firefox/4.0','Mozilla/5.0 (Windows NT 6.1; rv:1.9) Gecko/20100101 Firefox/4.0','Opera/9.20 (Windows NT 6.0; U; en)','Opera/9.00 (Windows NT 5.1; U; en)','Opera/9.64(Windows NT 5.1; U; en) Presto/2.1.1')
	return random.choice(agents)
	
def encode_multipart_formdata(fields, files):
    '''
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be uploaded as files
    Return (content_type, body) ready for httplib.HTTP instance
    '''
    BOUNDARY = '----------ThIs_Is_tHe_bouNdaRY_$'
    CRLF = '\r\n'
    L = []
    for (key, value) in fields:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"' % key)
        L.append('')
        L.append(value)
    for (key, filename, value) in files:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
        L.append('Content-Type: %s' % get_content_type(filename))
        L.append('')
        L.append(value)
    L.append('--' + BOUNDARY + '--')
    L.append('')
    body = CRLF.join(L)
    content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
    return content_type, body

def get_content_type(filename):
	return mimetypes.guess_type(filename)[0] or 'application/octet-stream'
	
class http(object):
	def __init__(self,proxy=None,head=False):
		self.head = head
		self.handlers = set()
		try:
			useragents = open('useragents.txt').read().strip().split('\n')
			self.useragent = text.spin(random.choice(useragents).strip())
		except:
			self.useragent = useragent()
		self.opener = urllib2.OpenerDirector()
		self.cookie_jar = cookielib.LWPCookieJar()
		cookie_support = urllib2.HTTPCookieProcessor(self.cookie_jar)
		self.proxy = False
		try:
			if proxy:
				if isinstance(proxy,list):
					self.proxy = random.choice(proxy)
				elif ':' in proxy:
					self.proxy = random.choice(proxy.strip().split('\n'))
				else:
					proxies = open(proxy).read().strip().split('\n')
					self.proxy = random.choice(proxies)
		except:
			pass
		if self.proxy:
			self.proxy = self.proxy.strip()
			parts = self.proxy.split(':')
			self.proxy_ip = parts[-2]
			proxy_support = urllib2.ProxyHandler({'http' : self.proxy,'https':self.proxy})
			if '@' in self.proxy:
				proxy_auth = urllib2.HTTPBasicAuthHandler()
				self.build_opener(proxy_support,cookie_support,proxy_auth)
			else:
				self.build_opener(proxy_support,cookie_support)	
		else:
			self.build_opener(cookie_support)

			
	def build_opener(self,*handlers):
		self.handlers |= set(handlers)
		self.opener = urllib2.build_opener(*self.handlers)

	def urlopen(self,url,post=None,ref='',files=None,username=None,password=None,compress=True):
		assert url.lower().startswith('http')
		if username and password:
			password_manager = urllib2.HTTPPasswordMgrWithDefaultRealm()
			password_manager.add_password(None,url,username,password)
			password_auth = urllib2.HTTPBasicAuthHandler(password_manager)
			self.build_opener(password_auth)
		urllib2.install_opener(self.opener)
		if compress:
			headers = {'User-Agent' : self.useragent, 'Referer' : ref, 'Accept-encoding' : 'gzip'}
		else:
			headers = {'User-Agent' : self.useragent, 'Referer' : ref}
		if files:
			content_type,post = encode_multipart_formdata(post.items(), files)
			headers['content-type'] = content_type
			headers['content-length'] = str(len(post))
		elif post:
			post = urllib.urlencode(post)
		if self.head:
			req = HeadRequest(url,post,headers)
		else:
			req = urllib2.Request(url,post,headers)
		response = urllib2.urlopen(req)
		response_headers = response.info()
		compressed_data = response.read()
		if filter(lambda (k,v): k.lower() == 'content-encoding' and v.lower() == 'gzip', response_headers.items()):
			response_data = gzip.GzipFile(fileobj=StringIO.StringIO(compressed_data)).read()
			headers['Content-type'] = 'text/html; charset=utf-8'
			response.read_compressed = lambda: compressed_data
			response.read = lambda: response_data
		else:
			response.read_compressed = lambda: compressed_data
			response.read = lambda: compressed_data

		return response


        
def grab(url,proxy=None,post=None,ref=None,xpath=False,compress=True):
	data = http(proxy).urlopen(url,post,ref,compress=compress).read()
	if xpath:
		return etree.HTML(data)
	return data
