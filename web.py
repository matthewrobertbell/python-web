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
import time

import gevent
from gevent import monkey
from gevent import queue
from gevent import pool
monkey.patch_all(thread=False)

from lxml import etree
from functools import partial

class ProxyManager(object):
	def __init__(self,proxy=True,delay=60):
		if isinstance(proxy,list):
			proxies = proxy
		elif proxy == True:
			proxies = open('proxies.txt').read().strip().split('\n')
		elif ':' in proxy:
			proxies = proxy.strip().split('\n')
		else:
			proxies = open(proxy).read().strip().split('\n')
			
		self.records = dict(zip(proxies,[0 for p in proxies]))
		self.delay = delay
		
	def get(self,debug=False):
		while True:
			proxies = [proxy for proxy,proxy_time in self.records.items() if proxy_time + self.delay < time.time()]
			if not proxies:
				gevent.sleep(1)
			else:
				if debug:
					print '%s Proxies available.' % len(proxies)
				proxy = random.sample(proxies,1)[0]
				self.records[proxy] = int(time.time())
				return proxy
		

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
	def __init__(self,proxy=None,cookie_filename=None):
		self.handlers = set()
		try:
			useragents = open('useragents.txt').read().strip().split('\n')
			self.useragent = random.choice(useragents).strip()
		except:
			self.useragent = useragent()
		self.opener = urllib2.OpenerDirector()
		self.cookie_jar = cookielib.LWPCookieJar()
		if cookie_filename:
			self.cookie_jar = cookielib.MozillaCookieJar(cookie_filename)
			self.cookie_jar.load()
		cookie_support = urllib2.HTTPCookieProcessor(self.cookie_jar)
		self.proxy = False
		if proxy:
			if isinstance(proxy,ProxyManager):
				self.proxy = proxy.get()
			else:
				self.proxy = ProxyManager(proxy).get()
		if self.proxy:
			self.proxy = self.proxy.strip()
			parts = self.proxy.split(':')
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

	def urlopen(self,url,post=None,ref='',files=None,username=None,password=None,compress=True,head=False,timeout=20):
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
		if head:
			req = HeadRequest(url,post,headers)
		else:
			req = urllib2.Request(url,post,headers)
		with gevent.Timeout(timeout):
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


		
def grab(url,proxy=None,post=None,ref=None,xpath=False,compress=True,include_url=False,retries=1):
	data = None
	for i in range(retries):
		try:
			data = http(proxy).urlopen(url=url,post=post,ref=ref,compress=compress).read()
			break
		except:
			pass
	if data:
		if xpath:
			data = etree.HTML(data)
		if include_url:
			return (url,data)
		else:
	   		return data
	return False
   	 
def multi_grab(urls,proxy=None,ref=None,xpath=False,compress=True,delay=10,pool_size=50,retries=1):
	if proxy is not None:
		proxy = web.ProxyManager(proxy,delay=delay)
		pool_size = len(pool_size.records)
	work_pool = pool.Pool(pool_size)
	partial_grab = partial(grab,proxy=proxy,post=None,ref=ref,xpath=xpath,compress=compress,include_url=True,retries=retries)
	for result in work_pool.imap_unordered(partial_grab,urls):
		if result:
			yield result

def redirecturl(url,proxy=None):
	return http(proxy).urlopen(url,head=True).geturl()
	
if __name__ == '__main__':
	links = [link for link in grab('http://www.reddit.com',xpath=True).xpath('//a/@href') if link.startswith('http') and 'reddit' not in link]
	print '%s links' % len(links)
	counter = 1
	for url, data in multi_grab(links,pool_size=3):
		print 'got', url, counter, len(data)
		counter += 1
