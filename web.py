import re
import random
import time
import cookielib
import urllib2
import urllib
import mimetypes
import gzip
import StringIO
import urlparse
import collections
import pybloom

import gevent
from gevent import monkey
from gevent import queue
import custompool
monkey.patch_all(thread=False)

from lxml import etree
from functools import partial

from urllib import quote_plus

class UberIterator(object):
	def __init__(self,objects=None):
		self.objects = []
		self.popped_counter = 0
		self.last_object = None
		if objects is not None:
			self.objects += objects
			
	def __iter__(self):
		return self
		
	def __len__(self):
		return len(self.objects)
	
	def next(self):
		if len(self.objects):
			self.popped_counter += 1
			self.last_object = self.objects.pop(0)
			return self.last_object
		else:
			raise StopIteration
			
	def progress(self):
		return int(len(self) / float(len(self) + popped_counter) * 100)
		
	def __add__(self,objects):
		self.objects += objects
		return self


class HTTPResponse(object):
	def __init__(self,response,url):
		self._xpath = None
		self._domain = urlparse.urlparse(url).netloc
		self.headers = response.info()
		compressed_data = response.read()
		if filter(lambda (k,v): k.lower() == 'content-encoding' and v.lower() == 'gzip', self.headers.items()):
			self.headers['Content-type'] = 'text/html; charset=utf-8'
			self._data = gzip.GzipFile(fileobj=StringIO.StringIO(compressed_data)).read()
		else:
			self._data = compressed_data
			
		self._encoded_data = unicode(self._data,'ISO-8859-1').encode('ISO-8859-1')
		
		self.original_url = url
		self.final_url = response.geturl()
		
	def __str__(self):
		return self._data
		
	def __len__(self):
		return len(str(self))
		
	def save(self,handle):
		handle.write(str(self))
		
		
	def xpath(self,expression):
		if not isinstance(expression,basestring):
			expression = '||'.join(expression)
		if '||' in expression:
			results = []
			for part in expression.split('||'):
				results.append(self.xpath(part))
			return zip(*results)
			
		if self._xpath is None:
			self._xpath = etree.HTML(self._encoded_data)
		results = []
		xpath_result = self._xpath.xpath(expression)
		if isinstance(xpath_result,basestring) or not isinstance(xpath_result,collections.Iterable):
			return xpath_result
		for result in xpath_result:
			if (expression.endswith('@href') or expression.endswith('@src')) and not result.startswith('http'):
				result = urlparse.urljoin(self.final_url,result).split('#')[0]
			if isinstance(result,basestring):
				result = result.strip()
			if isinstance(result,basestring):
				if len(result):
					results.append(result)
			else:
				results.append(result)
		return list(results)
				
		
	def single_xpath(self,expression):
		results = self.xpath(expression)
		if isinstance(results,basestring) or not isinstance(results,collections.Iterable):
			return results
		if results:
			return results[0]
		else:
			return ''
			
	def internal_links(self):
		return set([link for link in self.xpath('//a/@href') if urlparse.urlparse(link).netloc == self._domain])
		
	def external_links(self):
		return set([link for link in self.xpath('//a/@href') if urlparse.urlparse(link).netloc != self._domain])
		
	def dofollow_links(self):
		return set(self.xpath('//a[@rel!="nofollow" or not(@rel)]/@href'))
	
	def nofollow_links(self):
		return set(self.xpath('//a[@rel="nofollow"]/@href'))
		
	def external_images(self):
		return set([image for image in self.xpath('//img/@src') if urlparse.urlparse(image).netloc != self._domain])

	def regex(self,expression):
		return re.compile(expression).findall(self._encoded_data)
		
	def __unicode__(self):
		return 'HTTPResponse for %s' % self.final_url
		
	def link_exists(self,link,domain=False):
		if domain:
			link = urlparse.urlparse(link).netloc
		for l,l_obj in self.xpath('//a/@href||//a[@href]'):
			if domain:
				if urlparse.urlparse(l).netloc == link:
					return l_obj
			else:
				if l == link:
					return l_obj
		return False
		

class ProxyManager(object):
	def __init__(self,proxy=True,delay=60):
		if proxy in (None,False):
			proxies = [None]
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
	def __init__(self,proxy=None,cookie_filename=None,cookies=True):
		self.handlers = set()
		try:
			useragents = open('useragents.txt').read().strip().split('\n')
			self.useragent = random.choice(useragents).strip()
		except:
			self.useragent = useragent()
			
		self.opener = urllib2.OpenerDirector()
		
		if cookies:
			self.cookie_jar = cookielib.LWPCookieJar()
			if cookie_filename:
				self.cookie_jar = cookielib.MozillaCookieJar(cookie_filename)
				self.cookie_jar.load()
			cookie_support = urllib2.HTTPCookieProcessor(self.cookie_jar)
		else:
			cookie_support = None
			
		self.proxy = False
		proxy_auth = None
		
		if proxy:
			if isinstance(proxy,ProxyManager):
				self.proxy = proxy.get()
			else:
				self.proxy = ProxyManager(proxy).get()
		if self.proxy:
			self.proxy = self.proxy.strip()
			proxy_support = urllib2.ProxyHandler({'http' : self.proxy,'https':self.proxy})
			if '@' in self.proxy:
				proxy_auth = urllib2.HTTPBasicAuthHandler()
			else:
				proxy_auth = None
		else:
			proxy_support = None
		
		self.build_opener(proxy_support,cookie_support,proxy_auth)
			
	def build_opener(self,*handlers):
		self.handlers |= set([handler for handler in handlers if handler is not None])
		self.opener = urllib2.build_opener(*self.handlers)

	def urlopen(self,url,post=None,ref='',files=None,username=None,password=None,compress=True,head=False,timeout=30):
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
			return HTTPResponse(response,url)
		
def grab(url,proxy=None,post=None,ref=None,compress=True,include_url=False,retries=5,http_obj=None,cookies=False):
	data = None
	for i in range(retries):
		if not http_obj:
			http_obj = http(proxy,cookies=cookies)
		try:
			data = http_obj.urlopen(url=url,post=post,ref=ref,compress=compress)
			break
		except:
			pass
	if data:
		return data
	return False
   	 
def multi_grab(urls,proxy=None,ref=None,compress=True,delay=10,pool_size=10,retries=5,http_obj=None):
	if proxy is not None:
		proxy = web.ProxyManager(proxy,delay=delay)
		pool_size = len(proxy.records)
	work_pool = custompool.Pool(pool_size)
	partial_grab = partial(grab,proxy=proxy,post=None,ref=ref,compress=compress,include_url=True,retries=retries,http_obj=http_obj)
	queue_links = UberIterator(urls)
	try:
		for result in work_pool.imap_unordered(partial_grab,queue_links):
			if result:
				yield result
	except:
		pass
		
def domain_grab(urls,http_obj=None,pool_size=10,retries=5,proxy=None,delay=10,debug=False):
	if isinstance(urls,basestring):
		urls = [urls]
	domains = set([urlparse.urlparse(url).netloc for url in urls])
	queue_links = UberIterator(urls)
	seen_links = pybloom.ScalableBloomFilter(initial_capacity=100, error_rate=0.001, mode=pybloom.ScalableBloomFilter.SMALL_SET_GROWTH)
	seen_links.add([url for url in urls])
	while queue_links:
		new_links = set()
		if debug:
			progress_counter = 0
			progress_total = len(queue_links)
		for page in multi_grab(queue_links,http_obj=http_obj,pool_size=pool_size,retries=retries,proxy=proxy,delay=delay):
			if debug:
				progress_counter += 1
				print 'Got %s, Link %s/%s (%s%%)' % (page.final_url,progress_counter,progress_total,int((float(progress_counter)/progress_total)*100))
			if urlparse.urlparse(page.final_url).netloc in domains:
				yield page
				new_links |= page.internal_links()
		queue_links += list(set([link for link in new_links if link not in seen_links]))
		[seen_links.add(link) for link in new_links]
		if debug:
			print 'Seen Links: %s' %  len(seen_links)
			print 'Bloom Capacity: %s' % seen_links.capacity
			print 'Links in Queue: %s' % len(queue_links)
		

def redirecturl(url,proxy=None):
	return http(proxy).urlopen(url,head=True).geturl()
	
if __name__ == '__main__':
	for page in domain_grab(['http://www.bbc.co.uk/','http://www.reddit.com/','http://www.arstechnica.com/'],debug=True,pool_size=100):
		print page.final_url
