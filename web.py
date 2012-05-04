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
import json
import csv
import os
import multiprocessing
import httplib
import copy
import inspect
import Queue
import tempfile
import subprocess
import sys
import functools

import greenlet
import gevent
from gevent import monkey
from gevent import queue
from gevent import select
from gevent import pool
monkey.patch_all(thread=False)

from lxml import etree
import pybloom

from urllib import quote_plus

DBC_USERNAME = None
DBC_PASSWORD = None

EXCLUDED_LINK_EXTENSIONS = ('jpg','gif','jpeg','pdf','doc','docx','ppt','txt', 'png')

def unique_domains_filter(iterable):
	domains = set()
	for i in iterable:
		parsed = urlparse.urlparse(i.strip())
		if parsed.netloc not in domains:
			domains.add(parsed.netloc)
			yield i.strip()


class BloomFilter(object):
	def __init__(self, name=None):
		self.name = name
		self.add_counter = 0
		if self.name and not self.name.endswith('.bloom'):
			self.name += '.bloom'
		try:
			self.bloom = pybloom.ScalableBloomFilter.fromfile(open(self.name, 'rb'))
		except:
			self.bloom = pybloom.ScalableBloomFilter(initial_capacity=100, error_rate=0.001, mode=pybloom.ScalableBloomFilter.SMALL_SET_GROWTH)
		
	def save(self):
		if self.name:
			self.bloom.tofile(open(self.name+'.bloom', 'wb'))

	def __del__(self):
		self.save()

	def add(self, key):
		self.bloom.add(key)
		self.add_counter += 1
		if len(self) / self.add_counter > 10 and self.add_counter > 100:
			self.save()
			self.add_counter = 0

	def __contains__(self, key, autoadd=True):
		result = key in self.bloom
		if autoadd:
			self.add(key)
		return result

	@property
	def count(self):
		return len(self.bloom)

	def __len__(self):
		return len(self.bloom)

class RandomLines(object):
	def __init__(self, input_file, cache_index=True, repetitions=1):
		if isinstance(input_file, basestring):
			self.source_file = open(input_file,'rb')
			self.filename = input_file
		else:
			self.source_file = input_file
			self.filename = input_file.name
		self.index = []
		self.cache_index = cache_index

		if not os.path.isfile(self.filename+'.lineindex'):
			self.index_file()
		else:
			for line_counter, line in enumerate(open(self.filename+'.lineindex')):
				line = line.strip()
				if line_counter == 0:
					if int(line) != os.path.getsize(self.filename):
						self.index_file()
						break
				elif len(line):
					self.index.append(int(line))
		self.index *= repetitions
		self.start_index_len = len(self.index)

	def __iter__(self):
		return self

	def __len__(self):
		return len(self.index)

	def index_file(self):
		bytes_counter = 0
		for line in self.source_file:
			bytes_counter += len(line)
			if len(line.strip()):
				self.index.append(bytes_counter-len(line))
		if self.cache_index:
			open(self.filename+'.lineindex','w').write('\n'.join(str(i) for i in [os.path.getsize(self.filename)] + self.index))		

	def next(self):
		while len(self.index):
			offset = self.index.pop(random.randrange(0, len(self.index)))
			self.source_file.seek(offset, 0)
			return self.source_file.readline().strip()
		raise StopIteration

	def percentage(self):
		if len(self.index) == 0:
			return 100
		else:
			return 100 - int((float(len(self.index)) / self.start_index_len) * 100) #this is buggy

def spin(text_input, unique_choices=False):
	seen_fields = {}
	for _ in range(text_input.count('{')):
		field = re.findall('{([^{}]*)}', text_input)[0]

		if unique_choices:
			if field not in seen_fields:
				seen_fields[field] = field.split('|')
			if len(seen_fields[field]):
				replacement = seen_fields[field].pop(random.randint(0,len(seen_fields[field])))
			else:
				replacement = ''
		else:
			replacement = random.choice(field.split('|'))

		text_input = text_input.replace('{%s}' % field, replacement, 1)
	return text_input

class HTTPResponse(object):
	def __init__(self, response=None, url=None, fake=False, http=None):
		self._xpath = None
		self._json = None
		#self._encoded_data = None #might cache encoded data again in future, for now don't see the point
		if fake:
			self.original_domain = urlparse.urlparse(url).netloc.lower()
			self.original_url = url
			self.final_url = url
			self.final_domain = self.original_domain
			self._data = '<html><body><p>Hello!</p></body></html>'
		else:
			self.headers = response.info()
			compressed_data = response.read()
			if filter(lambda (k,v): k.lower() == 'content-encoding' and v.lower() == 'gzip', self.headers.items()):
				self.headers['Content-type'] = 'text/html; charset=utf-8'
				self._data = gzip.GzipFile(fileobj=StringIO.StringIO(compressed_data)).read()
			else:
				self._data = compressed_data
			
			self.original_domain = urlparse.urlparse(url).netloc.lower()
			self.original_url = url
			self.final_url = response.geturl()
			self.final_domain = urlparse.urlparse(self.final_url).netloc.lower()

		if http:
			self.http = http

	def encoded_data(self):
		return unicode(self._data,'ISO-8859-1').encode('ISO-8859-1')
		
	def __str__(self):
		return self._data
		
	def __len__(self):
		return len(str(self))

	def __contains__(self,x):
		return x.lower() in str(self).lower()
		
	def save(self, handle):
		if isinstance(handle, basestring):
			handle = open(handle, 'w')
		handle.write(str(self))
		handle.close()

	def json(self):
		if not self._json:
			self._json = json.loads(self._data)
		return self._json	
		
	def xpath(self,expression):
		if self._xpath is None:
			with gevent.Timeout(30, False):
				self._xpath = etree.HTML(self.encoded_data())
			if self._xpath is None:
				return []

		if not isinstance(expression,basestring):
			expression = '||'.join(expression)
		if '||' in expression:
			results = []
			for part in expression.split('||'):
				results.append(self.xpath(part))
			return zip(*results)

		results = []
		original_expression = expression
		if expression.endswith('/string()'):
			expression = expression.split('/string()')[0]
		with gevent.Timeout(30, False):	
			xpath_result = self._xpath.xpath(expression)
		if isinstance(xpath_result, basestring) or not isinstance(xpath_result, collections.Iterable):
			return xpath_result
		for result in xpath_result:
			if expression.endswith('@href') or expression.endswith('@src') or expression.endswith('@action'):
				if not result.startswith('http'):
					result = urlparse.urljoin(self.final_url,result)
				result = result.split('#')[0]
			if original_expression.endswith('/string()'):
				result = result.xpath('string()')
			if isinstance(result,basestring) and len(result.strip()):
					results.append(result.strip())
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

	def links(self):
		return {link.split('#')[0] for link in self.xpath('//a/@href')}
			
	def internal_links(self):
		return {link for link in self.links() if urlparse.urlparse(link).netloc.lower() == self.final_domain if not link.split('.')[-1] in EXCLUDED_LINK_EXTENSIONS}
		
	def external_links(self, exclude_subdomains=True):
		if exclude_subdomains:
			return {link for link in self.links() if max(self.final_domain.split('.'), key=len) not in urlparse.urlparse(link).netloc and link.lower().startswith('http') and link.lower().split('.')[-1] not in EXCLUDED_LINK_EXTENSIONS}
		else:
			return {link for link in self.links() if urlparse.urlparse(link).netloc != self.final_domain and link.lower().startswith('http') and link.lower().split('.')[-1] not in EXCLUDED_LINK_EXTENSIONS}
		
	def dofollow_links(self):
		return set(self.xpath('//a[@rel!="nofollow" or not(@rel)]/@href'))
	
	def nofollow_links(self):
		return set(self.xpath('//a[@rel="nofollow"]/@href'))
		
	def external_images(self):
		return set([image for image in self.xpath('//img/@src') if urlparse.urlparse(image).netloc != self._domain])

	def csv(self):
		return csv.reader(self.encoded_data())

	def regex(self,expression):
		if not isinstance(expression,basestring):
			expression = '||'.join(expression)
		if '||' in expression:
			results = []
			for part in expression.split('||'):
				results.append(self.regex(part))
			return zip(*results)
		return re.compile(expression,re.S|re.I).findall(self.encoded_data())

	def url_regex(self,expression):
		if not isinstance(expression,basestring):
			expression = '||'.join(expression)
		if '||' in expression:
			results = []
			for part in expression.split('||'):
				results.append(self.xpath(part))
			return zip(*results)
		return re.compile(expression).findall(self.final_url)
		
	def __repr__(self):
		return '<HTTPResponse for %s>' % self.final_url
		
	def link_with_url(self,link,domain=False):
		if not isinstance(link, basestring):
			for l in links:
				result = self.link_with_url(l, domain=domain)
				if result is not False:
					return result
		if domain:
			link = urlparse.urlparse(link).netloc
		for l, l_obj in self.xpath('//a/@href||//a[@href]'):
			if domain:
				if urlparse.urlparse(l).netloc == link:
					return l_obj
			else:
				if link in (l,l+'/',l.rstrip('/')):
					return l_obj
		return False

	def link_with_anchor(self,anchor):
		if not isinstance(anchor, basestring):
			for a in anchor:
				result = self.link_with_anchor(a, domain=domain)
				if result is not False:
					return result
		results = self.xpath('//a[text()="%s"]' % anchor)
		if len(results):
			return results[0]
		return False

	def image_captcha(self,xpath):
		try:
			from captcha import DBC_USERNAME, DBC_PASSWORD
		except:
			pass
		image_source = self.single_xpath(xpath)
		if image_source:
			image = grab(image_source, http_obj=self.http)
			import deathbycaptcha
			result = deathbycaptcha.HttpClient(DBC_USERNAME, DBC_PASSWORD).decode(StringIO.StringIO(str(image)))
			if result:
				return result['text']

	def recaptcha(self):
		iframe_source = self.single_xpath('//iframe[contains(@src,"recaptcha")]/@src')
		if iframe_source:
			iframe = grab(iframe_source,http_obj=self.http,ref=self.final_url)
			return (iframe.single_xpath('//input[@id="recaptcha_challenge_field"]/@value'),iframe.image_captcha('//center/img/@src'))

	def solvemedia(self):
		iframe_source = self.single_xpath('//iframe[contains(@src, "api.solvemedia.com")]/@src')
		if iframe_source:
			iframe = grab(iframe_source,http_obj=self.http,ref=self.final_url)
			response = iframe.image_captcha('//img[@id="adcopy-puzzle-image"]/@src')

			post = iframe.hidden_fields()
			post['adcopy_response'] = response

			submit_iframe = grab('http://api.solvemedia.com/papi/verify.noscript', http_obj=self.http, ref=iframe_source, post=post)

			if submit_iframe:
				if len(submit_iframe.regex('c=(.+?)"')):
					return (response, submit_iframe.regex('c=(.+?)"')[0])
				else:
					return ('', '')
			else:
				return ('', '')

	def hidden_fields(self):
		fields = {}
		for name, value in self.xpath('//input[@type="hidden"]/@name||//input[@type="hidden"]/@value'):
			fields[name] = value
		return fields

	def view(self):
		p = tempfile.mktemp() + '.html'
		self.save(p)
		if sys.platform == 'darwin':      subprocess.call(('open', p))
		elif sys.platform == 'nt':     os.startfile(p) #duno lol
		elif sys.platform.startswith('linux'):  subprocess.call(('xdg-open', p))

class ProxyManager(object):
	def __init__(self, proxy=True, min_delay=20, max_delay=None):
		if isinstance(proxy,list):
			proxies = proxy
		elif proxy == True:
			try:
				proxies = open('proxies.txt').read().strip().split('\n')
			except:
				proxies = [None]
		elif isinstance(proxy, basestring):
			if proxy.startswith('http'):
				proxies = [p.strip() for p in str(grab(proxy)).split('\n') if len(p.strip())]
			elif os.path.isfile(proxy):
				proxies = [p.strip() for p in open(proxy) if len(p.strip())]
			elif ':' in proxy:
				proxies = proxy.strip().split('\n')
			new_proxies = []
			for proxy in proxies:
				if proxy.count(':') == 3:
					ip, port, username, password = proxy.split(':')
					proxy = username+':'+password+'@'+ip+':'+port
				new_proxies.append(proxy)
			proxies = new_proxies
		else:
			proxies = [None]
			
		self.records = dict(zip(proxies,[0 for p in proxies]))
		self.min_delay = min_delay
		self.max_delay = max_delay or min_delay
		
	def get(self,debug=False):
		while True:
			proxies = [proxy for proxy,proxy_time in self.records.items() if proxy_time + random.randint(self.min_delay, self.max_delay) < time.time()]
			if not proxies:
				gevent.sleep(0.1)
			else:
				if debug:
					print '%s Proxies available.' % len(proxies)
				proxy = random.sample(proxies, 1)[0]
				self.records[proxy] = int(time.time())
				return proxy

	def __len__(self):
		return len(self.records)

	def split(self, number):
		chunk_size = len(self) / number
		managers = []
		for i in range(number):
			if len(self) % chunk_size >= number - i:
				managers.append(ProxyManager(self.records.keys()[chunk_size*i:chunk_size*(i+1)+1], min_delay=self.min_delay, max_delay=self.max_delay))
			else:
				managers.append(ProxyManager(self.records.keys()[chunk_size*i:chunk_size*(i+1)], min_delay=self.min_delay, max_delay=self.max_delay))
		return managers
		
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

class DisabledHTTPRedirectHandler(urllib2.HTTPRedirectHandler):
	def redirect_request(self, req, fp, code, msg, headers, newurl):
		print headers
		print req
		req.get_full_url()
		raise urllib2.HTTPError(req.get_full_url(), code, msg, headers, fp)

class http(object):
	def __init__(self, proxy=None, cookie_filename=None, cookies=True, redirects=True):
		self.handlers = set()
		try:
			useragents = [ua.strip() for ua in open('useragents.txt') if len(ua.strip())]
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
			if isinstance(proxy, ProxyManager):
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

		if not redirects:
			self.build_opener(DisabledHTTPRedirectHandler())

		self.build_opener(proxy_support,cookie_support,proxy_auth)
			
	def build_opener(self,*handlers):
		self.handlers |= set([handler for handler in handlers if handler is not None])
		self.opener = urllib2.build_opener(*self.handlers)

	def urlopen(self, url, post=None, ref=None, files=None, username=None, password=None, compress=True, head=False, timeout=30):
		assert url.lower().startswith('http')
		if isinstance(post, basestring):
			post = dict([part.split('=') for part in post.strip().split('&')])
		if post:
			for k, v in post.items():
				post[k] = spin(unicode(v).encode('utf-8'))
		if username and password:
			password_manager = urllib2.HTTPPasswordMgrWithDefaultRealm()
			password_manager.add_password(None, url, username, password)
			password_auth = urllib2.HTTPBasicAuthHandler(password_manager)
			self.build_opener(password_auth)
		urllib2.install_opener(self.opener)
		if compress:
			headers = {'User-Agent' : self.useragent, 'Accept-encoding' : 'gzip'}
		else:
			headers = {'User-Agent' : self.useragent}
		if ref:
			 headers['Referer'] = ref
		if files:
			content_type,post = encode_multipart_formdata(post.items(), files)
			headers['content-type'] = content_type
			headers['content-length'] = str(len(post))
		elif post:
			post = urllib.urlencode(post)
		if head:
			req = HeadRequest(url, post, headers)
		else:
			req = urllib2.Request(url, post, headers)
		with gevent.Timeout(timeout):
			response = urllib2.urlopen(req)
			return HTTPResponse(response, url, http=self)
		
def grab(url, proxy=None, post=None, ref=None, compress=True, include_url=False, retries=1, http_obj=None, cookies=False, redirects=True, timeout=30):
	data = None
	if retries < 1:
		retries = 1
	for i in range(retries):
		if not http_obj:
			http_obj = http(proxy, cookies=cookies, redirects=redirects)
		try:
			data = http_obj.urlopen(url=url, post=post, ref=ref, compress=compress, timeout=timeout)
			break
		except urllib2.HTTPError, e:
			if str(e.code).startswith('3') and not redirects:
				data = HTTPResponse(url=url, fake=True)
				break
		except:
			pass
	if data:
		return data
	return False

def WebQueue(iterator=None):
	queue = Queue.Queue()
	if iterator:
		[queue.put(item) for item in iterator]
	return queue

def generic_iterator(iterator):
	if isinstance(iterator, basestring):
		if '\n' in iterator:
			for i in iterator.split('\n'):
				if len(i.strip()):
					yield i.strip()
		else:
			yield iterator.strip()
	else:
		for i in iterator:
			yield i

class DomainQueue(object):
	def __init__(self, urls):
		self.domains = collections.defaultdict(list)
		for url in urls:
			if isinstance(url, basestring):
				url = urlparse.urlparse(url)
			self.domains[url.netloc].append(url.geturl())
		self.counter = {domain:0 for domain in self.domains.keys()}

	def empty(self):
		return len(self.domains) == 0

	def get_nowait(self):
		domain = min(self.counter, key=self.counter.get)
		url = self.domains[domain].pop()
		if len(self.domains[domain]) == 0:
			del(self.domains[domain])
			del(self.counter[domain])
		else:
			self.counter[domain] += 1
		return url

	def get(self):
		return self.get_nowait()

	def put(self, url):
		if isinstance(url, basestring):
			url = urlparse.urlparse(url)
		self.domains[url.netloc].append(url.geturl())
		if url.netloc not in self.counter:
			self.counter[url.netloc] = 0

	def __len__(self):
		return sum((len(d) for d in self.domains.values()))

def multi_grab(urls, pool_size=100, processes=1, timeout=10, queuify=True):
	if queuify:
		in_q = WebQueue(generic_iterator(urls))
	else:
		in_q = urls
	for result in pooler(grab, in_q, pool_size=pool_size, processes=processes, timeout=timeout):
		yield result

def domain_crawl(urls, pool_size=100, processes=1, timeout=30, max_pages=0):
	urls = {url for url in generic_iterator(urls)}
	domains = {urlparse.urlparse(url).netloc for url in urls}
	seen_urls = BloomFilter()
	[seen_urls.add(url) for url in urls]
	while len(urls):
		for result_counter, result in enumerate(multi_grab(urls, pool_size, processes, timeout)):
			if result.final_domain in domains:
				urls |= {link for link in result.internal_links() if link not in seen_urls}
				if max_pages > 0 and result_counter > max_pages:
					break
				yield result

def redirecturl(url, proxy=None):
	return http(proxy).urlopen(url, head=True).geturl()

def pooler_worker(func, pool_size, in_q, out_q, max_results, kwargs):
	monkey.patch_all(thread=False)
	p = pool.Pool(pool_size)
	greenlets = set()
	results_counter = 0
	while True:
		try:
			i = in_q.get_nowait()
		except:
			break
		if not isinstance(i, dict):
			i = {inspect.getargspec(func).args[0]: i}
		kwargs = dict(kwargs.items() + i.items())
		greenlets.add(p.spawn(func, **kwargs))
		finished_greenlets = {g for g in greenlets if g.value}
		greenlets -= finished_greenlets
		for g in finished_greenlets:
			out_q.put(g.value)
			results_counter += 1
		if max_results > 0 and results_counter >= max_results:
			break
	p.join()
	for g in greenlets:
		if g.value:
			out_q.put(g.value)
	out_q.put(None)

def cloud_pooler(func, in_q, chunk_size=1000, _env='python-web', _type='c2', _max_runtime=60, get_results=True, **kwargs):
	import cloud
	if chunk_size > 1:
		if isinstance(in_q, collections.Iterable):
			in_q = WebQueue(in_q)
		chunks = []
		chunk = []
		while not in_q.empty():
			chunk.append(in_q.get())
			if len(chunk) == chunk_size:
				chunks.append(chunk)
				chunk = []
		if len(chunk):
			chunks.append(chunk)
	else:
		chunks = in_q

	partial_func = functools.partial(func, **kwargs)
	jids = cloud.map(partial_func, chunks, _env=_env, _type=_type, _max_runtime=_max_runtime)

	if get_results:
		print jids
		for jid in jids:
			result = cloud.result(jid, ignore_errors=True)
			if result:
				yield result
	else:
		for jid in jids:
			yield jid

def pooler(func, in_q, pool_size=100, processes=multiprocessing.cpu_count(), proxy=False, max_results=0, **kwargs):
	if isinstance(in_q, collections.Iterable):
		in_q = WebQueue(in_q)
	out_q = multiprocessing.Queue()
	if proxy and not isinstance(proxy, ProxyManager):
		proxy = ProxyManager(proxy)

	if processes > 1:
		spawned = []
		multi_pool_size = pool_size / processes
		if multi_pool_size < 1:
			multi_pool_size = 1
		if proxy:
			proxy = [m for m in proxy.split(processes)]
		for i in range(processes):
			if proxy:
				kwargs['proxy'] = proxy[i]
			p = multiprocessing.Process(target=pooler_worker, args=(func, multi_pool_size, in_q, out_q, max_results / processes, kwargs))
			p.start()
			spawned.append(p)
		finished_counter = 0
		while True:
			result = out_q.get()
			if not result:
				finished_counter += 1
				if finished_counter == processes:
					break
			else:
				yield result
		[p.join() for p in spawned]
		while not out_q.empty():
			yield result
	else:
		p = pool.Pool(pool_size)
		greenlets = set()
		if proxy:
			kwargs['proxy'] = proxy
		result_counter = 0
		while True:
			try:
				i = in_q.get_nowait()
			except:
				break
			if not isinstance(i, dict):
				i = {inspect.getargspec(func).args[0]: i}
			kwargs = dict(kwargs.items() + i.items())
			greenlets.add(p.spawn(func, **kwargs))
			finished_greenlets = {g for g in greenlets if g.value}
			greenlets -= finished_greenlets
			for g in finished_greenlets:
				yield g.value
				result_counter += 1
			if max_results > 0 and result_counter >= max_results:
				break

		p.join()
		for g in greenlets:
			if g.value:
				yield g.value
