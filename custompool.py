from gevent import pool
from gevent.queue import Queue
import gevent

class LimitedIMapUnordered(pool.IMapUnordered):
	def __init__(self, func, iterable, max_queue, spawn=None):
		pool.IMapUnordered.__init__(self, func, iterable, spawn)
		self.queue = Queue(max_queue)
		self.max_queue = max_queue
		
	def _run(self):
		try:
			func = self.func
			for item in self.iterable:
				while self.queue.qsize() + self.count + 2 == self.max_queue:
					gevent.sleep(0.1)
				self.count += 1
				self.spawn(func, item).rawlink(self._on_result)
		finally:
			self.__dict__.pop('spawn', None)
			self.__dict__.pop('func', None)
			self.__dict__.pop('iterable', None)

class Pool(pool.Pool):
	def imap_unordered(self, func, iterable):
		"""The same as imap() except that the ordering of the results from the
		returned iterator should be considered in arbitrary order."""
		return LimitedIMapUnordered.spawn(func, iterable, self.size, self.spawn)
