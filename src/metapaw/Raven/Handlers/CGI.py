import metapaw.Raven as Raven
import os
import Cookie

def redirect(url):
	import sys
	print_to_stdout('Location: %s' % url)
	print_to_stdout('')
	sys.exit(0)

def wls_response():
	import cgi
	response_or_None = cgi.FieldStorage().getfirst('WLS-Response', None)
	return response_or_None

def print_to_stdout(s):
	print s

class InsecureCookiesPersistenceMethod:
	def __init__(self):
		self.cookie_name = 'metapaw-Raven-Authentication'
		
	def get(self):
		C = Cookie.SimpleCookie()
		try:
			C.load(os.environ['HTTP_COOKIE'])
			return C[self.cookie_name].value
		except KeyError:
			return None
	
	def set(self, wls_response):
		path = os.environ['SCRIPT_NAME']
		C = Cookie.SimpleCookie()
		C[self.cookie_name] = wls_response
		C[self.cookie_name]['path'] = path
		print C
	
	def delete(self):
		C = Cookie.SimpleCookie()
		try:
			C.load(os.environ['HTTP_COOKIE'])
			C[self.cookie_name]['max-age'] = '0'
			C[self.cookie_name] = "I'm trying to delete this cookie"
			print C
		except KeyError:
			pass

Raven.redirect = redirect
Raven.wls_response = wls_response
Raven.persistenceMethod = InsecureCookiesPersistenceMethod()
