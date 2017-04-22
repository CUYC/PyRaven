import unittest
import metapaw.Raven.Handlers.CGI as CGI
import metapaw.Raven as Raven

class TestRavenHandlersCGI(unittest.TestCase):
	def testRedirectExits(self):
		old_print_to_stdout = CGI.print_to_stdout
		CGI.print_to_stdout = lambda s: None
		
		try:
			try:
				CGI.redirect('http://example.com/')
				assert False
			except SystemExit, e:
				assert e.code == 0
		finally:
			CGI.print_to_stdout = old_print_to_stdout
	
	def testWLSResponse(self):
		import os
		os.environ['QUERY_STRING'] = 'WLS-Response=banana'
		
		self.assertEqual(CGI.wls_response(), 'banana')
	
	def testAssignments(self):
		self.assertEqual(Raven.redirect, CGI.redirect)
		self.assertEqual(Raven.wls_response, CGI.wls_response)
	
if __name__ == '__main__':
	unittest.main()
