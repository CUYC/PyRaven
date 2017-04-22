import unittest
import time
import metapaw.Raven as Raven

class TestRaven(unittest.TestCase):
	def __init__(self, something):
		super(TestRaven, self).__init__(something)
		self.UCamKeys = { '1': 'test_keys/pubkey1' }
		self.UCamServiceURL = 'https://raven.cam.ac.uk/auth/authenticate.html'
		self.UCamService = Raven.Service('https://raven.cam.ac.uk/auth/authenticate.html',{'1':'test_keys/pubkey1'})
	
	def setUp(self):
		self.oldRedirect = Raven.redirect
		Raven.redirect = self.redirect
		self.Raven_gmtime = Raven.gmtime
		Raven.gmtime = lambda: time.strptime(self.fake_timeString, "%b %d %Y %H:%M:%S %Z")
		self.Raven_wls_response = Raven.wls_response
		Raven.wls_response = lambda: self.fake_wls_response
		self.Raven_persistenceMethod = Raven.persistenceMethod
	
	def tearDown(self):
		Raven.redirect = self.oldRedirect
		Raven.gmtime = self.Raven_gmtime
		Raven.wls_response = self.Raven_wls_response
		Raven.persistenceMethod = self.Raven_persistenceMethod
	
	class Redirected(Exception):
		'''Exception'''
	
	def redirect(location):
		raise TestRaven.Redirected, location
	redirect = staticmethod(redirect)
	
	def testNeedsTwoArguments(self):
		self.assertRaises( TypeError, Raven.authenticate )
		self.assertRaises( TypeError, Raven.authenticate, self.UCamService )
	
	def authenticateRedirectsTo(self, location, *args, **namedArgs):
		try:
			Raven.authenticate(*args, **namedArgs)
		except TestRaven.Redirected, exception:
			self.assertEquals( exception.args[0], location )
		else:
			self.assert_( False, 'authenticate did not redirect' )
	
	def testSimpleRedirection(self):
		self.fake_wls_response = None
		
		self.authenticateRedirectsTo(self.UCamServiceURL + '?ver=1&url=http%3A%2F%2Flocalhost%2F',
		                             self.UCamService, thisURL = 'http://localhost/')
		
		testServiceURL = 'http://localhost/'
		testService = Raven.Service(testServiceURL,{})
		self.authenticateRedirectsTo(testServiceURL + '?ver=1&url=http%3A%2F%2Flocalhost%2F',
		                             testService, thisURL = 'http://localhost/')
	
	def testRedirectionWithArguments(self):
		baseRequest = '?ver=1&url=http%3A%2F%2Flocalhost%2F'
		baseRequestWithTarget = '?ver=1&url=http%3A%2F%2Flocalhost%2Fsome-secure-page'
		
		argumentsAndRedirectQuery = [
			( { 'allowedMethods' : ('pwd', 'card') }, baseRequest + '&aauth=pwd%2Ccard' ),
			( { 'targetURL' : 'http://localhost/some-secure-page' }, baseRequestWithTarget ),
			( { 'targetURL' : 'http://localhost/some-secure-page', 'targetDescription' : 'Some Secure Page' }, baseRequestWithTarget + '&desc=Some+Secure+Page' ),
			( { 'reauthenticate' : Raven.Always }, baseRequest + '&iact=yes' ),
			( { 'reauthenticate' : Raven.Never }, baseRequest + '&iact=no' ),
			( { 'reauthenticate' : Raven.DontCare }, baseRequest ),
			( { 'message' : 'Hello here is a hash #' }, baseRequest + '&msg=Hello+here+is+a+hash+%23' ),
			( { 'targetDescription' : 'blah blah blah' }, baseRequest + '&desc=blah+blah+blah' ),
			( { 'ravenHandlesErrors' : True }, baseRequest + '&fail=yes' ),
			( { 'ravenHandlesErrors' : False }, baseRequest ),
			( { 'pageParameters' : 'argh stuff' }, baseRequest + '&params=argh+stuff' ),
			( { 'maximumClockSkew' : 300 }, baseRequest + '&date=20040805T115526Z&skew=300' )
		]
		
		self.fake_timeString = "Aug 5 2004 11:55:26 UTC"
		self.fake_wls_response = None
		
		for argumentDict, redirectQuery in argumentsAndRedirectQuery:
			self.authenticateRedirectsTo( self.UCamServiceURL + redirectQuery, self.UCamService,
			                              thisURL = 'http://localhost/', **argumentDict)
	
	def testGmTimeFunction(self):
		self.assertEqual(self.Raven_gmtime(), time.gmtime())
	
	def testRespondToHTTPResponseWithWLSResponseParameter(self):
		validResponse = '1!200!!20040817T112037Z!1092741636-4961-0!http://www.srcf.ucam.org/~teh30/temporary/CGI/wls-response.cgi!teh30!!pwd!811!%21@#$$%25&^^&*%21(snthuas%21%21n%21oehuvvz=\-=+?|%21%21%21!1!mwvXPPpTDR.Lsx5kCpbihWToC0Hb-u7CHgEFwaGrP-x6eCwDORVLmtCt2zr4DN.Dj-pLuYvwihzFAzNN4Vq8HX5r175ytbYAGG2BWxLcr2FCax2AaHUYQ6.89rg0x3.B5lZQAe8.uPjw2hFB4YN.8L464vdQlJfkHKDyONn4A6c_'
		responseDate = 'Aug 17 2004 11:20:37 UTC'
		minuteAfterResponseDate = 'Aug 17 2004 11:21:37 UTC'
		yearsAfterResponseDate = 'Aug 17 2034 11:20:37 UTC'
		responseURL = 'http://www.srcf.ucam.org/~teh30/temporary/CGI/wls-response.cgi'
		notResponseURL = 'http://localhost'
		
		validResponse2WithAuth = '1!200!!20040731T184543Z!1091299543-22311-3!http://mnementh.csi.cam.ac.uk/raven-test/open/document1.html!teh30!pwd!!900!!1!ETd0EshgkpF8DlcwTju02sVgLqgkR3J3U8Dyax1Ki1YiUB9432Wi1g6zOTe64ucHCR5fGa3.VUCEImQIT6Bg8NxnG2hWO52kNA7CX5ucXlXtpLvP7CMmbqyUNOUx51HWgO8WuwfJA06LosaduAYmLhCYfY5HxIzDs5mOlv3i7no_'
		responseDate2 = 'Jul 31 2004 18:45:43 UTC'
		responseURL2 = 'http://mnementh.csi.cam.ac.uk/raven-test/open/document1.html'
		
		responsesAndResults = [
			# ( wls_response, date, args, exception )
			( validResponse, responseDate,            dict( thisURL = responseURL ),    None ),
			( 'wrong ver!!', None,                    dict( thisURL = responseURL ),   Raven.VersionNotUnderstood ),
			( '', None,                               dict( thisURL = responseURL ),   Raven.VersionNotUnderstood ),
			( validResponse, None,                    dict( thisURL = notResponseURL ), Raven.URLMismatch ),
			( validResponse, yearsAfterResponseDate,  dict( thisURL = responseURL ),   Raven.CredentialsExpired ),
			( validResponse, minuteAfterResponseDate, dict( thisURL = responseURL, maximumClockSkew = 30 ), Raven.CredentialsExpired ),
			( validResponse, minuteAfterResponseDate, dict( thisURL = responseURL, maximumClockSkew = 60 ), None ),
			( validResponse, responseDate,            dict( thisURL = responseURL, allowedMethods = ('pwd',) ), None ),
			( validResponse, responseDate,            dict( thisURL = responseURL, allowedMethods = ('card',) ), Raven.NoAcceptableAuthMethod ),
			( validResponse, responseDate,            dict( thisURL = responseURL, allowedMethods = ('pwd',), reauthenticate = Raven.Always ), Raven.DidNotReauthenticate ),
			( validResponse, responseDate,            dict( thisURL = responseURL, allowedMethods = ('card',), reauthenticate = Raven.Always ), Raven.NoAcceptableAuthMethod ),
			( validResponse, responseDate,            dict( thisURL = responseURL, reauthenticate = Raven.Always ), Raven.DidNotReauthenticate ),
			( validResponse2WithAuth, responseDate2,  dict( thisURL = responseURL2, reauthenticate = Raven.Always ), None ),
			( validResponse2WithAuth, responseDate2,  dict( thisURL = responseURL2, reauthenticate = Raven.Always, allowedMethods = ('card',) ), Raven.NoAcceptableAuthMethod ),
			( validResponse2WithAuth, responseDate2,  dict( thisURL = responseURL2 ), None ),
			( validResponse2WithAuth, responseDate2,  dict( thisURL = responseURL2, allowedMethods = ('pwd',) ), None ),
			( validResponse2WithAuth, responseDate2,  dict( thisURL = responseURL2, allowedMethods = ('card',) ), Raven.NoAcceptableAuthMethod ),
		]
		
		for self.fake_wls_response, self.fake_timeString, args, exception in responsesAndResults:
			if exception is None:
				Raven.authenticate( self.UCamService, **args )
			else:
				self.assertRaises( exception, Raven.authenticate, self.UCamService, **args )
	
	def assertCredentialsEqual(self, cred, principal, pageParameters, message):
		self.assertEqual( cred.principal, 'teh30' )
		self.assertEqual( cred.pageParameters, '!@#$$%&^^&*!(snthuas!!n!oehuvvz=\-=+?|!!!' )
		self.assertEqual( cred.message, '' )
	
	def testCredentials(self):
		self.fake_wls_response = '1!200!!20040817T112037Z!1092741636-4961-0!http://www.srcf.ucam.org/~teh30/temporary/CGI/wls-response.cgi!teh30!!pwd!811!%21@#$$%25&^^&*%21(snthuas%21%21n%21oehuvvz=\-=+?|%21%21%21!1!mwvXPPpTDR.Lsx5kCpbihWToC0Hb-u7CHgEFwaGrP-x6eCwDORVLmtCt2zr4DN.Dj-pLuYvwihzFAzNN4Vq8HX5r175ytbYAGG2BWxLcr2FCax2AaHUYQ6.89rg0x3.B5lZQAe8.uPjw2hFB4YN.8L464vdQlJfkHKDyONn4A6c_'
		self.fake_timeString = 'Aug 17 2004 11:20:37 UTC'
		thisURL = 'http://www.srcf.ucam.org/~teh30/temporary/CGI/wls-response.cgi'
		
		cred = Raven.authenticate( self.UCamService, thisURL = thisURL )
		self.assertCredentialsEqual( cred, 'teh30', '!@#$$%&^^&*!(snthuas!!n!oehuvvz=\-=+?|!!!', '' )
	
	def testPersistence(self):	
		wls_response = '1!200!!20040817T112037Z!1092741636-4961-0!http://www.srcf.ucam.org/~teh30/temporary/CGI/wls-response.cgi!teh30!!pwd!811!%21@#$$%25&^^&*%21(snthuas%21%21n%21oehuvvz=\-=+?|%21%21%21!1!mwvXPPpTDR.Lsx5kCpbihWToC0Hb-u7CHgEFwaGrP-x6eCwDORVLmtCt2zr4DN.Dj-pLuYvwihzFAzNN4Vq8HX5r175ytbYAGG2BWxLcr2FCax2AaHUYQ6.89rg0x3.B5lZQAe8.uPjw2hFB4YN.8L464vdQlJfkHKDyONn4A6c_'
		
		thisURL = 'http://www.srcf.ucam.org/~teh30/temporary/CGI/wls-response.cgi'
		
		timeOfRequest = 'Aug 17 2004 11:20:37 UTC'
		fifteenMinsAfterRequest = 'Aug 17 2004 11:35:37 UTC'
		twentyMinsAfterRequest = 'Aug 17 2004 11:40:37 UTC'
		
		def testPersistenceRestoring():
			class GetPersistenceMethod:
				def get(self):
					return wls_response
				def set(self, param):
					assert False
				def delete(self):
					pass
				
			Raven.persistenceMethod = GetPersistenceMethod()
			self.fake_wls_response = None
			
			self.fake_timeString = timeOfRequest
			cred = Raven.authenticate( self.UCamService, thisURL = thisURL )
			self.assertCredentialsEqual( cred, 'teh30', '!@#$$%&^^&*!(snthuas!!n!oehuvvz=\-=+?|!!!', '' )
			
			self.fake_timeString = fifteenMinsAfterRequest
			Raven.authenticate( self.UCamService, thisURL = thisURL )
			
			self.fake_timeString = twentyMinsAfterRequest
			self.assertRaises( Raven.CredentialsExpired, Raven.authenticate, self.UCamService, thisURL = thisURL )
		
		def testPersistenceSaving():
			class SetPersistenceMethod:
				def get(self):
					assert False
				def set(self, param):
					assert 'setTo' not in self.__dict__
					self.setTo = param
				def delete(self):
					assert False
			
			Raven.persistenceMethod = SetPersistenceMethod()
			self.fake_wls_response = wls_response
			
			self.fake_timeString = timeOfRequest
			Raven.authenticate( self.UCamService, thisURL = thisURL )
			self.assertEqual( Raven.persistenceMethod.setTo, Raven.wls_response() )
		
		def testPersistenceInvalid():
			class PersistenceMethod:
				def get(self):
					return 'invalid!'
				def delete(self):
					assert 'deleted' not in self.__dict__
					self.deleted = True
				def set(self, s): assert False
			
			Raven.persistenceMethod = PersistenceMethod()
			self.fake_wls_response = None
			
			self.assertRaises( self.Redirected, Raven.authenticate, self.UCamService, thisURL = 'whatever' )
			assert Raven.persistenceMethod.deleted
		
		def testPersistenceNotAllowedIfAuthRequired():
			validResponse2WithAuth = '1!200!!20040731T184543Z!1091299543-22311-3!http://mnementh.csi.cam.ac.uk/raven-test/open/document1.html!teh30!pwd!!900!!1!ETd0EshgkpF8DlcwTju02sVgLqgkR3J3U8Dyax1Ki1YiUB9432Wi1g6zOTe64ucHCR5fGa3.VUCEImQIT6Bg8NxnG2hWO52kNA7CX5ucXlXtpLvP7CMmbqyUNOUx51HWgO8WuwfJA06LosaduAYmLhCYfY5HxIzDs5mOlv3i7no_'
			self.fake_timeString = 'Jul 31 2004 18:45:43 UTC'
			responseURL2 = 'http://mnementh.csi.cam.ac.uk/raven-test/open/document1.html'
			
			class PersistenceMethod:
				def get(self):
					return validResponse2WithAuth
				def delete(self): pass
				def set(self, s): assert False
			
			Raven.persistenceMethod = PersistenceMethod()
			self.fake_wls_response = None
			
			Raven.authenticate( self.UCamService, thisURL = responseURL2 )
			self.assertRaises( self.Redirected, Raven.authenticate, self.UCamService, thisURL = responseURL2, reauthenticate = Raven.Always )
		
		testPersistenceRestoring()
		testPersistenceSaving()
		testPersistenceInvalid()
		testPersistenceNotAllowedIfAuthRequired()
		
	def testUnsuccessfulStatusCodes(self):
		thisURL = 'http://mnementh.csi.cam.ac.uk/raven-test/open/document1.html'
		unsuccessful_status_codes = [ '410', '510', '520', '530', '540', '550', '560', '570' ]
		unsuccessful_status_responses = [
			'1!' + code + '!!20040731T184543Z!1091299543-22311-3!' + thisURL + '!!pwd!!900!!1!'
			for code in unsuccessful_status_codes
		]
		
		self.fake_timeString = 'Jul 31 2004 18:45:43 UTC'

		for self.fake_wls_response in unsuccessful_status_responses:
			self.assertRaises(Raven.UnsuccessfulStatusCode, Raven.authenticate, self.UCamService, thisURL)
	
	def testExceptionDescendents(self):
		def ispropersubclass(A, B):
			return issubclass(A, B) and A is not B
		
		exceptions = [ Raven.VersionNotUnderstood, Raven.UnknownKey, Raven.MalformedResponse, 
			Raven.IncorrectSignature, Raven.URLMismatch, Raven.CredentialsExpired,
			Raven.NoAcceptableAuthMethod, Raven.DidNotReauthenticate,
			Raven.UnsuccessfulStatusCode ]
			
		for exception in exceptions:
			assert ispropersubclass(exception, Raven.Exception)
		
		assert ispropersubclass(Raven.Exception, Exception)
		
	#def usage(self):
		#settings = {
		#	'pageParameters': 'some params',
		#	'allowedMethods': ('pwd','card'),
		#	'thisURL': 'http://localhost/test.py'
		#	'thisRealm': 'http://localhost/' <-- defaults to thisURL
		#	'targetURL': 'http://localhost/them.py' <-- defaults to thisURL
		#	'targetDescription': 'I am Localhost. Bow down before me'
		#	'reauthenticate': Always | Never | DontCare
		#	'message': 'I vant to drink your passvord'
		#	'maximumClockSkew': 60
		#	'ravenHandlesErrors': False
		#}
		#Raven.persistenceMethod = Raven.Persistence.InsecureCookies
		#credentials = Raven.authenticate(self.UCamService, thisURL = 'http://localhost/')
		#if credentials.principal == 'teh30':
		#	print 'You are Tom.'
		#print credentials.pageParameters
		#print credentials.message

if __name__ == '__main__':
	unittest.main()
