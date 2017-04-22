import unittest
import time
import metapaw.__RavenLowLevel as RavenLL

class TestRavenLL(unittest.TestCase):
	def setUp(self):
		self.testKeys = { '1': 'test_keys/pubkey1' }
		self.service1 = 'https://raven.cam.ac.uk/auth/authenticate.html'
		self.service2 = 'https://www.example.com/authenticate.cgi'
		self.url1 = 'http://www.example.com'
		self.url2 = 'http://www.test.com/somecgi.cgi?amount=3'
		self.url1query = '?ver=1&url=http%3A%2F%2Fwww.example.com'
		self.url2query = '?ver=1&url=http%3A%2F%2Fwww.test.com%2Fsomecgi.cgi%3Famount%3D3'
	
	def constructAuthenticationResponseWithDefaultKeys( self, wls_response ):
		return RavenLL.AuthenticationResponse( wls_response, self.testKeys )
	
	def testNothing(self):
		assert(True)

	def testAuthenticationRequest_simple(self):
		service1, service2, url1, url2 = self.service1, self.service2, self.url1, self.url2
		url1query, url2query = self.url1query, self.url2query
		
		tests = [
			( service1, url1, service1 + url1query ),
			( service1, url2, service1 + url2query ),
			( service2, url1, service2 + url1query ),
			( service2, url2, service2 + url2query )
		]

		for service, url, response in tests:
			self.assertEqual( RavenLL.authenticationRequest( service, url ), response )

	def testEncodeURL(self):
		import urllib
		url = urllib.urlencode( [ ('value1', 'http://www'), ('value2', 'http://test?foo/bar') ] )
		self.assertEqual( url, 'value1=http%3A%2F%2Fwww&value2=http%3A%2F%2Ftest%3Ffoo%2Fbar' )

	def testAuthenticationRequest_optionalArguments(self):
		service1 = self.service1
		url1 = self.url1
		url1query = self.url1query
		
		optional_parameters = [ ('desc', 'A test parameter', '&desc=A+test+parameter'),
		                        ('aauth', 'pwd,card', '&aauth=pwd%2Ccard'),
		                        ('iact', 'yes', '&iact=yes'),
		                        ('msg', 'I want you & your password', '&msg=I+want+you+%26+your+password'),
		                        ('params', 'Here are some params', '&params=Here+are+some+params'),
		                        ('date', '20040805T115526Z', '&date=20040805T115526Z'),
		                        ('skew', '5', '&skew=5'),
		                        ('fail', 'yes', '&fail=yes') ]
		                        
		for name, value, parameters_query in optional_parameters:
			self.assertEqual( RavenLL.authenticationRequest( service1, url1, **{name: value} ),
			                  service1 + url1query + parameters_query )
			                  
	def testAuthenticationRequest_badArguments(self):
		self.assertRaises( TypeError, RavenLL.authenticationRequest, self.service1, self.url1, fail = 1)

	def testAuthenticationResponse_valid(self):
		valid_responses = [
			# Need more tests, with other keys
			'1!200!!20040731T184543Z!1091299543-22311-3!http://mnementh.csi.cam.ac.uk/raven-test/open/document1.html!teh30!pwd!!900!!1!ETd0EshgkpF8DlcwTju02sVgLqgkR3J3U8Dyax1Ki1YiUB9432Wi1g6zOTe64ucHCR5fGa3.VUCEImQIT6Bg8NxnG2hWO52kNA7CX5ucXlXtpLvP7CMmbqyUNOUx51HWgO8WuwfJA06LosaduAYmLhCYfY5HxIzDs5mOlv3i7no_',
			'1!200!!20040816T192420Z!1092684260-1402-5!http://mnementh.csi.cam.ac.uk/raven-test/open/document1.html!teh30!pwd!!900!!1!k.gWC47ImDAMpnARKNyAdOYP4ueCh8aSLgIH4C7gHAu.6uxe6O3aJFkxWRz7fJxM6EadhejOPuCKwfddrmw0mssLUC08lu5W6QBvOemaIqzWcjnGZYcjHeRzMOZ4EVzrgXQuBBGlsmzNGCxKlgX3ElVRmFaHX3oL7nAyzZC2Zgo_',
			'1!410!!20040731T184543Z!1091299543-22311-3!http://mnementh.csi.cam.ac.uk/raven-test/open/document1.html!!pwd!!900!!1!',
			'1!510!!20040731T184543Z!1091299543-22311-3!http://mnementh.csi.cam.ac.uk/raven-test/open/document1.html!!pwd!!900!!1!',
			'1!520!!20040731T184543Z!1091299543-22311-3!http://mnementh.csi.cam.ac.uk/raven-test/open/document1.html!!pwd!!900!!1!',
			'1!530!!20040731T184543Z!1091299543-22311-3!http://mnementh.csi.cam.ac.uk/raven-test/open/document1.html!!pwd!!900!!1!',
			'1!540!!20040731T184543Z!1091299543-22311-3!http://mnementh.csi.cam.ac.uk/raven-test/open/document1.html!!pwd!!900!!1!',
			'1!550!!20040731T184543Z!1091299543-22311-3!http://mnementh.csi.cam.ac.uk/raven-test/open/document1.html!!pwd!!900!!1!',
			'1!560!!20040731T184543Z!1091299543-22311-3!http://mnementh.csi.cam.ac.uk/raven-test/open/document1.html!!pwd!!900!!1!',
			'1!570!!20040731T184543Z!1091299543-22311-3!http://mnementh.csi.cam.ac.uk/raven-test/open/document1.html!!pwd!!900!!1!',
			# empty life
			'1!410!!20040731T184543Z!1091299543-22311-3!http://mnementh.csi.cam.ac.uk/raven-test/open/document1.html!!pwd!!!!1!',
			# zero life
			'1!410!!20040731T184543Z!1091299543-22311-3!http://mnementh.csi.cam.ac.uk/raven-test/open/document1.html!!pwd!!0!!1!',
		]
		for wls_response in valid_responses:
			self.constructAuthenticationResponseWithDefaultKeys(wls_response)

	def testAuthenticationResponse_illegal(self):
		illegal_responses = [
			# incorrect version number
			( '2!200!!20040731T184543Z!1091299543-22311-3!http://mnementh.csi.cam.ac.uk/raven-test/open/document1.html!teh30!pwd!!900!!1!ETd0EshgkpF8DlcwTju02sVgLqgkR3J3U8Dyax1Ki1YiUB9432Wi1g6zOTe64ucHCR5fGa3.VUCEImQIT6Bg8NxnG2hWO52kNA7CX5ucXlXtpLvP7CMmbqyUNOUx51HWgO8WuwfJA06LosaduAYmLhCYfY5HxIzDs5mOlv3i7no_', RavenLL.VersionNotUnderstood ),
			# missing signature on 200 response
			( '1!200!!20040731T184543Z!1091299543-22311-3!http://mnementh.csi.cam.ac.uk/raven-test/open/document1.html!teh30!pwd!!900!!1!', RavenLL.MalformedResponse ),
			# too many arguments
			( '1!200!extra!!20040731T184543Z!1091299543-22311-3!http://mnementh.csi.cam.ac.uk/raven-test/open/document1.html!teh30!pwd!!900!!1!ETd0EshgkpF8DlcwTju02sVgLqgkR3J3U8Dyax1Ki1YiUB9432Wi1g6zOTe64ucHCR5fGa3.VUCEImQIT6Bg8NxnG2hWO52kNA7CX5ucXlXtpLvP7CMmbqyUNOUx51HWgO8WuwfJA06LosaduAYmLhCYfY5HxIzDs5mOlv3i7no_', RavenLL.MalformedResponse ),
			( '1!560!extra!!20040731T184543Z!1091299543-22311-3!http://mnementh.csi.cam.ac.uk/raven-test/open/document1.html!!pwd!!900!!1!ETd0EshgkpF8DlcwTju02sVgLqgkR3J3U8Dyax1Ki1YiUB9432Wi1g6zOTe64ucHCR5fGa3.VUCEImQIT6Bg8NxnG2hWO52kNA7CX5ucXlXtpLvP7CMmbqyUNOUx51HWgO8WuwfJA06LosaduAYmLhCYfY5HxIzDs5mOlv3i7no_', RavenLL.MalformedResponse ),
			# too few arguments
			( '1!200!20040731T184543Z!1091299543-22311-3!http://mnementh.csi.cam.ac.uk/raven-test/open/document1.html!teh30!pwd!!900!!1!ETd0EshgkpF8DlcwTju02sVgLqgkR3J3U8Dyax1Ki1YiUB9432Wi1g6zOTe64ucHCR5fGa3.VUCEImQIT6Bg8NxnG2hWO52kNA7CX5ucXlXtpLvP7CMmbqyUNOUx51HWgO8WuwfJA06LosaduAYmLhCYfY5HxIzDs5mOlv3i7no_', RavenLL.MalformedResponse ),
			( '1!560!20040731T184543Z!1091299543-22311-3!http://mnementh.csi.cam.ac.uk/raven-test/open/document1.html!!pwd!!900!!1!', RavenLL.MalformedResponse ),
			# old bugs
			( '', RavenLL.VersionNotUnderstood ),
			( '!', RavenLL.VersionNotUnderstood ),
			( '1!', RavenLL.MalformedResponse ),
			# invalid status code
			( '1!100!!20040731T184543Z!1091299543-22311-3!http://mnementh.csi.cam.ac.uk/raven-test/open/document1.html!!pwd!!900!!1!', RavenLL.MalformedResponse ),
			# invalid date
			( '1!200!!MONKEY04TZXX43!1091299543-22311-3!http://mnementh.csi.cam.ac.uk/raven-test/open/document1.html!teh30!pwd!!900!!1!ETd0EshgkpF8DlcwTju02sVgLqgkR3J3U8Dyax1Ki1YiUB9432Wi1g6zOTe64ucHCR5fGa3.VUCEImQIT6Bg8NxnG2hWO52kNA7CX5ucXlXtpLvP7CMmbqyUNOUx51HWgO8WuwfJA06LosaduAYmLhCYfY5HxIzDs5mOlv3i7no_', RavenLL.MalformedResponse ),
			# date with some crap on the end
			( '1!410!!20040731T184543Zcrap!1091299543-22311-3!http://mnementh.csi.cam.ac.uk/raven-test/open/document1.html!!pwd!!900!!1!', RavenLL.MalformedResponse ),
			# status 200 but principal missing
			( '1!200!!20040731T184543Z!1091299543-22311-3!http://mnementh.csi.cam.ac.uk/raven-test/open/document1.html!!pwd!!900!!1!ETd0EshgkpF8DlcwTju02sVgLqgkR3J3U8Dyax1Ki1YiUB9432Wi1g6zOTe64ucHCR5fGa3.VUCEImQIT6Bg8NxnG2hWO52kNA7CX5ucXlXtpLvP7CMmbqyUNOUx51HWgO8WuwfJA06LosaduAYmLhCYfY5HxIzDs5mOlv3i7no_', RavenLL.MalformedResponse ),
			# status not 200 but principal present
			( '1!510!!20040731T184543Z!1091299543-22311-3!http://mnementh.csi.cam.ac.uk/raven-test/open/document1.html!teh30!pwd!!900!!1!', RavenLL.MalformedResponse ),
			# non-empty non-numeric life
			( '1!200!!20040731T184543Z!1091299543-22311-3!http://mnementh.csi.cam.ac.uk/raven-test/open/document1.html!teh30!pwd!!blah_life!!1!ETd0EshgkpF8DlcwTju02sVgLqgkR3J3U8Dyax1Ki1YiUB9432Wi1g6zOTe64ucHCR5fGa3.VUCEImQIT6Bg8NxnG2hWO52kNA7CX5ucXlXtpLvP7CMmbqyUNOUx51HWgO8WuwfJA06LosaduAYmLhCYfY5HxIzDs5mOlv3i7no_', RavenLL.MalformedResponse ),
		]
		for wls_response, exception in illegal_responses:
			self.assertRaises( exception, self.constructAuthenticationResponseWithDefaultKeys, wls_response )

	def testAuthenticationResponse_incorrectSignature(self):
		incorrect_signature_responses = [
			( '1!200!!20040731T184543Z!1091299543-22311-3!http://mnementh.csi.cam.ac.uk/raven-test/open/document1.html!teh30!pwd!!900!!1!mangled_signature_u02sVgLqgkR3J3U8Dyax1Ki1YiUB9432Wi1g6zOTe64ucHCR5fGa3.VUCEImQIT6Bg8NxnG2hWO52kNA7CX5ucXlXtpLvP7CMmbqyUNOUx51HWgO8WuwfJA06LosaduAYmLhCYfY5HxIzDs5mOlv3i7no_', RavenLL.IncorrectSignature ),
			( '1!200!mangle!20040816T192420Z!1092684260-1402-5!http://mnementh.csi.cam.ac.uk/raven-test/open/document1.html!teh30!pwd!!900!!1!k.gWC47ImDAMpnARKNyAdOYP4ueCh8aSLgIH4C7gHAu.6uxe6O3aJFkxWRz7fJxM6EadhejOPuCKwfddrmw0mssLUC08lu5W6QBvOemaIqzWcjnGZYcjHeRzMOZ4EVzrgXQuBBGlsmzNGCxKlgX3ElVRmFaHX3oL7nAyzZC2Zgo_', RavenLL.IncorrectSignature ),
			( '1!200!!20040731T184543Z!1091299543-22311-3!http://mnementh.csi.cam.ac.uk/raven-test/open/document1.html!teh30!pwd!!900!!nosuchkey!ETd0EshgkpF8DlcwTju02sVgLqgkR3J3U8Dyax1Ki1YiUB9432Wi1g6zOTe64ucHCR5fGa3.VUCEImQIT6Bg8NxnG2hWO52kNA7CX5ucXlXtpLvP7CMmbqyUNOUx51HWgO8WuwfJA06LosaduAYmLhCYfY5HxIzDs5mOlv3i7no_', RavenLL.UnknownKey ),
		]
		for wls_response, exception in incorrect_signature_responses:
			self.assertRaises( exception, self.constructAuthenticationResponseWithDefaultKeys, wls_response )

	def testAuthenticationResponse_accessors(self):
		wls_response = '1!200!!20040817T112037Z!1092741636-4961-0!http://www.srcf.ucam.org/~teh30/temporary/CGI/wls-response.cgi!teh30!!pwd!811!%21@#$$%25&^^&*%21(snthuas%21%21n%21oehuvvz=\-=+?|%21%21%21!1!mwvXPPpTDR.Lsx5kCpbihWToC0Hb-u7CHgEFwaGrP-x6eCwDORVLmtCt2zr4DN.Dj-pLuYvwihzFAzNN4Vq8HX5r175ytbYAGG2BWxLcr2FCax2AaHUYQ6.89rg0x3.B5lZQAe8.uPjw2hFB4YN.8L464vdQlJfkHKDyONn4A6c_'
		r = self.constructAuthenticationResponseWithDefaultKeys( wls_response )
		
		self.assertEquals( r.status, '200' )
		self.assertEquals( r.msg, '' )
		self.assertEquals( r.issue, '20040817T112037Z' )
		self.assertEquals( r.id, '1092741636-4961-0' )
		self.assertEquals( r.url, 'http://www.srcf.ucam.org/~teh30/temporary/CGI/wls-response.cgi' )
		self.assertEquals( r.principal, 'teh30' )
		self.assertEquals( r.auth, '' )
		self.assertEquals( r.sso, 'pwd' )
		self.assertEquals( r.life, '811' )
		self.assertEquals( r.params, '!@#$$%&^^&*!(snthuas!!n!oehuvvz=\-=+?|!!!' )
		assert( r.isSigned() )


class TestHelpers(unittest.TestCase):
	def testTimeToRFC3339(self):
		t1 = time.strptime("Aug 5 11:55:26 2004 UTC", "%b %d %H:%M:%S %Y %Z")
		t2 = time.strptime("Jan 16 18:53:03 1993 UTC", "%b %d %H:%M:%S %Y %Z")
		rfc1 = "20040805T115526Z"
		rfc2 = "19930116T185303Z"
		
		self.assertEqual(RavenLL.timeToRFC3339(t1), rfc1)
		self.assertEqual(RavenLL.timeToRFC3339(t2), rfc2)
	
	def testRFC3339ToTime(self):
		t1 = time.strptime("Aug 5 11:55:26 2004 UTC", "%b %d %H:%M:%S %Y %Z")
		t2 = time.strptime("Jan 16 18:53:03 1993 UTC", "%b %d %H:%M:%S %Y %Z")
		rfc1 = "20040805T115526Z"
		rfc2 = "19930116T185303Z"

		self.assertEqual(RavenLL.RFC3339ToTime(rfc1), t1)
		self.assertEqual(RavenLL.RFC3339ToTime(rfc2), t2)


if __name__ == '__main__':
	unittest.main()
