import urllib
import re
import __RavenRSAVerify as RSAVerify
import time

def authenticationRequest( service, url, **optional_parameters):
	required_parameters = { 'url': url }
		
	parameters_to_use = required_parameters.copy()
	
	for name, value in optional_parameters.iteritems():
		if not isinstance(value, str):
			raise TypeError, 'Argument %s must be string' % name
		if value:
			parameters_to_use[name] = value
	
	query_string = urllib.urlencode( parameters_to_use )
	return service + '?ver=1&' + query_string

RFC3339_Format = '%Y%m%dT%H%M%SZ'

def timeToRFC3339(pytime):
	return time.strftime(RFC3339_Format, pytime)

def RFC3339ToTime(rfc):
	return time.strptime(rfc + ' UTC', RFC3339_Format + ' %Z')


def _unquotedComponentGetter(n):
	return lambda self: urllib.unquote(self._AuthenticationResponse__components[n])

class AuthenticationResponse:
	def __init__( self, wlsResponse, keyFilenames ):
		components = wlsResponse.split('!')
		self.__components = components
		
		def checkCorrectVersion():
			if components[0] != '1':
				raise VersionNotUnderstood
		
		def checkLegalNumberOfComponents():
			if len(components) != 13:
				raise MalformedResponse
		
		def checkLegalStatusCode():
			knownStatusCodes = [ '200', '410', '510', '520', '530', '540', '550', '560', '570' ]
			if self.status not in knownStatusCodes:
				raise MalformedResponse
		
		def checkLegalIssue():
			if not re.match('[0-9]{8}T[0-9]{6}Z$', self.issue):
				raise MalformedResponse
		
		def checkLegalPrincipal():
			if self.status == '200' and self.principal == '':
				raise MalformedResponse
			
			if self.status != '200' and self.principal != '':
				raise MalformedResponse
		
		def checkLegalLife():
			if not re.match('([1-9][0-9]*|0|)$', self.life):
				raise MalformedResponse
		
		def checkLegalSignature():
			if self.status == '200' and not self.isSigned():
				raise MalformedResponse
		
		def checkCorrectSignature():
			if self.isSigned():
				kid = components[11]
				signature = components[12]
				try:
					keyFilename = keyFilenames[kid]
				except KeyError:
					raise UnknownKey
				dataToCheck = '!'.join(components[:11])
				if not RSAVerify.verifyRSASignature( keyFilename, dataToCheck, signature ):
					raise IncorrectSignature
		
		checkCorrectVersion()
		checkLegalNumberOfComponents()
		checkLegalStatusCode()
		checkLegalIssue()
		checkLegalPrincipal()
		checkLegalLife()
		checkLegalSignature()
		
		checkCorrectSignature()
	
	def isSigned(self):
		signature = self.__components[12]
		return signature != ''
	
	status = property( fget = _unquotedComponentGetter(1) )
	msg = property( fget = _unquotedComponentGetter(2) )
	issue = property( fget = _unquotedComponentGetter(3) )
	id = property( fget = _unquotedComponentGetter(4) )
	url = property( fget = _unquotedComponentGetter(5) )
	principal = property( fget = _unquotedComponentGetter(6) )
	auth = property( fget = _unquotedComponentGetter(7) )
	sso = property( fget = _unquotedComponentGetter(8) )
	life = property( fget = _unquotedComponentGetter(9) )
	params = property( fget = _unquotedComponentGetter(10) )

del _unquotedComponentGetter


class Exception(Exception):
	'''Exception'''

class VersionNotUnderstood(Exception):
	'''Exception'''

class MalformedResponse(Exception):
	'''Exception'''

class IncorrectSignature(Exception):
	'''Exception'''

class UnknownKey(Exception):
	'''Exception'''
