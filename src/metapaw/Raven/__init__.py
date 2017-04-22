import metapaw.__RavenLowLevel as RavenLL
from metapaw.__RavenLowLevel import Exception, VersionNotUnderstood, UnknownKey, MalformedResponse, IncorrectSignature

import time

Always = 'yes'
DontCare = ''
Never = 'no'

def authenticate( service, thisURL, targetURL = '', **args ):
	
	def haveArgument( arg ):
		return arg in args.keys()
	
	def mustReauthenticate():
		return haveArgument('reauthenticate') and args['reauthenticate'] == Always
	
	def maximumClockSkew():
		if haveArgument('maximumClockSkew'):
			return args['maximumClockSkew']
		else:
			return 300
	
	class RavenResponse:
		
		def checkAcceptableURL(self):
			if self.response.url != thisURL:
				raise URLMismatch
		
		def secondsSinceResponse(self):
			response_secs = time.mktime(RavenLL.RFC3339ToTime(self.response.issue))
			now_secs = time.mktime(gmtime())
			
			return now_secs - response_secs
		
		def maximumAllowableSecondsSinceResponse(self):
			return maximumClockSkew()
		
		#def maximumAllowableSecondsBeforeResponse(self):
		#	return maximumClockSkew()
		
		def checkAcceptableSkew(self):
			if self.secondsSinceResponse() > self.maximumAllowableSecondsSinceResponse():
				raise CredentialsExpired
		
		def checkAcceptableAuthMethod(self):
			oldMethods = self.response.sso.split(',')
			reauthMethod = self.response.auth
			
			def haveReauthMethod():
				return reauthMethod != ''
			
			def haveOldMethod():
				return oldMethods != []
			
			def intersection( list1, list2 ):
				return [ item for item in list1 if item in list2 ]
			
			def methodsAreRestricted():
				return haveArgument('allowedMethods')
			
			def reauthMethodAllowed():
				if methodsAreRestricted():
					return reauthMethod in args['allowedMethods']
				else:
					return haveReauthMethod()
			
			def oldMethodAllowed():
				if methodsAreRestricted():
					allowedAndPresent = intersection( args['allowedMethods'], oldMethods )
					return allowedAndPresent != []
				else:
					return haveOldMethod()
			
			if not oldMethodAllowed() and not reauthMethodAllowed():
				raise NoAcceptableAuthMethod
			
			if mustReauthenticate() and not reauthMethodAllowed():
				raise DidNotReauthenticate
		
		def __init__( self, wls_response ):
			if wls_response is not None:
				self.response = RavenLL.AuthenticationResponse( wls_response, service.keys )
				
				self.checkAcceptableURL()
				self.checkAcceptableSkew()
				self.checkAcceptableAuthMethod()
			else:
				self.response = None
	
	class RavenPersistentResponse(RavenResponse):
		def checkAcceptableSkew(self):
			if self.response.life != '':
				RavenResponse.checkAcceptableSkew(self)
		
		def maximumAllowableSecondsSinceResponse(self):
			return int(self.response.life) + maximumClockSkew()
		
		def checkAcceptableAuthMethod(self):
			RavenResponse.checkAcceptableAuthMethod(self)
			if mustReauthenticate(): raise DidNotReauthenticate
	
	def redirectToRaven():
		def theTargetURL():
			if targetURL:
				return targetURL
			else:
				return thisURL
		
		argMap = { 'allowedMethods': ('aauth', lambda x: ','.join(x)),
					'targetDescription': ('desc', lambda x: x),
					'reauthenticate': ('iact', lambda x: x),
					'message': ('msg', lambda x: x),
 					'wls_response': ('wls', lambda x: ''),
					'ravenHandlesErrors': ('fail', lambda b: {True: 'yes', False: ''}[b]),
					'pageParameters': ('params', lambda x: x),
					'maximumClockSkew': ('skew', lambda x: str(x)),
					}
		
		authArgs = {}
		if haveArgument('maximumClockSkew'):
			authArgs['date'] = RavenLL.timeToRFC3339(gmtime())
		
		for argName, value in args.iteritems():
			translatedArgName, translator = argMap[argName]
			authArgs[translatedArgName] = translator(value)
		
		ravenURL = RavenLL.authenticationRequest( service.url, theTargetURL(), **authArgs )
		return ravenURL
		
	if haveArgument('wls_response'):
		wls_response_string = args['wls_response']
	else:
		wls_response_string = None
	
	httpResponse = RavenResponse( wls_response_string ).response
	if httpResponse:
		persistenceMethod.set( wls_response_string )
		return Credentials( httpResponse )
	
	try:
		persistenceResponse = RavenPersistentResponse( persistenceMethod.get() ).response
		if persistenceResponse:
			return Credentials( persistenceResponse )
	except CredentialsExpired:
		raise
	except Exception:
		pass
	
	persistenceMethod.delete()
	return {"redirect": redirectToRaven()}

class Credentials:
	def __init__(self, response):
		if response.status != '200':
			raise UnsuccessfulStatusCode
			
		self.response = response
	
	principal = property(fget = lambda self: self.response.principal)
	pageParameters = property(fget = lambda self: self.response.params)
	message = property(fget = lambda self: self.response.msg)

def wls_response():
	return None


def gmtime():
	return time.gmtime()

class NullPersistenceMethod:
	def get(self): return None
	def set(self, param): pass
	def delete(self): pass

persistenceMethod = NullPersistenceMethod()

class Service:
	def __init__(self, url, keys):
		self.url = url
		self.keys = keys

class URLMismatch(Exception):
	'''Exception'''

class CredentialsExpired(Exception):
	'''Exception'''

class NoAcceptableAuthMethod(Exception):
	'''Exception'''

class DidNotReauthenticate(Exception):
	'''Exception'''

class UnsuccessfulStatusCode(Exception):
	'''Exception'''
