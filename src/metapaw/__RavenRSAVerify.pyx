# RSA key verification stuff

cdef extern from *:
	int RSA_sig_verify(char *, char *, char *)

class KeyFileNotFound:
	'''Exception'''

class KeyFileNotOpened:
	'''Exception'''

def verifyRSASignature( filename, data, signature ):
	VerificationFailed = 0
	VerificationSucceeded = 1
	KeyFileNotFound = 2
	KeyFileReadError = 3

	result = RSA_sig_verify( data, signature, filename )

	if result == VerificationSucceeded:
		return True
	elif result == VerificationFailed:
		return False
	elif result == KeyFileNotFound:
		raise IOError("[Errno 2] No such file or directory: '%s'" % filename)
	elif result == KeyFileReadError:
		raise IOError("Error reading file: '%s'" % filename)
	else:
		raise AssertionError("Unexpected result from RSA_sig_verify: %d" % result)
