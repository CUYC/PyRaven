import unittest

from metapaw.__RavenRSAVerify import verifyRSASignature

class TestRavenRSAVerify(unittest.TestCase):
	
	def setUp( self ):
		pass
	
	def testGoodSignatures( self ):
		data = '1!200!!20040816T192420Z!1092684260-1402-5!http://mnementh.csi.cam.ac.uk/raven-test/open/document1.html!teh30!pwd!!900!'
		signature = 'k.gWC47ImDAMpnARKNyAdOYP4ueCh8aSLgIH4C7gHAu.6uxe6O3aJFkxWRz7fJxM6EadhejOPuCKwfddrmw0mssLUC08lu5W6QBvOemaIqzWcjnGZYcjHeRzMOZ4EVzrgXQuBBGlsmzNGCxKlgX3ElVRmFaHX3oL7nAyzZC2Zgo_'
		
		assert( verifyRSASignature('test_keys/pubkey1',data,signature) )
		
		data = '1!200!!20040731T184543Z!1091299543-22311-3!http://mnementh.csi.cam.ac.uk/raven-test/open/document1.html!teh30!pwd!!900!'
		signature = 'ETd0EshgkpF8DlcwTju02sVgLqgkR3J3U8Dyax1Ki1YiUB9432Wi1g6zOTe64ucHCR5fGa3.VUCEImQIT6Bg8NxnG2hWO52kNA7CX5ucXlXtpLvP7CMmbqyUNOUx51HWgO8WuwfJA06LosaduAYmLhCYfY5HxIzDs5mOlv3i7no_'
		
		assert( verifyRSASignature('test_keys/pubkey1',data,signature) )
	
	def testBadSignatures( self ):
		data = '1!200!mangle!20040816T192420Z!1092684260-1402-5!http://mnementh.csi.cam.ac.uk/raven-test/open/document1.html!teh30!pwd!!900!'
		signature = 'k.gWC47ImDAMpnARKNyAdOYP4ueCh8aSLgIH4C7gHAu.6uxe6O3aJFkxWRz7fJxM6EadhejOPuCKwfddrmw0mssLUC08lu5W6QBvOemaIqzWcjnGZYcjHeRzMOZ4EVzrgXQuBBGlsmzNGCxKlgX3ElVRmFaHX3oL7nAyzZC2Zgo_'
		
		assert( not verifyRSASignature('test_keys/pubkey1',data,signature) )
		
		data = '1!200!!20040731T184543Z!1091299543-22311-3!http://mnementh.csi.cam.ac.uk/raven-test/open/document1.html!teh30!pwd!!900!'
		signature = 'ETd0EshmanglelcwTju02sVgLqgkR3J3U8Dyax1Ki1YiUB9432Wi1g6zOTe64ucHCR5fGa3.VUCEImQIT6Bg8NxnG2hWO52kNA7CX5ucXlXtpLvP7CMmbqyUNOUx51HWgO8WuwfJA06LosaduAYmLhCYfY5HxIzDs5mOlv3i7no_'
		
		assert( not verifyRSASignature('test_keys/pubkey1',data,signature) )

	def testFailsWithoutKeyFile( self ):
		self.assertRaises( IOError, verifyRSASignature, 'test_keys/no file here', 'anything', 'anything' )

	def testFailsWithBadKeyFile( self ):
		self.assertRaises( IOError, verifyRSASignature, 'test_keys/invalidKey', 'anything', 'anything' )

if __name__ == '__main__':
	unittest.main()
