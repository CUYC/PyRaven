/*

   University of Cambridge Web Authentication System
   Application Agent for Apache 1.3 and 2
   See http://raven.cam.ac.uk/ for more details
         
   $Id: mod_ucam_webauth.c,v 1.42 2004/07/12 14:21:50 jw35 Exp $
            
   Copyright (c) University of Cambridge 2004
   See the file NOTICE for conditions of use and distribution.
                  
   Author: Robin Brady-Roche <rbr268@cam.ac.uk>, based on a mod_perl
   application agent by Jon Warbrick <jw35@cam.ac.uk>
                        
*/
                        
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include <string.h>

/* aaaack but it's fast and const should make it shared text page. */
static const unsigned char pr2six[256] =
{
    /* ASCII table */
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};


static int ap_base64decode_len(const char *bufcoded)
{
    int nbytesdecoded;
    register const unsigned char *bufin;
    register int nprbytes;

    bufin = (const unsigned char *) bufcoded;
    while (pr2six[*(bufin++)] <= 63);

    nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    return nbytesdecoded + 1;
}

static int ap_base64decode_binary(unsigned char *bufplain,
                                   const char *bufcoded)
{
    int nbytesdecoded;
    register const unsigned char *bufin;
    register unsigned char *bufout;
    register int nprbytes;

    bufin = (const unsigned char *) bufcoded;
    while (pr2six[*(bufin++)] <= 63);
    nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    bufout = (unsigned char *) bufplain;
    bufin = (const unsigned char *) bufcoded;

    while (nprbytes > 4) {
        *(bufout++) =
            (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
        *(bufout++) =
            (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
        *(bufout++) =
            (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
        bufin += 4;
        nprbytes -= 4;
    }

    /* Note: (nprbytes == 1) would be an error, so just ingore that case */
    if (nprbytes > 1) {
        *(bufout++) =
            (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
    }
    if (nprbytes > 2) {
        *(bufout++) =
            (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
    }
    if (nprbytes > 3) {
        *(bufout++) =
            (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
    }

    nbytesdecoded -= (4 - nprbytes) & 3;
    return nbytesdecoded;
}

static int ap_base64decode(char *bufplain, const char *bufcoded)
{
    int len;
    
    len = ap_base64decode_binary((unsigned char *) bufplain, bufcoded);
    bufplain[len] = '\0';
    return len;
}

static int
wls_decode(
	   char *string,
	   unsigned char **result)
     
{
  int len, i;  
  char *d, *res;

  d = strdup(string);

  for (i = 0; i < strlen(d); i++) {
    if (d[i] == '-') d[i] = '+';
    else if (d[i] == '.') d[i] = '/';
    else if (d[i] == '_') d[i] = '=';
  }

  res = malloc(1+ap_base64decode_len(d));
  len = ap_base64decode(res, d);

  res[len] = '\0'; /* for safety if nothing else */

  *result = (unsigned char *)res;
  return len;
}

int 
RSA_sig_verify(
	       char *data, 
	       char *sig, 
	       char *key_path) 

{

  /* RETURNS
      -1 : verification error
       0 : Unsuccessful verification
       1 : successful verification
       2 : error opening public key file
       3 : error reading public key */

  unsigned char* decoded_sig;
  int sig_length;
  int result;
  char *key_full_path;
  FILE *key_file;
  char *digest = malloc(21);
  RSA *public_key;
  int openssl_error;

  key_full_path = key_path;

  SHA1((const unsigned char *)data, strlen(data), (unsigned char *)digest);
  
  key_file = (FILE *)fopen(key_full_path, "r");
  
  if (key_file == NULL) {
    return 2;
  }

  public_key = (RSA *)PEM_read_RSAPublicKey(key_file, NULL, NULL, NULL);

  fclose(key_file);
  
  if (public_key == NULL) return 3;

  sig_length = wls_decode(sig, &decoded_sig);

  result = RSA_verify(NID_sha1, 
		      (unsigned char *)digest, 
		      20, 
		      decoded_sig, 
		      sig_length, 
		      public_key);
  
  RSA_free(public_key);
  
  return result;

}
