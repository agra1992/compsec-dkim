/*
 * sudo apt-get install libssl-dev *
 * gcc <filename>.c -Wall -lcrypto -o sha
 * ./sha
 * rsacrypt.c
 *  RSA Encrypt/Decrypt & Sign/Verify Test Program for OpenSSL
 *  wrtten by blanclux
 *  This software is distributed on an "AS IS" basis WITHOUT WARRANTY OF ANY KIND.
 */
#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <time.h>

#define KEYBIT_LEN	2048

static void
printHex(const char *title, const unsigned char *s, int len)
{
	int     n;
	printf("%s:", title);
	for (n = 0; n < len; ++n) {
		if ((n % 16) == 0) {
			printf("\n%04x", n);
		}
		printf(" %02x", s[n]);
	}
	printf("\n");
}
/*
static void display_file(const char *file_name)
{
    FILE *f = fopen(file_name, "r");      // open the specified file
    if (f != NULL)
    {
        int c;

        while ((c = fgetc(f)) != EOF)     // read character from file until EOF
        {
            putchar(c);                   // output character
        }
        fclose(f);
    }
}
*/
/*
int
doCrypt(RSA *prikey, RSA *pubkey, unsigned char *data, int dataLen)
{
	int     i;
	int     encryptLen, decryptLen;
	unsigned char encrypt[1024], decrypt[1024];

	 encrypt 
	encryptLen = RSA_public_encrypt(dataLen, data, encrypt, pubkey,
									RSA_PKCS1_OAEP_PADDING);
* print data 
	printHex("ENCRYPT", encrypt, encryptLen);
	printf("Encrypt length = %d\n", encryptLen);

	 decrypt 
	decryptLen = RSA_private_decrypt(encryptLen, encrypt, decrypt, prikey,
									 RSA_PKCS1_OAEP_PADDING);
	printHex("DECRYPT", decrypt, decryptLen);
	if (dataLen != decryptLen) {
		return 1;
	}
	for (i = 0; i < decryptLen; i++) {
		if (data[i] != decrypt[i]) {
			return 1;
		}
	}

	return 0;
}
*/
int
doSign(RSA *prikey, RSA *pubkey, unsigned char *data, int dataLen)
{
	unsigned char hash[SHA_DIGEST_LENGTH];
	unsigned char sign[256];
	unsigned int signLen;
	int     ret;

	SHA(data, dataLen, hash);

	/* Sign */
	//Sign the message digest hash wtih RSA private key of length 2048 bits
	
	ret = RSA_sign(NID_sha1, hash, SHA_DIGEST_LENGTH, sign,
				   &signLen, prikey);
	printHex("SIGN", sign, signLen);
	printf("Signature length = %d\n", signLen);
	printf("RSA_sign: %s\n", (ret == 1) ? "OK" : "NG");

	/* Verify 
	ret = RSA_verify(NID_sha1, hash, SHA_DIGEST_LENGTH, sign,
					 signLen, pubkey);
	printf("RSA_Verify: %s\n", (ret == 1) ? "true" : "false");
    */
	return ret;
}

int
main()
{
    
    //~~~~~~~~~~~Beginning clock execution~~~~~~~~~~~~~~
    clock_t begin, end;
    double time_spent;
    
    begin = clock();
    //~~~~~~~~~~~Beginning clock execution~~~~~~~~~~~~~~
    
	int     ret;
	char   *text;
	
	FILE *fp;
    long lSize;
    char *buffer;
    
    fp = fopen ( "msg10.eml" , "rb" );
    //if( !fp ) perror("msg4.eml"),exit(1);
    
    fseek( fp , 0L , SEEK_END);
    lSize = ftell( fp );
    rewind( fp );
    
    /* allocate memory for entire content */
    buffer = calloc( 1, lSize+1 );
    if( !buffer ) fclose(fp),fputs("memory alloc fails",stderr),exit(1);
    
    /* copy the file into the buffer */
    if( 1!=fread( buffer , lSize, 1 , fp) )
      fclose(fp),free(buffer),fputs("entire read fails",stderr),exit(1);
    
    /* do your work here, buffer is a string contains the whole text */
    
    fclose(fp);
    free(buffer);
	
	text=buffer;
	//Extracted the values, now printing the original plain text:
	//printf("Printing original plaintext:\n");
	//display_file("msg4.eml");
	printf("\n");
	RSA    *prikey, *pubkey;
	unsigned char *data;
	unsigned int dataLen;
	char   *p, *q, *n, *e, *d;
	char    errbuf[2048];
	FILE   *priKeyFile;

	data = (unsigned char *) text;
	dataLen = strlen(text);

	ERR_load_crypto_strings();

	/* generate private key & public key */
	printf("< RSA Key Generation >\n");
	prikey = RSA_generate_key(KEYBIT_LEN, RSA_F4, NULL, NULL);
	if (prikey == NULL) {
		printf("RSA_generate_key: err = %s\n",
			   ERR_error_string(ERR_get_error(), errbuf));
		return 1;
	}
	priKeyFile = fopen("rsaprivatekey2048.pem", "w");
	if (priKeyFile == NULL)	{
		perror("failed to fopen");
		return 1;
	}
	p = BN_bn2hex(prikey->p);
	q = BN_bn2hex(prikey->q);
	n = BN_bn2hex(prikey->n);
	e = BN_bn2hex(prikey->e);
	d = BN_bn2hex(prikey->d);
	printf("p = 0x%s\n", p);
	printf("q = 0x%s\n", q);
	printf("n = 0x%s\n", n);
	printf("e = 0x%s\n", e);
	printf("d = 0x%s\n", d);

	/* write private key to file (PEM format) */
	if (PEM_write_RSAPrivateKey(priKeyFile, prikey, NULL, NULL, 0,
								NULL, NULL) != 1) {
		printf("PEM_write_RSAPrivateKey: err = %s\n",
			   ERR_error_string(ERR_get_error(), errbuf));
		return 1;
	}

	/* copy public keys */
	pubkey = RSA_new();
	BN_hex2bn(&(pubkey->e), e);
	BN_hex2bn(&(pubkey->n), n);

	/* encrypt & decrypt 
	printf("\n< RSA Encrypt/Decrypt >\n");
	printHex("PLAIN", data, dataLen);

	ret = doCrypt(prikey, pubkey, data, dataLen);
	if (ret != 0) {
		printf("Encrypt/Decrypt Error.\n");
		return ret;
	}
    */
	printf("\n< RSA Sign with 2048 PriKey and SHA1 >\n");
	ret = doSign(prikey, pubkey, data, dataLen);
	if (ret != 1) {
		printf("Sign/Verify Error.\n");
		return ret;
	}

	RSA_free(prikey);
	RSA_free(pubkey);
	OPENSSL_free(p);
	OPENSSL_free(q);
	OPENSSL_free(n);
	OPENSSL_free(e);
	OPENSSL_free(d);
	fclose(priKeyFile);

    //~~~~~~~~~~~~~~~~Ending clock execution~~~~~~~~~~~~ 
    end = clock();
    time_spent = (double)(end - begin) / CLOCKS_PER_SEC * 1000;
    printf("Elapsed time:\n%f", time_spent);
    printf(" milliseconds\n");
	return 0;
}
