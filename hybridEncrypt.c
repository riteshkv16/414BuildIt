#include <stdio.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>

int file_to_string_new(char* file_name, unsigned char* text){
	long length;
	FILE * f = fopen(file_name, "rb");
	if (f) {
		fseek (f, 0, SEEK_END);
		length = ftell (f);
		fseek (f, 0, SEEK_SET);
        if (text == NULL){
            return length;
        } else {
            fread (text, 1, length, f);
        }
		fclose (f);
	} else {
        return -1;
    }
	return 0;
}
EVP_PKEY* get_public_key(char* file_name){
	EVP_PKEY* pKey  = NULL;
	FILE* pFile = NULL;
	if((pFile = fopen(file_name,"rt")) && (pKey = PEM_read_PUBKEY(pFile,NULL,NULL,NULL))){
		//printf("Public key read.\n");
	} else {
		//printf("Cannot read \"pubkey.pem\".\n");
		return NULL;
	}
	return pKey;
}
EVP_PKEY* get_private_key(char* file_name){
	EVP_PKEY* pKey  = NULL;
	FILE* pFile = NULL;
	if((pFile = fopen(file_name,"rt")) && (pKey = PEM_read_PrivateKey(pFile,NULL,NULL,NULL))){
		//printf("Private key read.\n");
	} else {
		//printf("Cannot read \"privatekey.pem\".\n");
		return NULL;
	}
	return pKey;
}
int evp_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext){
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        return -1;

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        return -1;
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        return -1;
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}
int evp_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext){
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        return -1;

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        return -1;
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        return -1;
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int mode_e(char* pubkey_file, char* input_file){
    /* generate a 256 bit symmetric key */
	unsigned char symm_key[32];
	int rc = RAND_bytes(symm_key, sizeof(symm_key));
	if(rc != 1) return 2;
    int plaintext_len = file_to_string_new(input_file, NULL);
    if (plaintext_len == -1) return 2;
    unsigned char plaintext [plaintext_len];
    plaintext_len = file_to_string_new(input_file, plaintext);
    if (plaintext_len == -1) return 2;

    /**************************************/
    // Authenticated Encryption 
    /**************************************/
    /* a hardcoded 128 bit IV */
    unsigned char *iv = (unsigned char *)"0123456789012345";
	/* Encrypt the plaintext */
    int c_msg_len;
	unsigned char c_msg[(strlen(plaintext) / 16 + 1) * 16];
    c_msg_len = evp_encrypt(plaintext, strlen ((char *)plaintext), symm_key, iv, c_msg);
    if (c_msg_len == -1) return 2;
    
    /**************************************/
    // Asymmetric Encryption 
    /**************************************/
    int ret;
    EVP_PKEY* public_evp_key = get_public_key(pubkey_file);
    if (public_evp_key == NULL) return 2;
    
    EVP_PKEY_CTX *ctx = NULL;
    size_t symm_key_len = sizeof(symm_key);
    size_t out_len;
    ctx = EVP_PKEY_CTX_new(public_evp_key, NULL);
    if (ctx == NULL) {
        //printf("EVP_PKEY_CTX_new failed\n");
        return 2;
    }
    ret = EVP_PKEY_encrypt_init(ctx);
    if (ret < 0) {
        //printf("ras_pubkey_encrypt failed to EVP_PKEY_encrypt_init. ret = %d\n", ret);
        return 2;
    }
    ret = EVP_PKEY_encrypt(ctx, NULL, &out_len, symm_key, symm_key_len);
    if (ret < 0) {
        //printf("ras_pubkey_encrypt failed to EVP_PKEY_encrypt. ret = %d\n", ret);
        return 2;
    }
	size_t c_key_len = out_len;
	unsigned char c_key[c_key_len];
	ret = EVP_PKEY_encrypt(ctx, c_key, &c_key_len, symm_key, symm_key_len);
    if (ret < 0) {
        //printf("ras_pubkey_encrypt failed to EVP_PKEY_encrypt. ret = %d\n", ret);
        return 2;
    }
    unsigned char payload[c_key_len + c_msg_len];
	for (int i = 0; i < c_key_len; i ++){
        payload[i] = c_key[i];
	}
	for (int i = 0; i < c_msg_len; i ++){
        payload[i+c_key_len] = c_msg[i];
	}
    int payload_len = c_key_len + c_msg_len;
    fwrite(payload, 1, payload_len, stdout);
    return 0;
}
int mode_d(char* prikey_file, char* input_file){
    int payload_len = file_to_string_new(input_file, NULL);
    if (payload_len == -1) return 2;
    unsigned char payload [payload_len];
    payload_len = file_to_string_new(input_file, payload);

    size_t c_key_len_2 = 256;
    unsigned char c_key_2 [c_key_len_2];
    memcpy(c_key_2, payload, c_key_len_2);

    size_t c_msg_len_2 = sizeof(payload) - 256;
    unsigned char c_msg_2 [c_msg_len_2];
    memcpy(c_msg_2, payload+256, c_msg_len_2);

    /**************************************/
    // Asymmetric Decryption 
    /**************************************/
    int ret;
    EVP_PKEY* private_evp_key = get_private_key(prikey_file);
    if (private_evp_key == NULL) return 2;
    EVP_PKEY_CTX *ctx = NULL;
    size_t out_len;
    ctx = EVP_PKEY_CTX_new(private_evp_key, NULL);
    if (ctx == NULL) {
        //printf("EVP_PKEY_CTX_new failed\n");
    	return 2;
    }
    ret = EVP_PKEY_decrypt_init(ctx);
    if (ret != 1) {
        //printf("rsa_private_key decrypt failed to EVP_PKEY_decrypt_init. ret = %d\n", ret);
        return 2;
    }
    ret = EVP_PKEY_decrypt(ctx, NULL, &out_len, c_key_2, c_key_len_2);
    if (ret != 1) {
        //printf("rsa_prikey_decrypt failed to EVP_PKEY_decrypt. ret = %d\n", ret);
        return 1;
    }
	size_t s_key_len = out_len;
	unsigned char s_key[s_key_len];
	ret = EVP_PKEY_decrypt(ctx, s_key, &s_key_len, c_key_2, c_key_len_2);
    if (ret != 1) {
        //printf("rsa_prikey_decrypt failed to EVP_PKEY_decrypt. ret = %d\n", ret);
        return 1;
    }

    /**************************************/
    // Authenticated Decryption 
    /**************************************/
    /* a hardcoded 128 bit IV */
    unsigned char *iv = (unsigned char *)"0123456789012345";
	/* Decrypt the plaintext */
    int s_msg_len;
	unsigned char s_msg[sizeof(c_msg_2)];
    s_msg_len = evp_decrypt(c_msg_2, sizeof(c_msg_2), s_key, iv, s_msg);
    if (s_msg_len == -1) return 2;

    /* Add a NULL terminator. We are expecting printable text */
    s_msg[s_msg_len-3] = '\0';
    printf("%s\n", s_msg);
    return 0;
}
int main (int argc, char* argv[]){
    int ret;
	if (argc == 4){
        if (strcmp(argv[1],"e") == 0){
			ret = mode_e(argv[2], argv[3]);
		} else if (strcmp(argv[1],"d") == 0){
            ret = mode_d(argv[2], argv[3]);
		} else {
			printf("Invalid mode.");
            ret = 2;
		}
	} else {
		printf("Invalid number of arguements.\n");
        ret = 2;
	}
    return ret; 
}