#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tee_client_api.h>
#include <TEEencrypt_ta.h>

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char plaintext[300] = {0,};
	char ciphertext[300] = {0,};
	int len=300;

	char enc_key[300] = {0,};

	FILE *fp;

	res = TEEC_InitializeContext(NULL, &ctx);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INOUT,
					 TEEC_NONE, TEEC_NONE);


	if(!strcmp(argv[1], "-e"))
	{
		printf("========================Encryption========================\n");
		fp = fopen(argv[2], "r");
        	fgets(plaintext, sizeof(plaintext), fp);
        	fclose(fp);
    		
		op.params[0].tmpref.buffer = plaintext;
		op.params[0].tmpref.size = len;
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, &err_origin);

		memcpy(ciphertext, op.params[0].tmpref.buffer, len);
		
		fp = fopen(argv[2], "w");
        	fputs(ciphertext, fp);
        	fclose(fp);

		fp = fopen("enc_key.txt", "w");
		sprintf(enc_key, "%d", op.params[1].value.a);
        	fputs(enc_key, fp);
        	fclose(fp);

		printf("Ciphertext : %s\n", ciphertext);
	}
	else if(!strcmp(argv[1], "-d"))
	{
		printf("========================Decryption========================\n");
		fp = fopen(argv[2], "r");
        	fgets(ciphertext, sizeof(ciphertext), fp);
        	fclose(fp);

		fp = fopen(argv[3], "r");
        	fgets(enc_key, sizeof(enc_key), fp);
        	fclose(fp);

		op.params[0].tmpref.buffer = ciphertext;
		op.params[0].tmpref.size = len;
		op.params[1].value.a = atoi(enc_key);

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op, &err_origin);

		memcpy(plaintext, op.params[0].tmpref.buffer, len);

		fp = fopen(argv[2], "w"); 
        	fputs(plaintext, fp);
        	fclose(fp);
		printf("Plaintext : %s\n", plaintext);

	}
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}

