#include "aws_creds.h"
#include <openssl/hmac.h>
#include <string.h>
#include <time.h>

char *v4_key(const char *const secret_access_key) {
	char *key = malloc(strlen("AWS4") + strlen(secret_access_key));
	if (!key) {
		return NULL;
	}
	strcpy(key, "AWS4");
	strcat(key, secret_access_key);
	return key;
}

void now_yyyymmdd(char (*date)[9]) {
	struct tm tm;
	time_t now = time(NULL);
	gmtime_r(&now, &tm);
	strftime(*date, 9, "YYYYMMDD", &tm);
}

unsigned char *hmac(const char *const key, const char *const data,
                    unsigned char *md, unsigned int *md_len) {
	return HMAC(EVP_sha256(), key, strlen(key), (unsigned char *)data,
	            strlen(data), md, md_len);
}

unsigned char *aws_sig_v4(struct AwsCreds *creds,
                          const char *const aws_region,
                          const char *const aws_service,
                          const char *const request, unsigned char *md,
                          unsigned int *md_len) {
	char *key = v4_key(aws_creds_secret_access_key(creds));
	if (!key) {
		return NULL;
	}
	char date[9];
	now_yyyymmdd(&date);
	unsigned char *ret = hmac(key, date, md, md_len);
	free(key);
	return ret;
}
