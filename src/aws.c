#include <curl/curl.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <string.h>
#include <aws_creds.h>

void curl_example(void) {
    CURL *curl;
    CURLcode res;

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, "http://www.google.com/");
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        printf("Curl failed: %d\n", res);
    }
    curl_easy_cleanup(curl);
    curl_global_cleanup();
}

void log_hex(unsigned char *m, unsigned int len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02X", m[i]);
    }
}

unsigned char *aws_sig_v4(const char *const secret_access_key,
                          const char *const aws_region,
                          const char *const aws_service,
                          const char *const request, unsigned char *md,
                          unsigned int *md_len);

int main(void) {
	struct AwsCreds creds;
	aws_creds(&creds);
	
	printf("secret_access_key: %s\n", aws_creds_secret_access_key(&creds));
	printf("access_key: %s\n", aws_creds_access_key_id(&creds));


    //unsigned char md[EVP_MAX_MD_SIZE];

    //aws_sig_v4("yolo-secret-key", NULL, NULL, NULL, md, EVP_MAX_MD_SIZE);
    return 0;
}
