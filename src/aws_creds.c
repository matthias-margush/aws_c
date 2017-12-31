#include "aws_creds.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>

/**
 * Gets the secret access key.
 */
const char *aws_creds_secret_access_key(struct AwsCreds *creds) {
    return (creds && creds->secret_access_key) ? creds->secret_access_key(creds)
                                               : NULL;
}

/**
 * Gets the access key.
 */
const char *aws_creds_access_key_id(struct AwsCreds *creds) {
    return (creds && creds->access_key_id) ? creds->access_key_id(creds) : NULL;
}

/**
 * Gets the session token.
 */
const char *aws_creds_session_token(struct AwsCreds *creds) {
    return (creds && creds->session_token) ? creds->session_token(creds) : NULL;
}

/** Static space for creds. */
static struct AwsCreds static_creds;

typedef struct AwsCreds *(*AwsCredsProvider)(struct AwsCreds *creds);

/**
 * Provides anonymous credentials.
 */
struct AwsCreds *aws_creds_provider_anonymous(struct AwsCreds *creds) {
    if (!creds)
        creds = &static_creds;
    *creds = (struct AwsCreds){.provider_name = "anonymous"};
    return creds;
}

struct AwsCredsCache {
    const char *secret_access_key;
    const char *access_key_id;
    const char *session_token;
};

/**
 * Gets the cached secret access key.
 */
const char *aws_creds_secret_access_key_cached(struct AwsCreds *creds) {
    return creds ? creds->cache.secret_access_key : NULL;
}

/**
 * Gets the cached access key.
 */
const char *aws_creds_access_key_id_cached(struct AwsCreds *creds) {
    return creds ? creds->cache.access_key_id : NULL;
}

/**
 * Gets the cached session token.
 */
const char *aws_creds_session_token_cached(struct AwsCreds *creds) {
    return creds ? creds->cache.session_token : NULL;
}

/**
 * Provides credentials from the environment:
 *   AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_SESSION_TOKEN
 */
struct AwsCreds *aws_creds_provider_env(struct AwsCreds *creds) {
    if (!creds)
        creds = &static_creds;

    const char *secret_access_key = getenv("AWS_SECRET_ACCESS_KEY");
    const char *access_key_id = getenv("AWS_ACCESS_KEY_ID");
    const char *session_token = getenv("AWS_SESSION_TOKEN");

    if (!secret_access_key && !access_key_id && !session_token) {
        return NULL;
    }

    *creds = (struct AwsCreds){.provider_name = "env",
                               .secret_access_key =
                                   aws_creds_secret_access_key_cached,
                               .access_key_id = aws_creds_access_key_id_cached,
                               .session_token = aws_creds_session_token_cached,
                               .cache = {.secret_access_key = secret_access_key,
                                         .access_key_id = access_key_id,
                                         .session_token = session_token}};
    return creds;
}

/**
 * Default credential provider chain.
 */
static const AwsCredsProvider aws_creds_provider_chain_default[] = {
    aws_creds_provider_env,
};

/**
 * Queries each provider for credentials and returns the first.
 */
struct AwsCreds *aws_creds_provided(struct AwsCreds *creds,
                                    const AwsCredsProvider provider_chain[],
                                    size_t len) {
    for (size_t i = 0; i < len; ++i) {
        AwsCredsProvider provide_creds = provider_chain[i];
        struct AwsCreds *provided = provide_creds(creds);
        if (provided) {
            return provided;
        }
    }
    return NULL;
}

/**
 * Finds credentials from the default chain of providers.
 *
 *   1. Environment variables:
 *        AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_SESSION_TOKEN
 *   2. AWS credentials file (~/.aws/credentials) (TODO)
 *   3. AWS config file (~/.aws/config) (TODO)
 *   4. Elastic Container Service credentials (TODO)
 *   5. EC2 Instance Profile credentials (TODO)
 */
struct AwsCreds *aws_creds(struct AwsCreds *creds) {
    return aws_creds_provided(creds, aws_creds_provider_chain_default,
                              sizeof(aws_creds_provider_chain_default) *
                                  sizeof(aws_creds_provider_chain_default[0]));
}
