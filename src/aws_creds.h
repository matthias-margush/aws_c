#ifndef AWS_CREDS_H
#define AWS_CREDS_H

struct AwsCreds {
    const char *provider_name;
    const char *(*secret_access_key)(struct AwsCreds *);
    const char *(*access_key_id)(struct AwsCreds *);
    const char *(*session_token)(struct AwsCreds *);
	struct {
		const char *secret_access_key;
		const char *access_key_id;
		const char *session_token;
	} cache;
};

/**
 * Finds credentials from a chain of providers.
 *
 *   1. Environment variables:
 *        AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_SESSION_TOKEN
 *   2. AWS credentials file (~/.aws/credentials)
 *   3. AWS config file (~/.aws/config)
 *   4. Elastic Container Service credentials
 *   5. EC2 Instance Profile credentials
 *
 * The output is placed in creds. If creds is NULL, static storage is used.
 * Example:
 *   ```
 *   struct AwsCreds creds = {};
 *   aws_creds(creds);
 *   ```
 *
 * @returns Aws credentials 
 */
struct AwsCreds *aws_creds(struct AwsCreds *creds);

/**
 * Gets the secret access key.
 */
const char *aws_creds_secret_access_key(struct AwsCreds *);

/**
 * Gets the access key.
 */
const char *aws_creds_access_key_id(struct AwsCreds *);

/**
 * Gets the session token.
 */
const char *aws_creds_session_token(struct AwsCreds *);

#endif
