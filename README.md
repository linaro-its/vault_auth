# Vault Auth

This code is primarily derived from work done by [s3u](https://github.com/s3u) to provide functionality currently missing from [HVAC](https://github.com/ianunruh/hvac) to support AWS IAM Auth.

The code has been pulled out of the initial [PR](https://github.com/ianunruh/hvac/pull/155) and simplified to meet the core use of Vault by Linaro ITS, namely the retrieval of secrets.

## Installation

`pip install git+https://github.com/linaro-its/vault_auth.git`

## Usage

    import vault_auth

    secret = vault_auth.get_secret(
        "path to secret",
        iam_role="role name",
        url="https://vault_host:port"
    )

This returns the JSON data from Vault, allowing the data to be accessed thus:

    password = secret["data]["pw]

or whatever the key is.

The role name is assumed prior to building the response for Vault. This allows a script to be written to use a single IAM role regardless of where it is being run from. The IAM role can be configured to be assumed by the desired IAM instance role or by the role of a script tester/author.

`vault_auth` caches the authentication token and host details so subsequent calls can be simplified thus:

    different_secret = vault_auth.get_secret(
       "path to different secret"
    )
