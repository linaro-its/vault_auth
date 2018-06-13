# Vault Auth

This code is primarily derived from work done by [s3u](https://github.com/s3u) to provide functionality currently missing from [HVAC](https://github.com/ianunruh/hvac) to support AWS IAM Auth.

The code has been pulled out of the initial [PR](https://github.com/ianunruh/hvac/pull/155) and simplified to meet the core use of Vault by Linaro ITS, namely the retrieval of secrets.

## Installation

`pip install git+https://github.com/linaro-its/vault_auth.git`

or, if using pipenv:

`pipenv install git+https://github.com/linaro-its/vault_auth.git#egg=vault_auth`

## Principles

The majority of uses of this code will be by scripts running on AWS EC2 instances. As a result, IAM instance roles will be used to link to Vault policies.

To simplify authentication for scripts running in different places (e.g. on multiple instances or on developer systems), the role name specified in the call to `get_secret` is *assumed* prior to creating the signed response for Vault. This allows roles to be associated with the script itself rather than the instance the script is running on.


## Usage

    import vault_auth

    secret = vault_auth.get_secret(
        "path to secret",
        iam_role="role name",
        url="https://vault_host:port"
    )

This returns the JSON data from Vault, allowing the data to be accessed thus:

    password = secret["data]["pw]

or whatever the key used to hold the secret that is being retrieved.

`vault_auth` caches the authentication token and host details so subsequent calls can be simplified thus:

    different_secret = vault_auth.get_secret(
       "path to different secret"
    )
