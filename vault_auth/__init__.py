#!/usr/bin/python3
#
# The majority of this code has been "lifted" from
# https://github.com/ianunruh/hvac/pull/155/commits/81d94d9768d865358798d26e9271dd786b7ef02e
# because:
#
# a) the core hvac repo still doesn't support AWS IAM Auth and
# b) at the moment at least, ITS only needs simple secret retrieval, not the
#    whole of the hvac functionality.
#
# The ITS contribution to this code is at the end. The aim is to
# make retrieval of secrets as simple as possible, e.g.:
#
# foo = vault_auth.get_secret(
#     path,
#     iam_role="role name",
#     url="https://host:port")
# if foo is not None:
#     print(foo["data"]["pw"])
#
# The code does not cache the authentication token retrieved after performing the AWS IAM
# auth, so the token is revoked after the secret has been retrieved from Vault.


import base64
import json
import logging.handlers

import boto3
import requests

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse


vault_host = None
vault_port = None
logger = logging.getLogger(__name__)


def auth_iam(iam_role, url, debug):
    """
    Authenticate to Vault per https://www.vaultproject.io/docs/auth/aws.htm.

    :param iam_role: IAM role
    :return:
    """
    global vault_host, vault_port
    if debug:
        logger.debug("auth_iam(%s, %s)" % (iam_role, url))
    parsed = urlparse(url)
    vault_host = parsed.hostname
    vault_port = parsed.port
    return authenticate_to_vault(parsed.hostname,
                                 parsed.port,
                                 iam_role,
                                 True,
                                 debug)


def authenticate_to_vault(vault_host, vault_port, role, verify, debug):
    if debug:
        logger.debug("authenticate_to_vault(%s, %s, %s, %s)" % (
            vault_host, vault_port, role, verify))
    payload = generate_vault_request(role, vault_host, debug)

    headers = {
        'Content-type': 'application/json',
        'Accept': 'text/plain'
    }
    if debug:
        logger.debug('POST https://{}:{}/v1/auth/aws/login'.format(vault_host, vault_port))
    response = requests.post(
        'https://{}:{}/v1/auth/aws/login'.format(vault_host, vault_port),
        data=json.dumps(payload),
        headers=headers,
        verify=verify)
    if response.status_code != 200:
        raise Exception(
            "Failed to authenticate to Vault due to error {} with body {}".format(
                response.status_code, response.text))
    elif debug:
        logger.debug("Successfully authenticated to Vault")
    body = response.json()
    return body['auth']['client_token']


def generate_vault_request(role, vault_host, debug):
    """
    Generate a signed sts:GetCallerIdentity request to validate identify of
    the client. The Vault server reconstructs the query and forwards it to STS
    service to authenticate the client.

    See https://www.vaultproject.io/docs/auth/aws.html for more.

    :param role: AWS role name
    :return: Request body
    """

    client = boto3.client('sts')
    # Get the current identity so that we can extract the account details
    identity = client.get_caller_identity()
    role_arn = "arn:aws:iam::{}:role/{}".format(identity["Account"], role)
    try:
        new_identity = client.assume_role(
            RoleArn=role_arn, RoleSessionName=role)
    except Exception as e:
        raise Exception(
            "Failed to get identity for role {}".format(role_arn)) from e

    if debug:
        logger.debug("Got identity for role {}".format(role_arn))

    # Set up a new boto3 client with this identity
    client = boto3.client(
        'sts',
        aws_access_key_id=new_identity["Credentials"]["AccessKeyId"],
        aws_secret_access_key=new_identity["Credentials"]["SecretAccessKey"],
        aws_session_token=new_identity["Credentials"]["SessionToken"]
    )
    operation_model = client._service_model.operation_model(
        'GetCallerIdentity')
    request_dict = client._convert_to_request_dict({}, operation_model)
    request_dict['headers']['X-Vault-AWS-IAM-Server-ID'] = vault_host
    request = client._endpoint.create_request(request_dict, operation_model)

    return {
        'iam_http_request_method': request.method,
        'iam_request_url': bytes(
            base64.b64encode(request.url.encode('ascii'))).decode('ascii'),
        'iam_request_body': bytes(
            base64.b64encode(request.body.encode('ascii'))).decode('ascii'),
        'iam_request_headers': bytes(
            base64.b64encode(
                json.dumps(
                    prep_for_serialization(
                        dict(request.headers))).encode())).decode('ascii'),
        'role': role,
    }


def prep_for_serialization(headers):
    """
    ASCII encode each header value before serializing to JSON
    :param headers: headers
    :return: encoded headers
    """

    ret = {}
    for k, v in headers.items():
        if isinstance(v, bytes):
            ret[k] = [bytes(v).decode('ascii')]
        else:
            ret[k] = [v]
    return ret


def revoke_token(token, vault_host, vault_port, debug):
    """
    Since we aren't caching the authentication token, we need to revoke it
    after using it so that Vault doesn't fill up its database with leases.
    """
    if debug:
        logger.debug("Revoking token '%s'" % token)
    header = {
        "X-Vault-Token": token
    }
    response = requests.post(
        "https://{}:{}/v1/auth/token/revoke-self".format(vault_host, vault_port),
        headers=header)
    if response.status_code == 204:
        if debug:
            logger.debug("Successfully revoked '%s'" % token)
        return
    message = response.json()
    if "errors" in message:
        raise Exception(message["errors"][0])
    else:
        raise Exception(response.text)


def get_secret(path, token=None, iam_role=None, url=None, debug=False):
    token = auth_iam(iam_role, url, debug)
    header = {
        "X-Vault-Token": token
    }
    if debug:
        logger.debug('GET https://{}:{}/v1/{}'.format(vault_host, vault_port, path))
    response = requests.get(
        "https://{}:{}/v1/{}".format(vault_host, vault_port, path),
        headers=header)
    revoke_token(token, vault_host, vault_port, debug)
    if response.status_code == 200:
        if debug:
            logger.debug("Successfully got secret for %s" % path)
        return response.json()
    elif response.status_code == 400:
        raise Exception("Invalid request, missing or invalid data")
    elif response.status_code == 403:
        raise Exception("Forbidden to retrieve %s" % path)
    elif response.status_code == 404:
        raise Exception("Invalid path (%s)" % path)

    message = response.json()
    if "errors" in message:
        raise Exception(message["errors"][0])
    else:
        raise Exception(response.text)
