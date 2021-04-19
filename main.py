import jwt
import time
import requests
import logging
import sys
import json
import http.client as http_client
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

http_client.HTTPConnection.debuglevel = 1
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True

if __name__ == '__main__':
    #
    # A simple script for using oauth with a service api. See
    #
    # Example invocation:
    #
    # /home/sa/auth.json https://www.googleapis.com/auth/cloud-billing https://cloudbilling.googleapis.com/v1/billingAccounts
    #
    # Where the first parameter is the auth json file of the service account that can be
    # downloaded when creating a service account. See:
    #
    # https://cloud.google.com/iam/docs/service-accounts
    #
    # The second parameter is the OAuth 2.0 scope of tha API to call. See:
    #
    # https://developers.google.com/identity/protocols/oauth2/scopes
    #
    # And the third parameter ist the api endpoint to call
    #
    # See also the following guide on how to user OAuth 2.0 with a service account:
    #
    # https://developers.google.com/identity/protocols/oauth2/service-account#httprest
    #
    auth_file = sys.argv[1]
    scope = sys.argv[2]
    api = sys.argv[3]

    with open(auth_file) as json_file:
        data = json.load(json_file)

    private_key_id = data['private_key_id']
    email = data['client_email']
    private_key = data['private_key']
    token_uri = data['token_uri']
    client_x509_cert_url = data['client_x509_cert_url']
    algorithm = "RS256"

    iat = time.time()
    exp = iat + 3600

    payload = {
        "iss": email,
        "aud": token_uri,
        "scope": scope,
        "exp": exp,
        "iat": iat
    }

    public_cert = requests.get(client_x509_cert_url).json()[private_key_id]
    public_key = load_pem_x509_certificate(public_cert.encode('utf-8')).public_key().public_bytes(Encoding.PEM,
                                                                                                  PublicFormat.SubjectPublicKeyInfo)

    encoded = jwt.encode(payload, private_key, algorithm=algorithm)
    decoded = jwt.decode(encoded, key=public_key, audience=payload["aud"], algorithms=[algorithm],
                         options={"verify_exp": True, "verify_signature": True})

    params = {'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer', 'assertion': encoded}
    r = requests.post(token_uri, params=params)

    ret_val = r.json()
    access_token = r.json()['access_token']

    headers = {'Authorization': f'Bearer {access_token}'}
    r = requests.get(api, headers=headers)

    print(r.json())
