from functools import cached_property, wraps
import json
import binascii
import socket
from urllib import response
import yaml
import nacl.encoding
import nacl.signing
import nacl.secret
import nacl.exceptions
from nacl.public import PrivateKey, PublicKey, Box
import requests
from urllib3.exceptions import InsecureRequestWarning
from collections import OrderedDict

class LoginException(BaseException):
    pass

class DatastoreException(BaseException):
    pass

class DatastoreDecryptionException(DatastoreException):
    pass

class DatastoreSameTypeException(DatastoreException):
    pass

class PsonoApiError(BaseException):
    def __init__(self, message, response):
        self.message = message
        self.response = response

def force_session(method):
    @wraps(method)
    def wrapper(self, *args, **kwargs):
        if self._token is None:
            self._create_session()
        return method(self, *args, *kwargs)
    return wrapper

class PsonoClient():

    @staticmethod
    def get_device_description():
        """
        This info is later shown in the "Open sessions" overview in the client.
        Should be something so the user knows where this session is coming from.

        :return:
        :rtype:
        """
        return 'Console Client ' + socket.gethostname()

    @property
    def _session_secret_key(self):
        return self._login_info.get('session_secret_key', None) if self._login_info else None

    @property
    def _token(self):
        return self._login_info.get('token', None) if self._login_info else None

    def verify_cert(self, state=True):
        self._verify_cert = state
        if not state:
            requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
            self._verify_default_ciphers = requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS
            requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':@SECLEVEL=0'
        elif getattr(self, '_verify_default_ciphers', None) is not None:
            requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = self._verify_default_ciphers

    def _api(self, method, request, data = None, raw = False):
        """
        API Request helper that will also automatically decrypt the content if a session secret was provided.
        Will return the decrypted content.

        :param method:
        :type method:
        :param request:
        :type request:
        :param data:
        :type data: dict, list

        :return:
        :rtype:
        """

        headers = {
            'content-type': 'application/json'
        }
        if self._token:
            headers['authorization'] = f'Token {self._token}'

        # FIXME Use proper method to combine self._endpoint and request
        response = requests.request(
            method,
            self._endpoint + request,
            json=data,
            headers=headers,
            verify=self._verify_cert,
            cert=self._client_cert
        )

        if not response.ok:
            raise PsonoApiError(
                message=f'The server answered with: {response.status_code} {response.text}',
                response=response
            )
        elif (not self._session_secret_key) or raw:
            return response.json()
        else:
            encrypted_content = response.json()
            decrypted_content = self._decrypt_symmetric(
                encrypted_content['text'],
                encrypted_content['nonce'],
                self._session_secret_key
            )
            return json.loads(decrypted_content)

    @staticmethod
    def _decrypt_symmetric(text_hex, nonce_hex, secret):
        """
        Decryts an encrypted text with nonce with the given secret

        :param text_hex:
        :type text_hex:
        :param nonce_hex:
        :type nonce_hex:
        :param secret:
        :type secret:
        :return:
        :rtype:
        """

        text = nacl.encoding.HexEncoder.decode(text_hex)
        nonce = nacl.encoding.HexEncoder.decode(nonce_hex)

        secret_box = nacl.secret.SecretBox(secret, encoder=nacl.encoding.HexEncoder)

        return secret_box.decrypt(text, nonce)

    def _decrypt_with_api_secret_key(self, secret_hex, secret_nonce_hex):
        """
        take anything that is encrypted with the api keys secret and decrypts it. e.g. the users secret and private key

        :param secret_hex:
        :type secret_hex:
        :param secret_nonce_hex:
        :type secret_nonce_hex:

        :return:
        :rtype:
        """

        return self._decrypt_symmetric(
            secret_hex,
            secret_nonce_hex,
            self._api_key_secret_key
        )

    @cached_property
    @force_session
    def datastores(self):
        """
        Reads all datastores

        :param token:
        :type token:
        :param session_secret_key:
        :type session_secret_key:
        :return:
        :rtype:
        """

        method = 'GET'
        endpoint = '/datastore/'

        datastores = {}

        for datastore in self._api(method, endpoint).get('datastores', []):
            if datastore['type'] in datastores:
                raise DatastoreSameTypeException('Got multiple datastore of the same type. Can not handle this.')
            if datastore['is_default']:
                datastores[datastore['type']] = datastore

        return datastores

    def _decrypt_datastore(self, datastore):
        """
        Reads all datastores

        :param token:
        :type token:
        :param session_secret_key:
        :type session_secret_key:
        :return:
        :rtype:
        """

        if not self.unrestricted_access:
            raise DatastoreDecryptionException("Decryption of datastore not possible with restrictions to secrets.")

        method = 'GET'
        endpoint = f"/datastore/{datastore['id']}/"

        datastore_encrypted = self._api(method, endpoint)

        datastore_secret_key = self._decrypt_symmetric(
            datastore_encrypted['secret_key'],
            datastore_encrypted['secret_key_nonce'],
            self._user_secret_key
        ).decode()

        return json.loads(
            self._decrypt_symmetric(
                datastore_encrypted['data'],
                datastore_encrypted['data_nonce'],
                datastore_secret_key
            ).decode()
        )

    @cached_property
    def users(self):
        return self._decrypt_datastore(self.datastores['user'])['items']

    @cached_property
    def settings(self):
        return self._decrypt_datastore(self.datastores['settings'])

    @cached_property
    def passwords(self):
        return self._decrypt_datastore(self.datastores['password'])

    @property
    @force_session
    def insecure_access(self):
        if self._login_info is None:
            raise LoginException()
        return self._login_info.get('api_key_allow_insecure_access')

    @property
    @force_session
    def read_access(self):
        if self._login_info is None:
            raise LoginException()
        return self._login_info.get('api_key_read')

    @property
    @force_session
    def write_access(self):
        if self._login_info is None:
            raise LoginException()
        return self._login_info.get('api_key_write')

    @property
    @force_session
    def unrestricted_access(self):
        if self._login_info is None:
            raise LoginException()
        return not self._login_info.get('api_key_restrict_to_secrets')

    @cached_property
    def _user_secret_key(self):
        if self.unrestricted_access:
            return self._decrypt_with_api_secret_key(
                self._login_info['user']['secret_key'],
                self._login_info['user']['secret_key_nonce']
            ).decode()
        else:
            return None

    @property
    def server_info(self):
        return self._server_info

    def _clear(self):
        try:
            del self._user_secret_key
            del self.datastores
            del self.user
            del self.settings
            del self.passwords
        except AttributeError:
            pass
        self._login_info = None

    def logout(self):
        #TODO
        self._clear()

    def _verify_signature(self, text, signature_hex):
        if self._server_signature_verify_key is not None:
            self._server_signature_verify_key.verify(
                text.encode(),
                binascii.unhexlify(signature_hex)
            )
        return True

    def login(self, endpoint, api_key_id, api_key_private_key, api_key_secret_key, client_cert_key=None, client_cert_crt=None, server_signature=None):
        """
        API Request: Sends the actual login

        :return:
        :rtype:
        """

        self._clear()

        self._endpoint = endpoint
        self._api_key_id = api_key_id
        self._api_key_secret_key = api_key_secret_key
        self._api_key_signing_box = nacl.signing.SigningKey(api_key_private_key, encoder=nacl.encoding.HexEncoder)

        if client_cert_key or client_cert_crt:
            self._client_cert = (
                client_cert_crt,
                client_cert_key
            )
        else:
            self._client_cert = None

        if server_signature is not None:
            # Validate with the help of server_signature. Will raise an exception if it does not match.
            self._server_signature_verify_key = nacl.signing.VerifyKey(server_signature, encoder=nacl.encoding.HexEncoder)
        else:
            self._server_signature_verify_key = None

        server_info = self._api('GET', '/info/', raw=True)
        self._verify_signature(server_info['info'], server_info['signature'])

        self._server_info = json.loads(server_info['info'])

    def _create_session(self):
        self._session_private_key = PrivateKey.generate()

        login_info = json.dumps({
            'api_key_id': self._api_key_id,
            'session_public_key': self._session_private_key.public_key.encode(encoder=nacl.encoding.HexEncoder).decode(),
            'device_description': self.get_device_description(),
        })

        # The first 128 chars (512 bits or 64 bytes) are the actual signature, the rest the binary encoded info
        signature = self._api_key_signing_box.sign(login_info.encode())

        self._client_login_info = {
            'info': login_info,
            'signature': binascii.hexlify(signature.signature).decode(),
        }

        login_info_encrypted = self._api(
            'POST',
            '/api-key/login/',
            data=self._client_login_info
        )

        self._verify_signature(
            login_info_encrypted['login_info'],
            login_info_encrypted['login_info_signature']
        )

        self._server_public_key = PublicKey(login_info_encrypted['server_session_public_key'], encoder=nacl.encoding.HexEncoder)

        # Create crypto box from private session and public server keys
        crypto_box = Box(
            self._session_private_key,
            self._server_public_key
        )

        # Decrypt login_info_encrypted
        self._login_info = json.loads(
            crypto_box.decrypt(
                nacl.encoding.HexEncoder.decode(login_info_encrypted['login_info']),
                nacl.encoding.HexEncoder.decode(login_info_encrypted['login_info_nonce'])
            ).decode()
        )

    def __init__(self):
        self._clear()
        self._verify_cert = True

    def get_secret(self, secret_id):
        if self._token and self.unrestricted_access:
            raise NotImplementedError()
        else:
            data = {
                'api_key_id': self._api_key_id,
                'secret_id': secret_id,
            }

            encrypted_secret = self._api('POST', '/api-key-access/secret/', data, raw=True)

            # decrypt step 1: Decryption of the encryption key
            crypto_box = nacl.secret.SecretBox(self._api_key_secret_key, encoder=nacl.encoding.HexEncoder)
            encryption_key = crypto_box.decrypt(
                nacl.encoding.HexEncoder.decode(encrypted_secret['secret_key']),
                nacl.encoding.HexEncoder.decode(encrypted_secret['secret_key_nonce'])
            )

            # decrypt step 2: Decryption of the secret
            crypto_box = nacl.secret.SecretBox(encryption_key, encoder=nacl.encoding.HexEncoder)
            decrypted_secret = crypto_box.decrypt(
                nacl.encoding.HexEncoder.decode(encrypted_secret['data']),
                nacl.encoding.HexEncoder.decode(encrypted_secret['data_nonce'])
            )

            return json.loads(decrypted_secret)

    def get_share(self, share):
        encrypted_share = self._api(
            'GET',
            f"/share/{share['share_id']}/"
        )

        descrypted_share = self._decrypt_symmetric(
            encrypted_share['data'],
            encrypted_share['data_nonce'],
            share['share_secret_key']
        )

        return json.loads(descrypted_share)
