"""
This file contains some deprecated stuff and might be deleted in the future.
"""

def yprint(var):
    print(yaml.safe_dump(var, indent=2))

def api_read_datastore(token, session_secret_key, datastore_id):
    """
    Reads the content of a specific datastore

    :param token:
    :type token:
    :param session_secret_key:
    :type session_secret_key:
    :param datastore_id:
    :type datastore_id:
    :return:
    :rtype:
    """

    method = 'GET'
    endpoint = '/datastore/' + datastore_id + '/'

    return api_request(method, endpoint, token=token, session_secret_key=session_secret_key)

def api_read_secret(token, session_secret_key, secret_id):
    """
    Reads the content of a specific datastore

    :param token:
    :type str:
    :param session_secret_key:
    :type str:
    :param secret_id:
    :type str:
    :return:
    :rtype:
    """

    method = 'GET'
    endpoint = '/secret/' + secret_id + '/'

    return api_request(method, endpoint, token=token, session_secret_key=session_secret_key)