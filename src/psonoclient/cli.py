#!/bin/env python3

import sys
import requests
from urllib3.exceptions import InsecureRequestWarning
import nacl.exceptions
from argparse import ArgumentError

import yaml
import json

from psonoclient.client import PsonoClient, PsonoApiError
from psonoclient.misc import yprint
from psonoclient.fields import FIELDS
from psonoclient.parser import CliParser
from psonoclient.commands import *
from psonoclient import __version__

class FormatWrapper():
    def __init__(self, value, plain=None, subfield='message'):
        self._value = value
        self._plain = plain
        self._subfield = subfield

    def get(self, format):
        # 'yaml', 'json', 'columns', 'python', 'plain'
        if format == 'plain':
            return str(self)

        elif format == 'yaml':
            return yaml.dump(self._value)

        elif format == 'json':
            # https://stackoverflow.com/a/51674892/4239139
            return json.dumps(
                self._value,
                default=lambda o: f"<{repr(o)}>"
            )

        elif format == 'python':
            return repr(self._value)

        elif format == 'columns':
            raise NotImplementedError()

    def __str__(self):
        if self._plain:
            return self._plain
        if isinstance(self._value, str):
            return self._value

        if isinstance(self._value, list):
            if all(map(lambda e: isinstance(e, (str, bool, int)), self._value)):
                # convert a simple list to single lines
                return '\n'.join(map(str, self._value))

            if all(map(lambda e: ('key' in e) and ('value' in e) and len(e.keys()) == 2, self._value)):
                # convert a list of key-value-dicts to a <key> = <value>
                return '\n'.join(map(lambda e: f"{e['key']} = {e['value']}", self._value))

        if isinstance(self._value, dict) and all(map(lambda e: isinstance(e, str), self._value.keys())) and all(map(lambda e: isinstance(e, (str, bool, int, list)), self._value.values())):
            # convert a plain dict from str -> (str, bool, int, list)
            # if the value is a list, separate the entries by a comma
            return '\n'.join(
                ["{key} = {item}".format(
                    key=key,
                    item=', '.join(item) if isinstance(item, list) else str(item).replace('\n', '\n\t')
                ) for key, item in self._value.items()])

        if self._subfield and isinstance(self._value, dict) and (self._subfield in self._value):
            return self._value[self._subfield]

        return repr(self._value)

def main():
    parser = CliParser()

    try:
        parser.check()
    except ArgumentError as e:
        print(e.message)
        sys.exit(1)

    if parser.parsed.command == 'version':
        print(
            FormatWrapper(
                {
                    'name': "psonoclient",
                    'version': __version__
                },
                __version__
            ).get(parser.parsed.format)
        )
        sys.exit(0)

    client = PsonoClient()
    client.verify_cert(parser.parsed.verify_cert)

    try:
        client.login(
            endpoint=parser.parsed.endpoint,
            api_key_id=parser.parsed.api_key_id,
            api_key_private_key=parser.parsed.api_key_private_key,
            api_key_secret_key=parser.parsed.api_key_secret_key,
            client_cert_key=parser.parsed.client_cert_key,
            client_cert_crt=parser.parsed.client_cert_crt,
            server_signature=parser.parsed.server_signature
        )
    except nacl.exceptions.BadSignatureError:
        #TODO Make output nicer
        print("Server Signature does not match.")
        sys.exit(1)

    output = None
    error = 0
    try:
        if parser.parsed.command == 'info':
            output = FormatWrapper(
                client.server_info
            )

        elif parser.parsed.command == 'get':
            if parser.parsed.secret_id:
                secret = client.get_secret(parser.parsed.secret_id)

                if parser.parsed.fields:
                    output = FormatWrapper(list(secret.keys()))

                elif parser.parsed.field:
                    output = FormatWrapper(
                        secret[parser.parsed.field] if parser.parsed.field else secret
                    )

                else:
                    field_type = None
                    if parser.parsed.title:
                        field_type = 'title'
                    elif parser.parsed.url:
                        field_type = 'url'
                    elif parser.parsed.username:
                        field_type = 'username'
                    elif parser.parsed.password:
                        field_type = 'password'
                    elif parser.parsed.notes:
                        field_type = 'notes'

                    if field_type:
                        for field in FIELDS[field_type]:
                            if field in secret.keys():
                                output = FormatWrapper(secret[field])
                                break
                        else:
                            output = FormatWrapper(
                                {
                                    'message': f"{field_type} field not found.",
                                    'error': 1
                                },
                                subfield='message'
                            )
                            error = 1
                    else:
                        output = FormatWrapper(secret)

        elif parser.parsed.command == 'ls':
            cmd = CommandLs(client, parser.parsed)
            output = FormatWrapper(cmd.get())

        elif parser.parsed.command == 'users':
            output = FormatWrapper(client.users)

        elif parser.parsed.command == 'settings':
            output = FormatWrapper(client.settings)

    except PsonoApiError as e:
        output = FormatWrapper(
            {
                'message': e.message,
                'statuscode': e.response.status_code,
                'answer': e.response.text,
                'error': 1
            },
            subfield='message'
        )
        error = 1

    if output:
        print(output.get(parser.parsed.format))
    sys.exit(error)

if __name__ == '__main__':
    main()
