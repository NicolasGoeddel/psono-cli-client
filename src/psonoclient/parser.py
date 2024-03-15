import argparse

class CliParser():
    def __init__(self):
        self._parser = argparse.ArgumentParser()
        self._options()
        self._parsed = None

    def _options(self):
        # Mandatory arguments:
        # --endpoint <t:string>
        # --api-key-id <t:string>
        # --api-key-private-key <t:string>
        # --api-key-secret-key <t:string>
        mandatory_args_group = self._parser.add_argument_group(
            title="Mandatory arguments",
            description="Without these arguments a connection to a Psono server is not possible"
        )
        mandatory_args_group.add_argument(
            '--endpoint', '-e',
            action='store',
            type=str,
            help='The endpoint of the Psono server including the protocol (e.g. https://psono.example.com/server).',
            metavar='<URL>',
            dest='endpoint'
        )
        mandatory_args_group.add_argument(
            '--api-key-id',
            action='store',
            type=str,
            help='The API Key ID in the form xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.',
            metavar='<ID>',
            dest='api_key_id'
        )
        mandatory_args_group.add_argument(
            '--api-key-private-key',
            action='store',
            type=str,
            help='The private API Key in the form of a 64 character long hex number.',
            metavar='<Key>',
            dest='api_key_private_key'
        )
        mandatory_args_group.add_argument(
            '--api-key-secret-key',
            action='store',
            type=str,
            help='The secret API Key in the form of a 64 character long hex number.',
            metavar='<Key>',
            dest='api_key_secret_key'
        )

        # Formats:
        # --format <yaml|json|columns|python|plain*>
        formatting_group = self._parser.add_argument_group(
            title="Formatting",
            description="For now there is just that one argument to format the output."
        )
        formatting_group.add_argument(
            '--format', '-f',
            action='store',
            type=str,
            help='The output format (one of: yaml, json, columns, python, plain).',
            choices=['yaml', 'json', 'columns', 'python', 'plain'],
            default='plain',
            metavar='<Format>',
            dest='format'
        )

        # Security:
        # --server-signature <t:string>
        # --insecure
        security_group = self._parser.add_argument_group(
            title="Security",
            description="Here are a few arguments related to security."
        )
        security_group.add_argument(
            '--insecure', '-k',
            action='store_false',
            help='Ignore any problems with invalid or self signed certificates, incomplete certificate chains or old cipher suites.',
            dest='verify_cert',
            default=True
        )
        security_group.add_argument(
            '--server-signature',
            action='store',
            type=str,
            help='The servers signature in form of a 64 character long hex number to check against.',
            metavar='<Signature>',
            dest='server_signature'
        )

        # Authentication:
        # --client-cert-key <t:file>
        # --client-cert-crt <t:file>
        auth_group = self._parser.add_argument_group(
            title="Authentication",
            description="In case you need additional authentication against the Psono server."
        )
        auth_group.add_argument(
            '--client-cert-key',
            action='store',
            type=str,
            help='The client certificates key needed to connect to the endpoint.',
            metavar='<Key>',
            dest='client_cert_key'
        )
        auth_group.add_argument(
            '--client-cert-crt',
            action='store',
            type=str,
            help='The client certificate needed to connect to the endpoint.',
            metavar='<Certificate>',
            dest='client_cert_crt'
        )

        # Optional arguments
        # --verbose
        # --version
        # --conf <t:path>
        optional_group = self._parser.add_argument_group(
            title="Optional",
            description="Some optional arguments."
        )
        # optional_group.add_argument(
        #     '--version', '-V',
        #     action='store_true',
        #     help='Show the version.',
        #     default=False,
        #     dest='version'
        # )
        optional_group.add_argument(
            '--verbose', '-v',
            action='count',
            help='Increase verbosity level on stderr (0=quiet, 1=info, 2=debug).',
            default=0,
            dest='verbosity'
        )

        # Commands:
        # browse
        commands = self._parser.add_subparsers(
            title="Commands",
            description="All available commands.",
            dest="command"
        )
        commands.add_parser(
            'version',
            help="Show the client version."
        )
        # info (serverinfo)
        commands.add_parser(
            'info',
            help="Shows some information about the server."
        )
        # users
        commands.add_parser(
            'users',
            help="Shows all the users that are known to this account (requires unrestricted access)."
        )
        # settings
        commands.add_parser(
            'settings',
            help="Shows all the settings of this account (requires unrestricted access)."
        )

        # ls [<folder>] [--type <folder|item>]
        cmd_ls = commands.add_parser(
            'ls',
            help="List the entries in the password datastore (requires unrestricted access)."
        )
        cmd_ls.add_argument(
            '--type', '-t',
            action='store',
            type=str,
            help='Filter by entry type.',
            choices=['folder', 'item'],
            dest='entry_type'
        )
        # get --secret <secret-id> | --id <id> | --field <field> | --password | --user | --url | -notes | --title
        cmd_get = commands.add_parser(
            'get',
            help="Retrieve a secret as a whole."
        )
        cmd_get.add_argument(
            '--entry', '-e',
            action='store',
            type=str,
            help='The id of the entry in the database (requires unrestricted access).',
            metavar='<ID>',
            dest='entry_id'
        )
        cmd_get.add_argument(
            '--secret', '-s',
            action='store',
            type=str,
            help='The id of a certain secret (requires restricted access).',
            metavar='<ID>',
            dest='secret_id'
        )
        cmd_get.add_argument(
            '--field', '-f',
            action='store',
            type=str,
            help='The name of the field in this entry/secret.',
            metavar='<ID>',
            dest='field'
        )
        cmd_get.add_argument(
            '--fields',
            action='store_true',
            help='List all available fields of this entry/secret.',
            default=False,
            dest='fields'
        )
        cmd_get.add_argument(
            '--password', '-p',
            action='store_true',
            help='Find the password field and just output it.',
            default=False,
            dest='password'
        )
        cmd_get.add_argument(
            '--username', '--user', '-u',
            action='store_true',
            help='Find the user field and just output it.',
            default=False,
            dest='username'
        )
        cmd_get.add_argument(
            '--url',
            action='store_true',
            help='Find the URL field and just output it.',
            default=False,
            dest='url'
        )
        cmd_get.add_argument(
            '--title',
            action='store_true',
            help='Find the title field and just output it.',
            default=False,
            dest='title'
        )
        cmd_get.add_argument(
            '--notes',
            action='store_true',
            help='Find the notes field and just output it.',
            default=False,
            dest='notes'
        )

    def _check_all_or_nothing(self, msg, *args):
        if any(args) and not all(args):
            raise argparse.ArgumentError(argument=None, message=msg)

    def _check_count(self, msg, count, *args):
        if len([x for x in args if (x is not None) and (x is not False)]) != count:
            raise argparse.ArgumentError(argument=None, message=msg)

    def _check_max1(self, msg, *args):
        if len([x for x in args if (x is not None) and (x is not False)]) > 1:
            raise argparse.ArgumentError(argument=None, message=msg)

    def _check_all(self, msg, *args):
        if not all(args):
            raise argparse.ArgumentError(argument=None, message=msg)

    def check(self):
        p = self._parser.parse_args()
        self._parsed = p
        if p.command == 'version':
            return True
        elif p.command == 'get':
            self._check_count(
                "You must either define --entry or --secret.",
                1,
                p.entry_id, p.secret_id
            )
            self._check_max1(
                "You can only define one of --field, --fields, --password.",
                p.field, p.fields, p.password, p.username, p.url, p.title, p.notes
            )
        elif p.command == 'ls':
            pass
        elif p.command == 'users':
            pass
        elif p.command == 'settings':
            pass

        self._check_all(
            "You must define all mandatory arguments.",
            p.endpoint, p.api_key_id, p.api_key_private_key, p.api_key_secret_key
        )
        self._check_all_or_nothing(
            "For the client certificate both arguments are needed.",
            p.client_cert_crt, p.client_cert_key
        )

        return True

    @property
    def parsed(self):
        if self._parsed is None:
            self.check()
        return self._parsed
