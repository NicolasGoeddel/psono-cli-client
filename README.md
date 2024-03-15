# psonoclient

A CLI client for the Psono password manager, written in Python, usable for scripting purposes.

## Installation

```bash
$ pip install psonoclient
```

## Usage
`psono` has some global mandatory and optional arguments and a few subcommands that come with their own arguments.
You always have to write the global arguments first, then the subcommand and then its arguments.

### General usage
```
usage: psono [-h] [--endpoint <URL>] [--api-key-id <ID>] [--api-key-private-key <Key>] [--api-key-secret-key <Key>] [--format <Format>] [--insecure] [--server-signature <Signature>] [--client-cert-key <Key>]
             [--client-cert-crt <Certificate>] [--verbose]
             {version,info,users,settings,ls,get} ...

options:
  -h, --help            show this help message and exit

Mandatory arguments:
  Without these arguments a connection to a Psono server is not possible

  --endpoint <URL>, -e <URL>
                        The endpoint of the Psono server including the protocol (e.g. https://psono.example.com/server).
  --api-key-id <ID>     The API Key ID in the form xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.
  --api-key-private-key <Key>
                        The private API Key in the form of a 64 character long hex number.
  --api-key-secret-key <Key>
                        The secret API Key in the form of a 64 character long hex number.

Formatting:
  For now there is just that one argument to format the output.

  --format <Format>, -f <Format>
                        The output format (one of: yaml, json, columns, python, plain).

Security:
  Here are a few arguments related to security.

  --insecure, -k        Ignore any problems with invalid or self signed certificates, incomplete certificate chains or old cipher suites.
  --server-signature <Signature>
                        The servers signature in form of a 64 character long hex number to check against.

Authentication:
  In case you need additional authentication against the Psono server.

  --client-cert-key <Key>
                        The client certificates key needed to connect to the endpoint.
  --client-cert-crt <Certificate>
                        The client certificate needed to connect to the endpoint.

Optional:
  Some optional arguments.

  --verbose, -v         Increase verbosity level on stderr (0=quiet, 1=info, 2=debug).

Commands:
  All available commands.

  {version,info,users,settings,ls,get}
    version             Show the client version.
    info                Shows some information about the server.
    users               Shows all the users that are known to this account (requires unrestricted access).
    settings            Shows all the settings of this account (requires unrestricted access).
    ls                  List the entries in the password datastore (requires unrestricted access).
    get                 Retrieve a secret as a whole.
```
**Example:**
Get some information about the server.
```sh
psono \
    --endpoint "https://psono.example.com/server" \
    --api-key-id "12345678-1234-1234-1234-123456789012" \
    --api-key-private-key "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" \
    --api-key-secret-key "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" \
    info
```

### Subcommand `get`
```
usage: psono get [-h] [--entry <ID>] [--secret <ID>] [--field <ID>] [--fields] [--password] [--username] [--url] [--title] [--notes]

options:
  -h, --help            show this help message and exit
  --entry <ID>, -e <ID>
                        The id of the entry in the database (requires unrestricted access).
  --secret <ID>, -s <ID>
                        The id of a certain secret (requires restricted access).
  --field <ID>, -f <ID>
                        The name of the field in this entry/secret.
  --fields              List all available fields of this entry/secret.
  --password, -p        Find the password field and just output it.
  --username, --user, -u
                        Find the user field and just output it.
  --url                 Find the URL field and just output it.
  --title               Find the title field and just output it.
  --notes               Find the notes field and just output it.
```
**Example:**
Get a password of a secret that was shared with a restricted API key.
```sh
psono \
    --endpoint "https://psono.example.com/server" \
    --api-key-id "12345678-1234-1234-1234-123456789012" \
    --api-key-private-key "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" \
    --api-key-secret-key "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" \
    --format 'plain' \
    get \
    --secret '12345678-1234-1234-1234-123456789012' \
    --password
```

### Subcommand `ls`
```
usage: psono ls [-h] [--type {folder,item}]

options:
  -h, --help            show this help message and exit
  --type {folder,item}, -t {folder,item}
                        Filter by entry type.
```

## Contributing

Interested in contributing? Check out the contributing guidelines. Please note that this project is released with a Code of Conduct. By contributing to this project, you agree to abide by its terms.

## License

`psonoclient` was created by Nicolas Göddel. It is licensed under the terms of the GNU General Public License v3.0 license.

## Credits

`psonoclient` was created with [`cookiecutter`](https://cookiecutter.readthedocs.io/en/latest/) and the `py-pkgs-cookiecutter` [template](https://github.com/py-pkgs/py-pkgs-cookiecutter).
