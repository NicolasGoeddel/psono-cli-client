from psonoclient.commands import CommandBase

class CommandLs(CommandBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, *kwargs)

        self._type = {self._args.entry_type} if self._args.entry_type else {'folder', 'type'}
        self._prefix = list(filter(lambda e: e, (self._args.path or '').strip('/').split('/')))
        self._recursive = self._args.recursive or False

    @staticmethod
    def add_cmd_parser(parser):
        # ls [<folder>] [--type <folder|item>]
        cmd_ls = parser.add_parser(
            'ls',
            help="List the entries in the password datastore (requires unrestricted access)."
        )
        cmd_ls.add_argument(
            '--type', '-t',
            action='store',
            type=str,
            help='Filter by entry type.',
            choices=['folder', 'item'],
            default=None,
            dest='entry_type'
        )
        cmd_ls.add_argument(
            '--recursive', '-r',
            action='store_true',
            help='Recursively show all subfolders and their items.',
            default=False,
            dest='recursive'
        )
        cmd_ls.add_argument(
            action='store',
            type=str,
            nargs='?',
            help='The path you want to list.',
            default='',
            dest='path'
        )

    def _resolve_share(self, item_or_folder):
        if 'share_id' in item_or_folder:
            orig_id = item_or_folder.get('id', None)
            item_or_folder = self._client.get_share(item_or_folder)
            if not 'id' in item_or_folder and orig_id:
                item_or_folder['id'] = orig_id
        return item_or_folder

    def _recurse(self, tree, prefix=[], depth=1) -> list:
        output = []

        if depth == 0:
            return None

        else:
            if prefix:
                # Just recurse without listing the content of the current folder
                # until we have reached the desired prefix.
                for folder in tree.get('folders', []):
                    if folder['name'] == prefix[0]:
                        return self._recurse(
                            self._resolve_share(folder),
                            prefix[1:],
                            depth
                        )
                        break
                else:
                    # Output an error message if the given prefix can not be found
                    return {
                        'message': f"Path {'/'.join(prefix)} not found.",
                        'error': 1
                    }

            else:
                if depth > 1 or 'folder' in self._type:
                    for iter_folder in tree.get('folders', []):
                        if iter_folder.get('deleted', False):
                            continue

                        folder = self._resolve_share(iter_folder)

                        output.append(
                            {
                                'name': folder['name'],
                                'id': folder['id'],
                                'children': self._recurse(
                                    folder,
                                    prefix,
                                    depth - 1
                                ),
                                'type': 'folder'
                            }
                        )

                if 'item' in self._type:
                    for iter_item in tree.get('items', []):
                        if iter_item.get('deleted', False):
                            continue

                        item = self._resolve_share(iter_item)

                        output.append(
                            {
                                'name': item['name'],
                                'id': item['id'],
                                'type': item.get('type', 'unknown')
                            }
                        )

        return output

    def get(self):
        return self._recurse(
            self._client.passwords,
            self._prefix,
            depth=1000 if self._recursive else 1
        )

