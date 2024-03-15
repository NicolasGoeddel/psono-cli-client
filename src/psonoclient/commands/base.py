class CommandBase():
    def __init__(self, client, args):
        self._client = client
        self._args = args
