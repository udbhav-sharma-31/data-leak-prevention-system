class CloudScannerBase:
    def __init__(self, user):
        self.user = user

    def authenticate(self):
        raise NotImplementedError("Authentication not implemented")

    def list_files(self):
        raise NotImplementedError("List files not implemented")

    def read_file(self, file_id):
        raise NotImplementedError("Read file not implemented")

    def scan_file(self, content):
        raise NotImplementedError("Scan file not implemented")
