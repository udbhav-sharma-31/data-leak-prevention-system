import boto3
from .rules import detect_sensitive_data

class AWSS3Scanner:
    def __init__(self, bucket_name):
        self.bucket = bucket_name
        self.s3 = boto3.client("s3")

    def list_files(self):
        response = self.s3.list_objects_v2(Bucket=self.bucket)
        return response.get("Contents", [])

    def read_file(self, key):
        obj = self.s3.get_object(Bucket=self.bucket, Key=key)
        return obj["Body"].read().decode(errors="ignore")

    def scan_file(self, content):
        return detect_sensitive_data(content)
