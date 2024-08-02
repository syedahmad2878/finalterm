from minio import Minio
from minio.error import S3Error
from settings.config import settings
import mimetypes

class MinioClient:
    def __init__(self):
        self.client = Minio(
            f"{settings.minio}:{settings.port}",
            access_key=settings.minio_access_key,
            secret_key=settings.minio_secret_key,
            secure=settings.isSecure
        )
        self.bucket_name = settings.minio_bucket_name
        self._create_bucket_if_not_exists()

    def _create_bucket_if_not_exists(self):
        """Create the bucket if it does not exist."""
        try:
            found = self.client.bucket_exists(self.bucket_name)
            if not found:
                self.client.make_bucket(self.bucket_name)
                print(f"Bucket '{self.bucket_name}' created successfully.")
            else:
                print(f"Bucket '{self.bucket_name}' already exists.")
        except S3Error as e:
            print(f"Error occurred while checking/creating the bucket: {e}")

    def upload_file(self, object_name, file_path):
        """Upload a file to the bucket."""
        try:
            content_type, _ = mimetypes.guess_type(file_path)
            self.client.fput_object(
                self.bucket_name,
                object_name,
                file_path,
                content_type=content_type
            )
            print(f"'{file_path}' is successfully uploaded as '{object_name}' to bucket '{self.bucket_name}'.")
        except S3Error as e:
            print(f"Error occurred while uploading the file: {e}")
