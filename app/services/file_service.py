from typing import Any

from fastapi import HTTPException
from app.utils.minio import MinioClient
import os
import shutil
from settings.config import settings

class FileService:
    def __init__(self):
        self.minio_client = MinioClient()

    async def upload_File(self, file: Any, object_name: str) -> str:
        """Upload profile picture to MinIO and return the URL."""
        file_path = f"/tmp/{object_name}"
        try:
            # Save file to temporary location
            with open(file_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)

            # Upload file to MinIO
            await self.minio_client.upload_file(object_name, file_path)

        except Exception as e:
            print(f"Error during file upload: {e}")
            raise HTTPException(status_code=503, detail=str(e))
        
        finally:
            # Cleanup temporary file
            if os.path.exists(file_path):
                os.remove(file_path)
        
        url = f"{'https' if settings.isSecure else 'http'}://{settings.minio if settings.isSecure else 'localhost'}:{settings.port}/{self.minio_client.bucket_name}/{object_name}"
        print(url)
        return url

