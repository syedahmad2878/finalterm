from unittest.mock import patch, MagicMock
from app.utils.minio import MinioClient
import pytest
from httpx import AsyncClient
from app.main import app
from app.models.user_model import User, UserRole
from app.utils.nickname_gen import generate_nickname
from app.utils.security import hash_password
from app.services.jwt_service import decode_token
from app.services.file_service import FileService
from uuid import uuid4
from fastapi import status
import asyncio

# Example of a test function using the async_client fixture
@pytest.mark.asyncio
async def test_create_user_access_denied(async_client, user_token, email_service):
    headers = {"Authorization": f"Bearer {user_token}"}
    # Define user data for the test
    user_data = {
        "nickname": generate_nickname(),
        "email": "test@example.com",
        "password": "sS#fdasrongPassword123!",
    }
    # Send a POST request to create a user
    response = await async_client.post("/users/", json=user_data, headers=headers)
    # Asserts
    assert response.status_code == 403

# You can similarly refactor other test functions to use the async_client fixture
@pytest.mark.asyncio
async def test_retrieve_user_access_denied(async_client, verified_user, user_token):
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.get(f"/users/{verified_user.id}", headers=headers)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_retrieve_user_access_allowed(async_client, admin_user, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.get(f"/users/{admin_user.id}", headers=headers)
    assert response.status_code == 200
    assert response.json()["id"] == str(admin_user.id)

@pytest.mark.asyncio
async def test_update_user_email_access_denied(async_client, verified_user, user_token):
    updated_data = {"email": f"updated_{verified_user.id}@example.com"}
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.put(f"/users/{verified_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_update_user_email_access_allowed(async_client, admin_user, admin_token):
    updated_data = {"email": f"updated_{admin_user.id}@example.com"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["email"] == updated_data["email"]


@pytest.mark.asyncio
async def test_delete_user(async_client, admin_user, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    delete_response = await async_client.delete(f"/users/{admin_user.id}", headers=headers)
    assert delete_response.status_code == 204
    # Verify the user is deleted
    fetch_response = await async_client.get(f"/users/{admin_user.id}", headers=headers)
    assert fetch_response.status_code == 404

@pytest.mark.asyncio
async def test_create_user_duplicate_email(async_client, verified_user):
    user_data = {
        "email": verified_user.email,
        "password": "AnotherPassword123!",
        "role": UserRole.ADMIN.name
    }
    response = await async_client.post("/register/", json=user_data)
    assert response.status_code == 400
    assert "Email already exists" in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_create_user_invalid_email(async_client):
    user_data = {
        "email": "notanemail",
        "password": "ValidPassword123!",
    }
    response = await async_client.post("/register/", json=user_data)
    assert response.status_code == 422

import pytest
from app.services.jwt_service import decode_token
from urllib.parse import urlencode

@pytest.mark.asyncio
async def test_login_success(async_client, verified_user):
    # Attempt to login with the test user
    form_data = {
        "username": verified_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    
    # Check for successful login response
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

    # Use the decode_token method from jwt_service to decode the JWT
    decoded_token = decode_token(data["access_token"])
    assert decoded_token is not None, "Failed to decode token"
    assert decoded_token["role"] == "AUTHENTICATED", "The user role should be AUTHENTICATED"

@pytest.mark.asyncio
async def test_login_user_not_found(async_client):
    form_data = {
        "username": "nonexistentuser@here.edu",
        "password": "DoesNotMatter123!"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401
    assert "Incorrect email or password." in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_login_incorrect_password(async_client, verified_user):
    form_data = {
        "username": verified_user.email,
        "password": "IncorrectPassword123!"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401
    assert "Incorrect email or password." in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_login_unverified_user(async_client, unverified_user):
    form_data = {
        "username": unverified_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_login_locked_user(async_client, locked_user):
    form_data = {
        "username": locked_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 400
    assert "Account locked due to too many failed login attempts." in response.json().get("detail", "")
@pytest.mark.asyncio
async def test_delete_user_does_not_exist(async_client, admin_token):
    non_existent_user_id = "00000000-0000-0000-0000-000000000000"  # Valid UUID format
    headers = {"Authorization": f"Bearer {admin_token}"}
    delete_response = await async_client.delete(f"/users/{non_existent_user_id}", headers=headers)
    assert delete_response.status_code == 404

@pytest.mark.asyncio
async def test_update_user_github(async_client, admin_user, admin_token):
    updated_data = {"github_profile_url": "http://www.github.com/kaw393939"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["github_profile_url"] == updated_data["github_profile_url"]

@pytest.mark.asyncio
async def test_update_user_linkedin(async_client, admin_user, admin_token):
    updated_data = {"linkedin_profile_url": "http://www.linkedin.com/kaw393939"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["linkedin_profile_url"] == updated_data["linkedin_profile_url"]

@pytest.mark.asyncio
async def test_list_users_as_admin(async_client, admin_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    assert 'items' in response.json()

@pytest.mark.asyncio
async def test_list_users_as_manager(async_client, manager_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {manager_token}"}
    )
    assert response.status_code == 200

@pytest.mark.asyncio
async def test_list_users_unauthorized(async_client, user_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert response.status_code == 403  # Forbidden, as expected for regular user

@pytest.mark.asyncio
async def test_upload_profile_picture_jpeg(async_client: AsyncClient, admin_user, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    user_id = admin_user.id

    with patch.object(FileService, 'upload_File', return_value="http://example.com/fake_profile_picture.jpg"), \
         patch.object(MinioClient, 'upload_file', return_value=None), \
         patch.object(MinioClient, '_create_bucket_if_not_exists', return_value=None):
        file_data = {'file': ('profile_picture.jpg', b'fake image data', 'image/jpeg')}
        response = await async_client.post(f"/upload-profile-picture?user_id={user_id}", files=file_data, headers=headers)
    
    assert response.status_code == status.HTTP_200_OK

# @pytest.mark.asyncio
# async def test_upload_profile_picture_png(async_client: AsyncClient, admin_user, admin_token):
#     headers = {"Authorization": f"Bearer {admin_token}"}
#     user_id = admin_user.id

#     with patch.object(FileService, 'upload_File', return_value="http://example.com/fake_profile_picture.png"), \
#          patch.object(MinioClient, 'upload_file', return_value=None), \
#          patch.object(MinioClient, '_create_bucket_if_not_exists', return_value=None):
#         file_data = {'file': ('profile_picture.png', b'fake image data', 'image/png')}
#         response = await async_client.post(f"/upload-profile-picture?user_id={user_id}", files=file_data, headers=headers)
    
#     assert response.status_code == status.HTTP_200_OK

# @pytest.mark.asyncio
# async def test_upload_profile_picture_gif(async_client: AsyncClient, admin_user, admin_token):
#     headers = {"Authorization": f"Bearer {admin_token}"}
#     user_id = admin_user.id

#     with patch.object(FileService, 'upload_File', return_value="http://example.com/fake_profile_picture.gif"), \
#          patch.object(MinioClient, 'upload_file', return_value=None), \
#          patch.object(MinioClient, '_create_bucket_if_not_exists', return_value=None):
#         file_data = {'file': ('profile_picture.gif', b'fake image data', 'image/gif')}
#         response = await async_client.post(f"/upload-profile-picture?user_id={user_id}", files=file_data, headers=headers)
    
#     assert response.status_code == status.HTTP_200_OK

@pytest.mark.asyncio
async def test_upload_profile_picture_invalid_file_type(async_client: AsyncClient, admin_user, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    user_id = admin_user.id

    file_data = {'file': ('invalid.txt', b'fake text data', 'text/plain')}
    response = await async_client.post(f"/upload-profile-picture?user_id={user_id}", files=file_data, headers=headers)
    
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == "Invalid file format. Only JPEG, PNG, and GIF are allowed."

@pytest.mark.asyncio
async def test_upload_profile_picture_empty_file(async_client: AsyncClient, admin_user, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    user_id = admin_user.id

    file_data = {'file': ('empty.jpg', b'', 'image/jpeg')}
    response = await async_client.post(f"/upload-profile-picture?user_id={user_id}", files=file_data, headers=headers)
    
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert response.json()["detail"] == "File is empty."

@pytest.mark.asyncio
async def test_upload_profile_picture_large_file(async_client: AsyncClient, admin_user, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    user_id = admin_user.id

    large_file_data = b'a' * (10 * 1024 * 1024)  # 10MB fake file data
    file_data = {'file': ('large_file.jpg', large_file_data, 'image/jpeg')}
    response = await async_client.post(f"/upload-profile-picture?user_id={user_id}", files=file_data, headers=headers)
    
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert response.json()["detail"] == "File is too large."

@pytest.mark.asyncio
async def test_upload_profile_picture_missing_file(async_client: AsyncClient, admin_user, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    user_id = admin_user.id

    # Simulate missing file
    response = await async_client.post(f"/upload-profile-picture?user_id={user_id}", headers=headers)

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

@pytest.mark.asyncio
async def test_upload_profile_picture_missing_authorization(async_client: AsyncClient, admin_user, mocker):
    user_id = admin_user.id

    file_data = {'file': ('profile_picture.jpg', b'fake image data', 'image/jpeg')}
    response = await async_client.post(f"/upload-profile-picture?user_id={user_id}", files=file_data)
    
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

@pytest.mark.asyncio
async def test_upload_profile_picture_invalid_user_id(async_client: AsyncClient, admin_user, admin_token, mocker):
    headers = {"Authorization": f"Bearer {admin_token}"}
    invalid_user_id = "invalid_user_id"

    file_data = {'file': ('profile_picture.jpg', b'fake image data', 'image/jpeg')}
    response = await async_client.post(f"/upload-profile-picture?user_id={invalid_user_id}", files=file_data, headers=headers)
    
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

@pytest.mark.asyncio
async def test_upload_profile_picture_insufficient_permissions(async_client: AsyncClient, anonymous_user, anonymous_token):
    headers = {"Authorization": f"Bearer {anonymous_token}"}
    user_id = anonymous_user.id

    file_data = {'file': ('profile_picture.jpg', b'fake image data', 'image/jpeg')}
    response = await async_client.post(f"/upload-profile-picture?user_id={user_id}", files=file_data, headers=headers)
    
    assert response.status_code == status.HTTP_403_FORBIDDEN
