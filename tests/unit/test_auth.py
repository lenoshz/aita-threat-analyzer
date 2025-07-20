"""
Test authentication endpoints
"""

import pytest
from fastapi.testclient import TestClient


def test_register_user(client: TestClient, sample_user_data):
    """Test user registration."""
    response = client.post("/api/v1/auth/register", json=sample_user_data)
    assert response.status_code == 201
    data = response.json()
    assert data["username"] == sample_user_data["username"]
    assert data["email"] == sample_user_data["email"]
    assert "id" in data


def test_register_duplicate_user(client: TestClient, sample_user_data):
    """Test registration with duplicate username."""
    # Register first user
    client.post("/api/v1/auth/register", json=sample_user_data)
    
    # Try to register again
    response = client.post("/api/v1/auth/register", json=sample_user_data)
    assert response.status_code == 400


def test_login_user(client: TestClient, sample_user_data):
    """Test user login."""
    # Register user first
    client.post("/api/v1/auth/register", json=sample_user_data)
    
    # Login
    login_data = {
        "username": sample_user_data["username"],
        "password": sample_user_data["password"]
    }
    response = client.post("/api/v1/auth/login", json=login_data)
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_login_invalid_credentials(client: TestClient):
    """Test login with invalid credentials."""
    login_data = {
        "username": "nonexistent",
        "password": "wrongpassword"
    }
    response = client.post("/api/v1/auth/login", json=login_data)
    assert response.status_code == 401


def test_get_current_user(client: TestClient, sample_user_data):
    """Test getting current user info."""
    # Register and login
    client.post("/api/v1/auth/register", json=sample_user_data)
    login_response = client.post("/api/v1/auth/login", json={
        "username": sample_user_data["username"],
        "password": sample_user_data["password"]
    })
    token = login_response.json()["access_token"]
    
    # Get current user
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/api/v1/auth/me", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == sample_user_data["username"]


def test_get_current_user_unauthorized(client: TestClient):
    """Test getting current user without token."""
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401