"""Homepage tests."""
import pytest


def test_homepage_loads(client):
    """Test homepage returns 200 and renders template."""
    response = client.get("/")
    assert response.status_code == 200
    assert b"ToolkitRAG" in response.content
    assert b"AI Toolkit Learning Platform" in response.content


def test_homepage_has_health_links(client):
    """Test homepage has links to health endpoints."""
    response = client.get("/")
    assert response.status_code == 200
    assert b"/health" in response.content
    assert b"/ready" in response.content
