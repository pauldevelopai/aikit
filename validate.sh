#!/bin/bash
set -e

echo "======================================"
echo "ToolkitRAG - Milestone 1 Validation"
echo "======================================"
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker Desktop and try again."
    exit 1
fi
echo "✅ Docker is running"

# Check if services are up
if ! docker compose ps | grep -q "app.*running"; then
    echo "⚠️  Application not running. Starting services..."
    docker compose up -d
    echo "⏳ Waiting for services to be ready (30s)..."
    sleep 30
else
    echo "✅ Services already running"
fi

echo ""
echo "Testing endpoints..."
echo "===================="

# Test /health
echo -n "Testing GET /health... "
HEALTH_RESPONSE=$(curl -s http://localhost:8000/health)
if echo "$HEALTH_RESPONSE" | grep -q '"status":"healthy"'; then
    echo "✅ PASSED"
else
    echo "❌ FAILED"
    echo "   Response: $HEALTH_RESPONSE"
    exit 1
fi

# Test /ready
echo -n "Testing GET /ready... "
READY_RESPONSE=$(curl -s http://localhost:8000/ready)
if echo "$READY_RESPONSE" | grep -q '"database":"connected"'; then
    echo "✅ PASSED"
else
    echo "❌ FAILED"
    echo "   Response: $READY_RESPONSE"
    exit 1
fi

# Test homepage
echo -n "Testing GET / (homepage)... "
HOME_RESPONSE=$(curl -s http://localhost:8000/)
if echo "$HOME_RESPONSE" | grep -q "ToolkitRAG"; then
    echo "✅ PASSED"
else
    echo "❌ FAILED"
    exit 1
fi

echo ""
echo "Running test suite..."
echo "===================="
docker compose run --rm app pytest -v

echo ""
echo "======================================"
echo "✅ ALL VALIDATIONS PASSED!"
echo "======================================"
echo ""
echo "Application is running at:"
echo "  🌐 http://localhost:8000"
echo ""
echo "To view logs:"
echo "  docker compose logs -f"
echo ""
echo "To stop:"
echo "  docker compose down"
