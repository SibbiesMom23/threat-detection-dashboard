#!/bin/bash

# Test script for Threat Detection Dashboard API
# Usage: ./test-api.sh

BASE_URL="http://localhost:3000"

echo "========================================"
echo "Threat Detection Dashboard - API Tests"
echo "========================================"
echo ""

# Test 1: Health Check
echo "1. Testing health check..."
curl -s "$BASE_URL/health" | jq '.'
echo ""

# Test 2: Upload sample logs
echo "2. Uploading sample logs..."
curl -s -X POST "$BASE_URL/api/logs/upload" \
  -F "logfile=@data/sample-logs.json" | jq '.'
echo ""

# Test 3: Get stats
echo "3. Fetching dashboard stats..."
curl -s "$BASE_URL/api/stats" | jq '.'
echo ""

# Test 4: Get alerts
echo "4. Fetching alerts..."
curl -s "$BASE_URL/api/alerts?status=open&limit=10" | jq '.'
echo ""

# Test 5: Run detection manually
echo "5. Running threat detection..."
curl -s -X POST "$BASE_URL/api/detect" | jq '.'
echo ""

# Test 6: Generate AI analysis
echo "6. Generating AI summary..."
curl -s -X POST "$BASE_URL/api/analyze" | jq '.'
echo ""

# Test 7: Batch log ingestion
echo "7. Testing batch log ingestion..."
curl -s -X POST "$BASE_URL/api/logs/batch" \
  -H "Content-Type: application/json" \
  -d '[
    {
      "timestamp": "2025-10-15T15:30:00Z",
      "event_type": "login",
      "username": "test_user",
      "source_ip": "192.168.1.200",
      "status": "success",
      "message": "Test login via API"
    }
  ]' | jq '.'
echo ""

# Test 8: Get recent logs
echo "8. Fetching recent logs..."
curl -s "$BASE_URL/api/logs?limit=5" | jq '.'
echo ""

echo "========================================"
echo "All tests completed!"
echo "========================================"
