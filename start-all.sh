#!/bin/bash

# Start script for Threat Detection Dashboard
# Starts both backend API and React frontend

echo "🚀 Starting AI-Assisted Threat Detection Dashboard"
echo "=================================================="
echo ""

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
  echo "📦 Installing backend dependencies..."
  npm install
fi

if [ ! -d "dashboard/node_modules" ]; then
  echo "📦 Installing dashboard dependencies..."
  cd dashboard && npm install && cd ..
fi

echo ""
echo "✅ Starting backend API on http://localhost:3000"
echo "✅ Starting dashboard on http://localhost:5173"
echo ""
echo "Press Ctrl+C to stop both servers"
echo ""

# Start backend in background
npm run dev &
BACKEND_PID=$!

# Wait a bit for backend to start
sleep 2

# Start frontend in background
cd dashboard && npm run dev &
FRONTEND_PID=$!

# Function to cleanup on exit
cleanup() {
  echo ""
  echo "🛑 Stopping servers..."
  kill $BACKEND_PID $FRONTEND_PID 2>/dev/null
  exit 0
}

# Trap Ctrl+C and cleanup
trap cleanup INT TERM

# Wait for both processes
wait
