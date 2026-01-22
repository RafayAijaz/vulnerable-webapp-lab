#!/bin/bash
echo "🚀 Starting Vulnerable Web Application Lab..."

# Create uploads directory
mkdir -p uploads

echo "🌐 Starting Flask server on port 5000..."
echo "🔓 Application will be available at: http://localhost:5000"
echo "=========================================="

# Run the app directly (init_database() is called in app.py)
exec python app.py
