#!/bin/bash

# NIST Compliance Evidence Evaluation API - POC Startup Script

echo "🚀 Starting NIST Compliance Evidence Evaluation API - Proof of Concept"
echo "=================================================================="

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found. Please run setup.py first:"
    echo "   python setup.py"
    exit 1
fi

# Activate virtual environment
echo "📦 Activating virtual environment..."
source venv/bin/activate

# Check for API keys
if [ -z "$OPENAI_API_KEY" ] && [ -z "$ANTHROPIC_API_KEY" ]; then
    echo "⚠️  Warning: No API keys found. The evidence evaluation will not work."
    echo "   Please set one of the following environment variables:"
    echo "   export OPENAI_API_KEY='your-key-here'"
    echo "   OR"
    echo "   export ANTHROPIC_API_KEY='your-key-here'"
    echo ""
    echo "   Basic endpoints (health, controls) will still work for testing."
    echo ""
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Show configuration
echo "🔧 Configuration:"
if [ ! -z "$OPENAI_API_KEY" ]; then
    echo "   LLM Provider: OpenAI GPT"
elif [ ! -z "$ANTHROPIC_API_KEY" ]; then
    echo "   LLM Provider: Anthropic Claude"
else
    echo "   LLM Provider: None (basic functionality only)"
fi

echo "   API Port: ${PORT:-8000}"
echo ""

# Start the API server
echo "🌐 Starting API server..."
echo "   API will be available at: http://localhost:${PORT:-8000}"
echo "   Documentation: http://localhost:${PORT:-8000}/docs"
echo ""
echo "📋 Useful endpoints:"
echo "   Health check:  http://localhost:${PORT:-8000}/health"
echo "   List controls: http://localhost:${PORT:-8000}/controls"
echo "   API docs:      http://localhost:${PORT:-8000}/docs"
echo ""
echo "🧪 To test the API, run in another terminal:"
echo "   python test_api_poc.py"
echo ""
echo "⏹️  Press Ctrl+C to stop the server"
echo ""

# Start the server
python -m src.api.main