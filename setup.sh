#!/bin/bash
# Setup script for Automated Web Vulnerability Discovery Framework

set -e

echo "=========================================="
echo "Vulnerability Scanner Setup"
echo "=========================================="

# Check Python version
echo "[*] Checking Python version..."
python3 --version

# Create virtual environment
echo "[*] Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
echo "[*] Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Install Playwright browsers
echo "[*] Installing Playwright browsers..."
playwright install

# Check for external tools
echo ""
echo "[*] Checking for external tools..."
echo ""

check_tool() {
    if command -v $1 &> /dev/null; then
        echo "✓ $1 found"
        return 0
    else
        echo "✗ $1 NOT FOUND - Install with: go install $2@latest"
        return 1
    fi
}

tools_found=0

echo "Required tools:"
check_tool "nuclei" "github.com/projectdiscovery/nuclei/v2/cmd/nuclei" && ((tools_found++)) || true
check_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx" && ((tools_found++)) || true

echo ""
echo "Recommended tools:"
check_tool "gau" "github.com/lc/gau/v2/cmd/gau" || true
check_tool "katana" "github.com/projectdiscovery/katana/cmd/katana" || true
check_tool "waybackurls" "github.com/tomnomnom/waybackurls" || true

if [ $tools_found -lt 1 ]; then
    echo ""
    echo "[!] At least nuclei and httpx are recommended"
    echo "[!] Visit: https://github.com/projectdiscovery for installation"
fi

echo ""
echo "=========================================="
echo "Setup complete!"
echo ""
echo "To validate installation:"
echo "  python3 main.py --validate-only"
echo ""
echo "To run a scan:"
echo "  python3 main.py -d example.com"
echo "=========================================="
