#!/bin/bash

# SubSpector Linux Installation Script
# Version: 1.4

echo "🛡️  SubSpector - Linux Installation Script"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${RED}❌ This script should not be run as root${NC}"
   exit 1
fi

echo -e "${BLUE}📋 Checking system requirements...${NC}"

# Check Python 3
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python 3 is not installed${NC}"
    echo -e "${YELLOW}   Please install Python 3: sudo apt update && sudo apt install python3 python3-pip${NC}"
    exit 1
else
    echo -e "${GREEN}✅ Python 3 found: $(python3 --version)${NC}"
fi

# Check pip
if ! command -v pip3 &> /dev/null; then
    echo -e "${RED}❌ pip3 is not installed${NC}"
    echo -e "${YELLOW}   Please install pip3: sudo apt install python3-pip${NC}"
    exit 1
else
    echo -e "${GREEN}✅ pip3 found${NC}"
fi

# Create virtual environment
echo -e "${BLUE}🔧 Creating virtual environment...${NC}"
python3 -m venv subspector_env
source subspector_env/bin/activate

# Install requirements
echo -e "${BLUE}📦 Installing Python dependencies...${NC}"
pip install --upgrade pip
pip install -r requirements.txt

# Download subfinder for Linux
echo -e "${BLUE}🔍 Setting up subfinder...${NC}"
SUBFINDER_VERSION="v2.6.6"
SUBFINDER_URL="https://github.com/projectdiscovery/subfinder/releases/download/${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip"

# Create subfinder directory
mkdir -p subfinder

# Download and extract subfinder
if command -v wget &> /dev/null; then
    wget -q "$SUBFINDER_URL" -O subfinder.zip
elif command -v curl &> /dev/null; then
    curl -L "$SUBFINDER_URL" -o subfinder.zip
else
    echo -e "${RED}❌ Neither wget nor curl found. Please install one of them.${NC}"
    exit 1
fi

if command -v unzip &> /dev/null; then
    unzip -q subfinder.zip -d subfinder/
    chmod +x subfinder/subfinder
    rm subfinder.zip
    echo -e "${GREEN}✅ Subfinder installed successfully${NC}"
else
    echo -e "${RED}❌ unzip not found. Please install unzip: sudo apt install unzip${NC}"
    exit 1
fi

# Create directories
echo -e "${BLUE}📁 Creating directories...${NC}"
mkdir -p logs/{security,whois,stats,status,updown,headers,terminal}
mkdir -p reports

# Create run script
echo -e "${BLUE}📝 Creating run script...${NC}"
cat > run_subspector.sh << 'EOF'
#!/bin/bash

# SubSpector Run Script
# Activate virtual environment and run SubSpector

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Activate virtual environment
source subspector_env/bin/activate

# Check if domain is provided
if [ -z "$1" ]; then
    echo "Usage: ./run_subspector.sh <domain> [options]"
    echo ""
    echo "Examples:"
    echo "  ./run_subspector.sh example.com"
    echo "  ./run_subspector.sh example.com -m analysis"
    echo "  ./run_subspector.sh example.com -m security"
    echo "  ./run_subspector.sh example.com -m monitor"
    echo ""
    exit 1
fi

# Run SubSpector
python3 subspector.py "$@"
EOF

chmod +x run_subspector.sh

echo -e "${GREEN}🎉 Installation completed successfully!${NC}"
echo ""
echo -e "${PURPLE}📋 Usage Instructions:${NC}"
echo -e "   ${YELLOW}1.${NC} Activate virtual environment: ${BLUE}source subspector_env/bin/activate${NC}"
echo -e "   ${YELLOW}2.${NC} Run SubSpector: ${BLUE}./run_subspector.sh <domain>${NC}"
echo ""
echo -e "${PURPLE}📚 Examples:${NC}"
echo -e "   ${BLUE}./run_subspector.sh reddit.com -m analysis${NC}"
echo -e "   ${BLUE}./run_subspector.sh google.com -m security${NC}"
echo -e "   ${BLUE}./run_subspector.sh facebook.com -m monitor${NC}"
echo ""
echo -e "${GREEN}✨ Ready to use SubSpector!${NC}" 