#!/bin/bash

# Check if a domain argument was provided
if [ -z "$1" ]; then
  echo "Usage: ./scan.sh <domain>"
  exit 1
fi

DOMAIN=$1
echo "Starting security analysis for target: $DOMAIN"
echo "=========================================="

# 1. Whois lookup for domain ownership and restrictions
echo ">> Running Whois lookup..."
whois "$DOMAIN"
echo "=========================================="

# 2. DNS record check for various service types
echo ">> Running DNS lookup..."
dig ANY "$DOMAIN"
echo "=========================================="

# 3. Nmap scan to check for open ports and services
echo ">> Running Nmap scan on ports 80 and 443..."
nmap -sV -p 80,443 "$DOMAIN"
echo "=========================================="

# 4. SSL certificate check
echo ">> Running SSL certificate check..."
openssl s_client -connect "$DOMAIN":443 -showcerts < /dev/null
echo "=========================================="

# 5. HTTP Headers check using curl
echo ">> Running HTTP Headers check..."
curl -I --silent "$DOMAIN"
echo "=========================================="

echo "Analysis complete."
