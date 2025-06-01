#!/bin/bash
# generate_rsa_keys.sh - Script to generate RSA key pair for JWT signing

echo "Generating RSA key pair for Vespeyr Auth Server JWT signing..."

# Check if OpenSSL is available
if ! command -v openssl &> /dev/null; then
    echo "Error: OpenSSL is not installed or not in PATH."
    echo "Please install OpenSSL and try again."
    exit 1
fi

# Define output directory (same as script location by default)
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Define key file paths
PRIVATE_KEY="$DIR/private_key.pem"
PUBLIC_KEY="$DIR/public_key.pem"

# Check if files already exist
if [ -f "$PRIVATE_KEY" ] || [ -f "$PUBLIC_KEY" ]; then
    echo "Warning: Key files already exist. Generating new keys will replace existing ones."
    read -p "Continue? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Operation cancelled."
        exit 0
    fi
fi

# Generate private key
echo "Generating private key..."
openssl genrsa -out "$PRIVATE_KEY" 2048

if [ $? -ne 0 ]; then
    echo "Error: Failed to generate private key."
    exit 1
fi

# Extract public key
echo "Extracting public key..."
openssl rsa -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY"

if [ $? -ne 0 ]; then
    echo "Error: Failed to extract public key."
    exit 1
fi

# Set appropriate permissions
chmod 600 "$PRIVATE_KEY"
chmod 644 "$PUBLIC_KEY"

echo "RSA key pair generated successfully:"
echo "Private key: $PRIVATE_KEY"
echo "Public key: $PUBLIC_KEY"
echo
echo "IMPORTANT: Keep the private key secure and do not share it."
echo "Copy the contents of the public key to configure your Coherence dashboard."
echo
echo "To view the public key contents, run:"
echo "cat $PUBLIC_KEY"
echo
echo "Done."