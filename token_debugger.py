import base64
import json
import argparse
import jwt
import sys
import os

def decode_jwt(token):
    """Decode and display the contents of a JWT token without verification."""
    # If token includes 'Bearer ' prefix, remove it
    if token.startswith('Bearer '):
        token = token[7:]
    
    try:
        # Split the token into parts
        parts = token.split('.')
        if len(parts) != 3:
            print("Error: Invalid JWT format. Expected 3 parts separated by dots.")
            return False
        
        # Decode header
        header_data = parts[0]
        # Add padding if needed
        padded_header = header_data + '=' * (4 - len(header_data) % 4) % 4
        header_bytes = base64.urlsafe_b64decode(padded_header)
        header = json.loads(header_bytes)
        
        # Decode payload
        payload_data = parts[1]
        # Add padding if needed
        padded_payload = payload_data + '=' * (4 - len(payload_data) % 4) % 4
        payload_bytes = base64.urlsafe_b64decode(padded_payload)
        payload = json.loads(payload_bytes)
        
        # Signature (not decoded)
        signature = parts[2]
        
        # Print information
        print("\n=== JWT Token Information ===")
        print("\nHEADER:")
        print(json.dumps(header, indent=2))
        
        print("\nPAYLOAD:")
        print(json.dumps(payload, indent=2))
        
        print("\nSIGNATURE (base64url encoded):")
        print(signature)
        
        # Check algorithm
        if header.get('alg') != 'RS256':
            print("\nWARNING: Token is not using RS256 algorithm!")
            print(f"Current algorithm: {header.get('alg')}")
        
        # Check expiration
        if 'exp' in payload:
            import time
            exp_time = payload['exp']
            current_time = int(time.time())
            if exp_time < current_time:
                print(f"\nWARNING: Token expired on {time.ctime(exp_time)}")
            else:
                print(f"\nToken valid until: {time.ctime(exp_time)}")
        
        return True
    
    except Exception as e:
        print(f"Error decoding token: {e}")
        return False

def verify_jwt(token, public_key_path=None):
    """Verify a JWT token signature."""
    # If token includes 'Bearer ' prefix, remove it
    if token.startswith('Bearer '):
        token = token[7:]
    
    if not public_key_path:
        print("Warning: No public key provided. Skipping signature verification.")
        return
    
    try:
        # Load the public key
        with open(public_key_path, 'r') as f:
            public_key = f.read()
        
        # Verify the token
        print("\n=== Verifying Token Signature ===")
        decoded = jwt.decode(token, public_key, algorithms=["RS256"])
        print("✅ Signature verified successfully!")
        return True
    except jwt.InvalidSignatureError:
        print("❌ Invalid signature! Token has been tampered with or signed with a different key.")
        return False
    except jwt.ExpiredSignatureError:
        print("❌ Token has expired!")
        return False
    except jwt.DecodeError:
        print("❌ Token could not be decoded! It may be malformed.")
        return False
    except Exception as e:
        print(f"❌ Verification error: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description='JWT Token Debugger')
    parser.add_argument('token', nargs='?', help='JWT token to decode (if not provided, will look for TOKEN environment variable)')
    parser.add_argument('-f', '--file', help='File containing the JWT token')
    parser.add_argument('-v', '--verify', help='Verify signature using the provided public key file')
    
    args = parser.parse_args()
    
    # Get token from command line, file, or environment variable
    token = None
    if args.token:
        token = args.token
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                token = f.read().strip()
        except Exception as e:
            print(f"Error reading token file: {e}")
            return
    else:
        token = os.environ.get('TOKEN')
    
    if not token:
        print("Error: No token provided. Use command line argument, --file option, or TOKEN environment variable.")
        return
    
    # Decode the token
    if decode_jwt(token):
        # If verification requested, verify the signature
        if args.verify:
            verify_jwt(token, args.verify)

if __name__ == "__main__":
    main()
