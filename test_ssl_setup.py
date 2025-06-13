#!/usr/bin/env python3
"""
Quick test script to verify SSL certificate processing works
"""
import os
import subprocess
import sys

def generate_test_certificates():
    """Generate test SSL certificates"""
    print("🔐 Generating test SSL certificates...")
    
    try:
        # Check OpenSSL availability
        subprocess.run(["openssl", "version"], capture_output=True, check=True)
        print("✅ OpenSSL found")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ OpenSSL not found. Please install OpenSSL first.")
        return False
    
    # Create ssl_certs directory
    os.makedirs("ssl_certs", exist_ok=True)
    
    cert_file = "ssl_certs/server.crt"
    key_file = "ssl_certs/server.key"
    
    try:
        # Generate private key
        subprocess.run([
            "openssl", "genrsa", "-out", key_file, "2048"
        ], check=True, capture_output=True)
        
        # Generate self-signed certificate
        subprocess.run([
            "openssl", "req", "-new", "-x509",
            "-key", key_file,
            "-out", cert_file,
            "-days", "365",
            "-subj", "/C=US/ST=State/L=City/O=Test/CN=localhost"
        ], check=True, capture_output=True)
        
        print(f"✅ SSL certificates generated:")
        print(f"   Certificate: {os.path.abspath(cert_file)}")
        print(f"   Private Key: {os.path.abspath(key_file)}")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to generate certificates: {e}")
        return False

def test_ssl_validation():
    """Test SSL certificate validation"""
    print("\n🧪 Testing SSL certificate validation...")
    
    try:
        # Import the validation function
        from gui.server_runner import validate_ssl_certificates
        
        cert_file = "ssl_certs/server.crt"
        key_file = "ssl_certs/server.key"
        
        if not os.path.exists(cert_file) or not os.path.exists(key_file):
            print("❌ SSL certificates not found. Run generate_test_certificates() first.")
            return False
        
        issues = validate_ssl_certificates(cert_file, key_file)
        
        if not issues:
            print("✅ SSL certificate validation passed!")
            return True
        else:
            print("❌ SSL certificate validation failed:")
            for issue in issues:
                print(f"   - {issue}")
            return False
            
    except Exception as e:
        print(f"❌ SSL validation test failed: {e}")
        return False

def test_ssl_context_creation():
    """Test SSL context creation"""
    print("\n🔧 Testing SSL context creation...")
    
    try:
        from gui.server_runner import create_ssl_context
        
        cert_file = "ssl_certs/server.crt"
        key_file = "ssl_certs/server.key"
        
        if not os.path.exists(cert_file) or not os.path.exists(key_file):
            print("❌ SSL certificates not found.")
            return False
        
        context = create_ssl_context(cert_file, key_file)
        
        if context:
            print("✅ SSL context created successfully!")
            return True
        else:
            print("❌ Failed to create SSL context")
            return False
            
    except Exception as e:
        print(f"❌ SSL context creation failed: {e}")
        return False

def main():
    """Run all SSL tests"""
    print("🚀 SSL Certificate Processing Test Suite")
    print("=" * 50)
    
    # Test 1: Generate certificates
    if not generate_test_certificates():
        print("\n❌ Test suite failed at certificate generation")
        return False
    
    # Test 2: Validate certificates
    if not test_ssl_validation():
        print("\n❌ Test suite failed at certificate validation")
        return False
    
    # Test 3: Create SSL context
    if not test_ssl_context_creation():
        print("\n❌ Test suite failed at SSL context creation")
        return False
    
    print("\n🎉 All SSL tests passed!")
    print("\nNext steps:")
    print("1. Update your configuration to enable SSL")
    print("2. Set SSL_CERT_PATH to ssl_certs/server.crt")
    print("3. Set SSL_KEY_PATH to ssl_certs/server.key")
    print("4. Start your server - it will run on HTTPS!")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)