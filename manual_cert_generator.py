#!/usr/bin/env python3
"""
Generate SSL certificates using Python cryptography library (no OpenSSL required)
"""
import os
import ipaddress
from datetime import datetime, timedelta

def install_cryptography():
    """Install cryptography library if not present"""
    try:
        import cryptography
        return True
    except ImportError:
        print("📦 Installing cryptography library...")
        import subprocess
        try:
            subprocess.run(["pip", "install", "cryptography"], check=True)
            print("✅ cryptography library installed successfully!")
            return True
        except subprocess.CalledProcessError:
            print("❌ Failed to install cryptography library")
            return False

def generate_certificates():
    """Generate SSL certificates using Python cryptography library"""
    if not install_cryptography():
        return False
    
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError as e:
        print(f"❌ Failed to import cryptography: {e}")
        return False
    
    print("🔐 Generating SSL certificates with Python cryptography...")
    
    # Create ssl_certs directory
    os.makedirs("ssl_certs", exist_ok=True)
    
    try:
        # Generate private key
        print("   🔑 Generating private key...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Create certificate
        print("   📜 Creating certificate...")
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Organization"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("127.0.0.1"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        # Write private key
        key_file = "ssl_certs/server.key"
        print("   💾 Saving private key...")
        with open(key_file, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Write certificate
        cert_file = "ssl_certs/server.crt"
        print("   💾 Saving certificate...")
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        print(f"\n✅ SSL certificates generated successfully!")
        print(f"   📁 Directory: {os.path.abspath('ssl_certs')}")
        print(f"   📜 Certificate: {os.path.abspath(cert_file)}")
        print(f"   🔑 Private Key: {os.path.abspath(key_file)}")
        print(f"   ⏰ Valid for: 365 days")
        print(f"   🌐 Domain: localhost, 127.0.0.1")
        
        return True
        
    except Exception as e:
        print(f"❌ Failed to generate certificates: {e}")
        return False

def test_certificates():
    """Test the generated certificates"""
    cert_file = "ssl_certs/server.crt"
    key_file = "ssl_certs/server.key"
    
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        print("❌ Certificate files not found")
        return False
    
    try:
        # Test if we can load the certificate and key
        import ssl
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(cert_file, key_file)
        print("✅ Certificate validation: PASSED")
        return True
    except Exception as e:
        print(f"❌ Certificate validation failed: {e}")
        return False

def main():
    """Main function"""
    print("🚀 SSL Certificate Generator")
    print("=" * 40)
    
    # Generate certificates
    if not generate_certificates():
        print("\n❌ Certificate generation failed!")
        return False
    
    # Test certificates
    print("\n🧪 Testing generated certificates...")
    if not test_certificates():
        print("\n❌ Certificate testing failed!")
        return False
    
    print("\n🎉 Success! Your SSL certificates are ready!")
    print("\nNext steps:")
    print("1. 📋 Copy these paths for your configuration:")
    print(f"   SSL_CERT_PATH: {os.path.abspath('ssl_certs/server.crt')}")
    print(f"   SSL_KEY_PATH: {os.path.abspath('ssl_certs/server.key')}")
    print("2. ⚙️  Enable SSL in your server configuration")
    print("3. 🚀 Start your server - it will run on HTTPS!")
    print("4. 🌐 Test by visiting https://localhost:5000")
    print("\n⚠️  Note: Browsers will show security warnings for self-signed certificates (this is normal)")
    
    return True

if __name__ == "__main__":
    success = main()
    if not success:
        print("\nIf you encounter issues, ensure you have Python pip working correctly.")
        input("Press Enter to exit...")
    else:
        input("\nPress Enter to exit...")