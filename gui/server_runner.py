# gui/server_runner.py - Server running functionality with SSL support (Conservative WebSocket integration)
import time
import logging
import os
import ssl
import subprocess
import threading
import sys


def run_server(host, port, debug=False, stop_event=None, ssl_enabled=False, ssl_cert_path=None, ssl_key_path=None, ssl_ca_cert_path=None, server_type="development"):
    """Run the Flask server - production or development based on config with SSL support
    PLUS start WebSocket server in background"""
    
    # Determine protocol for logging
    protocol = "HTTPS" if ssl_enabled else "HTTP"
    logging.info(f"Starting {protocol} server on {host}:{port}")
    
    # Store start time for uptime calculations
    if hasattr(threading.current_thread(), 'start_time'):
        threading.current_thread().start_time = int(time.time())
    
    # Get current directory for log paths
    current_dir = os.getcwd()
    
    # Flask server instance for possible shutdown
    flask_server_instance = None
    
    # Start WebSocket server in background (non-blocking)
    websocket_process = None
    try:
        websocket_process = start_websocket_server_background(host, port + 1, ssl_enabled, ssl_cert_path, ssl_key_path, stop_event)
        logging.info(f"WebSocket chat server started in background on port {port + 1}")
    except Exception as e:
        logging.warning(f"Failed to start WebSocket server: {e} - continuing with Flask API only")
    
    # Store WebSocket process on the thread for shutdown
    if websocket_process:
        threading.current_thread().websocket_process = websocket_process
    
    # Validate SSL certificates if SSL is enabled
    if ssl_enabled:
        ssl_issues = validate_ssl_certificates(ssl_cert_path, ssl_key_path, ssl_ca_cert_path)
        if ssl_issues:
            logging.error("SSL Certificate validation failed:")
            for issue in ssl_issues:
                logging.error(f"  - {issue}")
            raise ValueError(f"SSL configuration invalid: {'; '.join(ssl_issues)}")
        
        logging.info(f"SSL certificates validated successfully")
        logging.info(f"SSL Certificate: {ssl_cert_path}")
        logging.info(f"SSL Private Key: {ssl_key_path}")
        if ssl_ca_cert_path:
            logging.info(f"SSL CA Certificate: {ssl_ca_cert_path}")
    
    try:
        # Import the Flask app
        from api import app
        
        # Check if we should use production server (Gunicorn)
        from config import config
        if config.get("SERVER_TYPE", "development") == "production" or server_type == "production":
            flask_server_instance = run_gunicorn_server(host, port, debug, stop_event, ssl_enabled, ssl_cert_path, ssl_key_path, current_dir, config)
        else:
            # Development mode - use werkzeug server with SSL support
            flask_server_instance = run_flask_development_server(host, port, debug, stop_event, ssl_enabled, ssl_cert_path, ssl_key_path, ssl_ca_cert_path, app)
    
    except Exception as e:
        logging.error(f"Error running Flask server: {e}")
        # Clean up WebSocket server if it was started
        if websocket_process:
            try:
                websocket_process.terminate()
                websocket_process.wait(timeout=5)
            except:
                try:
                    websocket_process.kill()
                except:
                    pass
        raise
    
    # Return the Flask server instance (unchanged behavior)
    return flask_server_instance


def start_websocket_server_background(host, port, ssl_enabled, ssl_cert_path, ssl_key_path, stop_event):
    """Start the WebSocket chat server as a background subprocess (non-blocking)"""
    try:
        # Prepare environment variables for the WebSocket server
        env = os.environ.copy()
        env['WEBSOCKET_HOST'] = host
        env['WEBSOCKET_PORT'] = str(port)
        env['SSL_ENABLED'] = str(ssl_enabled)
        if ssl_enabled:
            env['SSL_CERT_PATH'] = ssl_cert_path or ''
            env['SSL_KEY_PATH'] = ssl_key_path or ''
        
        # Start WebSocket server as subprocess
        websocket_process = subprocess.Popen([
            sys.executable, "websocket_chat_server.py"
        ], 
        stdout=subprocess.PIPE, 
        stderr=subprocess.STDOUT, 
        text=True,
        env=env
        )
        
        # Start a thread to monitor WebSocket server output (non-blocking)
        def monitor_websocket_output():
            try:
                for line in iter(websocket_process.stdout.readline, ''):
                    if line.strip():
                        logging.info(f"[WebSocket] {line.strip()}")
            except Exception as e:
                logging.error(f"Error monitoring WebSocket output: {e}")
        
        websocket_thread = threading.Thread(target=monitor_websocket_output, daemon=True)
        websocket_thread.start()
        
        # Start a thread to monitor for stop_event and terminate WebSocket server
        def monitor_websocket_shutdown():
            try:
                while not (stop_event and stop_event.is_set()):
                    if websocket_process.poll() is not None:
                        # Process has terminated
                        break
                    time.sleep(0.5)
                
                # Stop event was set or process died
                if websocket_process.poll() is None:
                    logging.info("Stopping WebSocket chat server...")
                    websocket_process.terminate()
                    try:
                        websocket_process.wait(timeout=10)
                        logging.info("WebSocket chat server stopped gracefully")
                    except subprocess.TimeoutExpired:
                        logging.warning("WebSocket server didn't stop gracefully, killing...")
                        websocket_process.kill()
                        websocket_process.wait()
                        logging.info("WebSocket chat server killed")
            except Exception as e:
                logging.error(f"Error in WebSocket shutdown monitor: {e}")
        
        shutdown_thread = threading.Thread(target=monitor_websocket_shutdown, daemon=True)
        shutdown_thread.start()
        
        return websocket_process
        
    except Exception as e:
        logging.error(f"Failed to start WebSocket chat server: {e}")
        raise


def validate_ssl_certificates(ssl_cert_path, ssl_key_path, ssl_ca_cert_path=None):
    """Validate SSL certificates before server startup."""
    issues = []
    
    if not ssl_cert_path or not os.path.exists(ssl_cert_path):
        issues.append(f"SSL certificate file not found: {ssl_cert_path}")
    
    if not ssl_key_path or not os.path.exists(ssl_key_path):
        issues.append(f"SSL private key file not found: {ssl_key_path}")
    
    if ssl_ca_cert_path and not os.path.exists(ssl_ca_cert_path):
        issues.append(f"SSL CA certificate file not found: {ssl_ca_cert_path}")
    
    # Try to load the certificate and key to verify they're valid
    if ssl_cert_path and ssl_key_path and os.path.exists(ssl_cert_path) and os.path.exists(ssl_key_path):
        try:
            # Test SSL context creation
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(ssl_cert_path, ssl_key_path)
            logging.info("SSL certificate and key pair validated successfully")
        except Exception as e:
            issues.append(f"SSL certificate/key validation failed: {str(e)}")
    
    return issues


def create_ssl_context(ssl_cert_path, ssl_key_path, ssl_ca_cert_path=None):
    """Create SSL context for Flask/Werkzeug server."""
    try:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(ssl_cert_path, ssl_key_path)
        
        if ssl_ca_cert_path and os.path.exists(ssl_ca_cert_path):
            context.load_verify_locations(ssl_ca_cert_path)
        
        # Security settings
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        return context
    except Exception as e:
        logging.error(f"Failed to create SSL context: {str(e)}")
        raise


def run_gunicorn_server(host, port, debug, stop_event, ssl_enabled, ssl_cert_path, ssl_key_path, current_dir, config):
    """Run Gunicorn server with SSL support."""
    # Check for Gunicorn
    gunicorn_path = None
    try:
        import shutil
        gunicorn_path = shutil.which("gunicorn")
    except:
        pass
    
    if gunicorn_path:
        # Build command line for Gunicorn
        from config import LOG_DIR
        cmd = [
            gunicorn_path,
            "--bind", f"{host}:{port}",
            "--workers", str(config.get("WORKERS", 1)),
            "--timeout", "60",
            "--log-level", config.get("LOG_LEVEL", "info").lower(),
            "--access-logfile", os.path.join(current_dir, LOG_DIR, "gunicorn_access.log"),
            "--error-logfile", os.path.join(current_dir, LOG_DIR, "gunicorn_error.log"),
            "api:app"
        ]
        
        # Add SSL configuration for Gunicorn
        if ssl_enabled and ssl_cert_path and ssl_key_path:
            cmd.extend([
                "--certfile", ssl_cert_path,
                "--keyfile", ssl_key_path,
                "--ssl-version", "TLSv1_2",
                "--ciphers", "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA"
            ])
            logging.info("Gunicorn configured with SSL/HTTPS")
        else:
            logging.info("Gunicorn configured for HTTP")
        
        # Start Gunicorn as subprocess
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        
        # Log Gunicorn output
        def log_gunicorn_output():
            for line in iter(proc.stdout.readline, ''):
                if line.strip():
                    logging.info(f"Gunicorn: {line.strip()}")
        
        output_thread = threading.Thread(target=log_gunicorn_output, daemon=True)
        output_thread.start()
        
        # Wait for process to exit or stop_event
        while proc.poll() is None:
            if stop_event and stop_event.is_set():
                logging.info("Stopping Gunicorn server...")
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    logging.warning("Gunicorn didn't stop gracefully, killing...")
                    proc.kill()
                break
            time.sleep(0.1)
        
        logging.info("Gunicorn server has stopped")
        return proc
    else:
        logging.warning("Gunicorn not found. Install with: pip install gunicorn")
        logging.warning("Falling back to Flask development server")
        
        # Fall back to Flask development server
        return run_flask_development_server(host, port, debug, stop_event, ssl_enabled, ssl_cert_path, ssl_key_path, None, None)


def run_flask_development_server(host, port, debug, stop_event, ssl_enabled, ssl_cert_path, ssl_key_path, ssl_ca_cert_path, app):
    """Run Flask development server with SSL support."""
    import werkzeug.serving
    
    # Create SSL context if SSL is enabled
    ssl_context = None
    if ssl_enabled and ssl_cert_path and ssl_key_path:
        ssl_context = create_ssl_context(ssl_cert_path, ssl_key_path, ssl_ca_cert_path)
        logging.info("Flask development server configured with SSL/HTTPS")
    else:
        logging.info("Flask development server configured for HTTP")
    
    # Create the server with SSL context
    server = werkzeug.serving.make_server(
        host, 
        port, 
        app, 
        threaded=True,
        ssl_context=ssl_context
    )
    
    # Run server in a separate thread so we can monitor stop_event
    def server_thread():
        try:
            server.serve_forever()
        except Exception as e:
            logging.error(f"Flask server error: {str(e)}")
    
    server_thread = threading.Thread(target=server_thread)
    server_thread.daemon = True
    server_thread.start()
    
    # Monitor for shutdown
    while not (stop_event and stop_event.is_set()):
        time.sleep(0.1)
    
    # Shutdown the server when stop_event is set
    logging.info("Shutting down Flask development server...")
    server.shutdown()
    logging.info("Flask development server has stopped")
    
    return server