# gui/server_runner.py - Server running functionality
import time
import logging
import os
import subprocess
import threading

def run_server(host, port, debug=False, stop_event=None):
    """Run the server - production or development based on config"""
    logging.info(f"Starting server on {host}:{port}")
    
    # Store start time for uptime calculations
    if hasattr(threading.current_thread(), 'start_time'):
        threading.current_thread().start_time = int(time.time())
    
    # Get current directory for log paths
    current_dir = os.getcwd()
    
    # Flask server instance for possible shutdown
    flask_server_instance = None
    
    try:
        # Import the Flask app
        from api import app
        
        # Check if we should use production server (Gunicorn)
        from config import config
        if config.get("SERVER_TYPE", "development") == "production":
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
                
                # Start Gunicorn as subprocess
                proc = subprocess.Popen(cmd)
                flask_server_instance = proc
                
                # Wait for process to exit or stop_event
                while proc.poll() is None:
                    if stop_event and stop_event.is_set():
                        proc.terminate()
                        try:
                            proc.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            proc.kill()  # Force kill if it doesn't terminate
                        break
                    time.sleep(0.1)
                
                logging.info("Gunicorn server has stopped")
            else:
                logging.warning("Gunicorn not found. Install with: pip install gunicorn")
                logging.warning("Falling back to Flask development server")
                
                # Import werkzeug to create a server
                import werkzeug.serving
                
                # Create and start werkzeug server
                server = werkzeug.serving.make_server(host, port, app, threaded=True)
                flask_server_instance = server
                
                # Run server in a separate thread so we can monitor stop_event
                def server_thread():
                    server.serve_forever()
                
                server_thread = threading.Thread(target=server_thread)
                server_thread.daemon = True
                server_thread.start()
                
                # Monitor for shutdown
                while not (stop_event and stop_event.is_set()):
                    time.sleep(0.1)
                
                # Shutdown the server when stop_event is set
                server.shutdown()
                logging.info("Flask development server has stopped")
        else:
            # Development mode - use werkzeug server with serve_forever pattern
            import werkzeug.serving
            
            # Create the server
            server = werkzeug.serving.make_server(host, port, app, threaded=True)
            flask_server_instance = server
            
            # Run server in a separate thread so we can monitor stop_event
            def server_thread():
                server.serve_forever()
            
            server_thread = threading.Thread(target=server_thread)
            server_thread.daemon = True
            server_thread.start()
            
            # Monitor for shutdown
            while not (stop_event and stop_event.is_set()):
                time.sleep(0.1)
            
            # Shutdown the server when stop_event is set
            server.shutdown()
            logging.info("Flask development server has stopped")
    
    except Exception as e:
        logging.error(f"Error running server: {e}")
    
    return flask_server_instance
