# Vespeyr Authentication Server

A secure, all-in-one authentication server for game backends and web applications with theme management and automatic updates.

## Overview

The Vespeyr Authentication Server provides a complete solution for user registration, authentication, password management, and session tracking. It includes both an API server and an administration interface for easy management, with customizable themes and automatic update capabilities.

## Features

### Core Authentication
- **User Management**
  - Secure registration and login
  - Password reset via email
  - Profile management
  
- **Security**
  - bcrypt password hashing
  - JWT token-based authentication
  - Account lockout after failed login attempts
  - Rate limiting for sensitive endpoints
  - HTTPS redirection
  - CORS protection
  - Security headers

### Administration Interface
- **Server Management**
  - Graphical user interface for server control
  - Real-time server monitoring
  - Log viewing and filtering
  - Database backup and management
  - Configuration management

### Theme Management
- **Customizable Themes**
  - Light mode
  - Dark Classic mode
  - Dark Soft mode
  - Dark Ultra Black mode
  - Theme settings persistence
  - Instant theme switching

### Automatic Updates
- **Update Management**
  - Automatic version checking
  - Notification of available updates
  - One-click update downloads
  - Launch new version option
  - Update history tracking

## Requirements

- Python 3.7+
- Required packages (install via pip):
  - flask
  - flask-limiter
  - flask-cors
  - bcrypt
  - PyJWT
  - PyQt6 (for theme management)
  - packaging (for update management)
  - requests (for update management)
  - tkinter (usually included with Python)

## Installation

1. Clone the repository or unzip the package:
   ```
   git clone https://github.com/yourusername/vespeyr-auth.git
   cd vespeyr-auth
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Run the server application:
   ```
   python server.py
   ```

## Configuration

The server uses a `config.json` file to store settings. This is created automatically on first run with default values. You can modify the configuration through the GUI or by directly editing the file.

### Key Configuration Options

- **Server Settings**
  - `HOST`: Server bind address (0.0.0.0 for all interfaces)
  - `PORT`: Server port number
  - `DEBUG_MODE`: Enable Flask debug mode
  - `ENABLE_HTTPS_REDIRECT`: Redirect HTTP to HTTPS

- **Email Settings**
  - `SMTP_HOST`: SMTP server address
  - `SMTP_PORT`: SMTP server port
  - `SMTP_USER`: SMTP username/from address
  - `SMTP_PASS`: SMTP password
  - `RESET_URL_BASE`: Base URL for password reset links

- **Security Settings**
  - `JWT_SECRET`: Secret key for JWT tokens
  - `JWT_EXPIRATION`: Access token expiration in seconds
  - `PASSWORD_MIN_LENGTH`: Minimum password length
  - `ACCOUNT_LOCKOUT_THRESHOLD`: Failed attempts before lockout

- **Theme Settings**
  - Theme preferences are stored in application settings

- **Update Settings**
  - Update manifest URL is configurable

## API Endpoints

### Public Endpoints

- `GET /health`  
  Check server health

- `POST /auth/register`  
  Register a new user  
  Body: `{"username": "user", "email": "user@example.com", "password": "secure_password"}`

- `POST /auth/login`  
  Authenticate a user  
  Body: `{"username": "user", "password": "secure_password"}`

- `POST /auth/request-password-reset`  
  Request a password reset link  
  Body: `{"email": "user@example.com"}`

- `POST /auth/reset-password`  
  Reset password using a token  
  Body: `{"token": "reset_token", "new_password": "new_secure_password"}`

### Protected Endpoints (require Bearer token)

- `GET /auth/profile`  
  Get user profile information  
  Header: `Authorization: Bearer <token>`

- `POST /auth/change-password`  
  Change password  
  Header: `Authorization: Bearer <token>`  
  Body: `{"current_password": "old_password", "new_password": "new_password"}`

- `POST /auth/logout`  
  Logout (invalidate token)  
  Header: `Authorization: Bearer <token>`

- `POST /auth/refresh`  
  Refresh an access token  
  Body: `{"refresh_token": "refresh_token"}`

### Admin Endpoints (require admin privileges)

- `GET /auth/admin/users`  
  List all users  
  Header: `Authorization: Bearer <admin_token>`

- `PUT /auth/admin/users/<user_id>`  
  Update user status  
  Header: `Authorization: Bearer <admin_token>`  
  Body: `{"account_status": "active|locked|suspended"}`

## Using Theme Manager

The Theme Manager provides an intuitive interface for customizing the application's appearance:

1. Access the Theme Manager from the application interface
2. Select a theme from the dropdown (Light, Dark Classic, Dark Soft, or Dark Ultra Black)
3. Use the toggle button to quickly switch between Light and Dark modes
4. Theme preferences are saved automatically and persist between sessions

For programmatic theme control:
```python
from theme_manager import apply_theme_to_all_widgets, get_theme_data

# Apply current theme to all widgets
apply_theme_to_all_widgets()

# Get current theme data
theme, theme_name = get_theme_data()
```

## Using Update Manager

The Update Manager automatically checks for new versions and facilitates easy updates:

1. The application checks for updates on startup
2. When updates are available, a notification will appear
3. Click "Yes" to download the update
4. After download completes, you can launch the new version immediately

For programmatic update control:
```python
from update_manager import UpdateManager

# Create update manager
updater = UpdateManager(
    parent=self,  # Parent widget
    manifest_url="https://your-update-server.com/manifest.json",
    current_version="1.0.0"
)

# Check for updates
updater.check_for_updates()
```

The update manifest should be a JSON file with the following format:
```json
{
  "version": "1.1.0",
  "url": "https://your-update-server.com/downloads/vespeyr-auth-1.1.0.exe"
}
```

## Security Best Practices

1. **HTTPS**: Always use HTTPS in production environments
2. **JWT Secret**: Regularly rotate the JWT secret to invalidate old tokens
3. **Email Configuration**: Configure email to enable password reset functionality
4. **Admin Account**: Set up a dedicated admin account for administration tasks
5. **Backups**: Regularly backup your database and verify the backups
6. **Updates**: Keep the application updated to the latest version

## File Structure

- `server.py` - Main application entry point
- `config.py` - Configuration management
- `db.py` - Database operations
- `api.py` - API routes and endpoints
- `auth.py` - Authentication functions
- `email_service.py` - Email functionality
- `gui.py` - Graphical user interface
- `theme_manager.py` - Theme management functionality
- `update_manager.py` - Automatic update functionality
- `logs/` - Log directory
- `backups/` - Database backup directory
- `config.json` - Configuration file

## Troubleshooting

- **Server won't start**: Check logs in the 'logs' directory for error details
- **Email not working**: Verify SMTP settings and credentials
- **Database errors**: Ensure SQLite is installed and database file is writable
- **Theme issues**: Clear application settings if themes aren't applying correctly
- **Update problems**: Check your internet connection and update manifest URL

## License

This project is licensed under the MIT License - see the LICENSE file for details.
