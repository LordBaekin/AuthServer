#!/usr/bin/env python3
"""
WebSocket Chat Server - Optimized for Selective Storage
Stores only important messages while broadcasting all messages in real-time
"""

import asyncio
import websockets
import json
import logging
import ssl
import sqlite3
import time
from datetime import datetime
from typing import Dict, Set, Optional
import os
import sys
import re

# Add the parent directory to the path so we can import from the main app
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from config import config
from db import db_execute

# Try to import aiohttp for REST API calls
try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    print("[WebSocket] aiohttp not available - REST API integration disabled")

# Configuration - with environment variable overrides
WEBSOCKET_HOST = os.getenv("WEBSOCKET_HOST", config.get("HOST", "0.0.0.0"))
WEBSOCKET_PORT = int(os.getenv("WEBSOCKET_PORT", "5001"))

# SSL Configuration with environment overrides
SSL_ENABLED = os.getenv("SSL_ENABLED", "").lower() in ('true', '1', 'yes') if os.getenv("SSL_ENABLED") else config.get("SSL_ENABLED", False)
SSL_CERT_PATH = os.getenv("SSL_CERT_PATH", config.get("SSL_CERT_PATH", ""))
SSL_KEY_PATH = os.getenv("SSL_KEY_PATH", config.get("SSL_KEY_PATH", ""))

# Active connections: {websocket: {'world_key': str, 'player_name': str, 'user_id': str}}
active_connections: Dict[websockets.WebSocketServerProtocol, dict] = {}

# World rooms: {world_key: set of websockets}
world_rooms: Dict[str, Set[websockets.WebSocketServerProtocol]] = {}

# In-memory recent chat history (last 50 messages per world/channel)
recent_chat_history: Dict[str, list] = {}

# Storage statistics tracking
storage_stats = {
    'total_messages': 0,
    'stored_messages': 0,
    'broadcasted_messages': 0,
    'start_time': time.time()
}

# Setup logging to stdout so it appears in the main GUI console
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout,
    force=True
)
logger = logging.getLogger('websocket_chat')

async def handle_client(websocket, path):
    """Handle individual WebSocket client connections"""
    client_id = f"{websocket.remote_address[0]}:{websocket.remote_address[1]}"
    print(f"[WebSocket] New connection from {client_id}")
    
    try:
        async for message in websocket:
            try:
                data = json.loads(message)
                await handle_message(websocket, data)
            except json.JSONDecodeError:
                print(f"[WebSocket] Invalid JSON from {client_id}: {message}")
                await send_error(websocket, "Invalid JSON format")
            except Exception as e:
                print(f"[WebSocket] Error handling message from {client_id}: {e}")
                await send_error(websocket, "Message processing error")
                
    except websockets.exceptions.ConnectionClosed:
        print(f"[WebSocket] Connection closed for {client_id}")
    except Exception as e:
        print(f"[WebSocket] Unexpected error for {client_id}: {e}")
    finally:
        await handle_disconnect(websocket)

async def handle_message(websocket, data):
    """Process incoming WebSocket messages"""
    message_type = data.get('type', '')
    
    if message_type == 'join':
        await handle_join(websocket, data)
    elif message_type == 'leave':
        await handle_leave(websocket, data)
    elif message_type == 'message':
        await handle_chat_message(websocket, data)
    elif message_type == 'ping':
        await handle_ping(websocket, data)
    elif message_type == 'status':
        await handle_status_check(websocket, data)
    elif message_type == 'chat_history':
        await handle_chat_history_request(websocket, data)
    elif message_type == 'storage_stats':
        await handle_storage_stats_request(websocket, data)
    else:
        print(f"[WebSocket] Unknown message type: {message_type}")
        await send_error(websocket, f"Unknown message type: {message_type}")

async def handle_join(websocket, data):
    """Handle player joining a world"""
    world_key = data.get('worldKey')
    user_id = data.get('user_id')
    player_name = data.get('player_name', 'Unknown')
    
    if not world_key or not user_id:
        await send_error(websocket, "Missing worldKey or user_id")
        return
    
    # Store connection info
    active_connections[websocket] = {
        'world_key': world_key,
        'user_id': user_id,
        'player_name': player_name,
        'joined_at': time.time()
    }
    
    # Add to world room
    if world_key not in world_rooms:
        world_rooms[world_key] = set()
    world_rooms[world_key].add(websocket)
    
    print(f"[WebSocket] {player_name} joined world {world_key}")
    
    # Send confirmation
    await websocket.send(json.dumps({
        'type': 'joined',
        'worldKey': world_key,
        'player_name': player_name,
        'message': f'Successfully joined world {world_key}'
    }))
    
    # Notify other players
    await broadcast_to_world(world_key, {
        'type': 'player_joined',
        'player_name': player_name,
        'worldKey': world_key,
        'timestamp': datetime.utcnow().isoformat()
    }, exclude_websocket=websocket)

async def handle_leave(websocket, data):
    """Handle player leaving a world"""
    if websocket not in active_connections:
        await send_error(websocket, "Not connected to a world")
        return
    
    conn_info = active_connections[websocket]
    leave_world = data.get('worldKey') or conn_info.get('world_key')
    player_name = conn_info.get('player_name', 'Unknown')
    
    if leave_world and leave_world in world_rooms:
        world_rooms[leave_world].discard(websocket)
        
        if not world_rooms[leave_world]:
            del world_rooms[leave_world]
        
        print(f"[WebSocket] {player_name} left world {leave_world}")
        
        # Send confirmation
        await websocket.send(json.dumps({
            'type': 'left',
            'worldKey': leave_world,
            'message': f'Successfully left world {leave_world}'
        }))
        
        # Notify other players
        await broadcast_to_world(leave_world, {
            'type': 'player_left',
            'player_name': player_name,
            'worldKey': leave_world,
            'timestamp': datetime.utcnow().isoformat()
        })
    
    # Update connection info
    active_connections[websocket]['world_key'] = None

async def handle_chat_message(websocket, data):
    """Handle incoming chat messages with selective storage strategy"""
    if websocket not in active_connections:
        await send_error(websocket, "Not connected to a world")
        return
    
    conn_info = active_connections[websocket]
    world_key = conn_info.get('world_key')
    user_id = conn_info.get('user_id')
    player_name = conn_info.get('player_name', 'Unknown')
    
    if not world_key:
        await send_error(websocket, "Not in a world")
        return
    
    message_text = data.get('message', '').strip()
    channel_id = data.get('channel_id', 'General_1')
    message_type = data.get('message_type', 'normal')
    
    if not message_text:
        await send_error(websocket, "Empty message")
        return
    
    # Update statistics
    storage_stats['total_messages'] += 1
    
    # STEP 1: Always broadcast immediately for real-time chat experience
    timestamp = int(time.time())
    message_response = {
        'type': 'message',
        'player_id': user_id,
        'player_name': player_name,
        'message': message_text,
        'channel_id': channel_id,
        'message_type': message_type,
        'timestamp': datetime.fromtimestamp(timestamp).isoformat(),
        'world_key': world_key
    }
    
    await broadcast_to_world(world_key, message_response)
    storage_stats['broadcasted_messages'] += 1
    print(f"[WebSocket] ⚡ Real-time message broadcasted from {player_name} to world {world_key}")
    
    # STEP 2: Determine if message needs permanent storage
    storage_reason = should_store_message_permanently(message_text, message_type, channel_id, player_name)
    
    if storage_reason:
        print(f"[WebSocket] 🗄️ Message marked for permanent storage: {storage_reason}")
        storage_stats['stored_messages'] += 1
        
        # Send to REST API for validation and permanent storage
        if AIOHTTP_AVAILABLE:
            api_data = {
                'message': message_text,
                'channel_id': channel_id,
                'world_key': world_key,
                'player_name': player_name,
                'user_id': user_id,
                'message_type': message_type,
                'permanent_storage': True,
                'storage_reason': storage_reason
            }
            asyncio.create_task(send_to_rest_api(api_data, world_key, player_name))
        else:
            # Fallback direct database storage for important messages
            await store_important_message(user_id, player_name, channel_id, message_text, world_key, timestamp, message_type, storage_reason)
    else:
        print(f"[WebSocket] 💬 Regular chat message - no permanent storage needed")
    
    # STEP 3: Add to in-memory recent history (for chat history requests)
    add_to_recent_history(world_key, channel_id, message_response)

def should_store_message_permanently(message_text: str, message_type: str, channel_id: str, player_name: str) -> Optional[str]:
    """
    Determine if a message should be permanently stored in database
    Returns: storage reason string if should store, None if should not store
    """
    
    # Always store these message types
    important_types = {
        'gm_broadcast': 'GM Broadcast',
        'guild_motd': 'Guild MOTD', 
        'raid_motd': 'Raid MOTD',
        'daily_motd': 'Daily MOTD',
        'server_announcement': 'Server Announcement',
        'admin_message': 'Admin Message',
        'system_message': 'System Message'
    }
    
    if message_type in important_types:
        return important_types[message_type]
    
    # Store system/special channels
    important_channels = {
        'System': 'System Messages',
        'Announcements': 'Server Announcements', 
        'GM': 'GM Channel',
        'Admin': 'Admin Channel',
        'ModAlert': 'Moderation Alert',
        'ServerStatus': 'Server Status'
    }
    
    if channel_id in important_channels:
        return important_channels[channel_id]
    
    # Store messages from staff/important players
    staff_keywords = ['[GM]', '[ADMIN]', '[MOD]', '[STAFF]']
    for keyword in staff_keywords:
        if keyword.lower() in player_name.lower():
            return f'Staff member message ({keyword})'
    
    # Store messages that might be offensive (for moderation)
    if contains_offensive_content(message_text):
        return 'Content flagged for moderation'
    
    # Store very long messages (might be spam or important announcements)
    if len(message_text) > 200:
        return 'Long message (potential spam or announcement)'
    
    # Store messages with excessive caps (might be spam or important)
    if message_text.isupper() and len(message_text) > 20:
        return 'All caps message (potential spam or announcement)'
    
    # Store messages with excessive repetition
    if has_excessive_repetition(message_text):
        return 'Repetitive content (potential spam)'
    
    # Store messages with URLs (might be spam or important links)
    if contains_urls(message_text):
        return 'Message contains URLs'
    
    # Store trade/economy related messages
    economy_keywords = ['wtb', 'wts', 'wtt', 'selling', 'buying', 'trade', 'auction', 'gold', 'coins']
    message_lower = message_text.lower()
    for keyword in economy_keywords:
        if keyword in message_lower:
            return 'Trade/economy related message'
    
    # Store recruitment messages
    recruitment_keywords = ['recruiting', 'guild invite', 'join guild', 'raid signup', 'lfg', 'lf group', 'lf raid']
    for keyword in recruitment_keywords:
        if keyword in message_lower:
            return 'Recruitment/group formation message'
    
    # Don't store regular chat messages
    return None

def contains_offensive_content(message_text: str) -> bool:
    """Check if message contains potentially offensive content"""
    # Basic profanity filter - expand as needed
    offensive_patterns = [
        r'\bf+u+c+k+\w*',
        r'\bs+h+i+t+\w*', 
        r'\bd+a+m+n+\w*',
        r'\ba+s+s+\w*',
        r'\bb+i+t+c+h+\w*',
        # Add more patterns as needed
    ]
    
    message_lower = message_text.lower()
    for pattern in offensive_patterns:
        if re.search(pattern, message_lower):
            return True
    
    return False

def contains_urls(message_text: str) -> bool:
    """Check if message contains URLs"""
    url_patterns = [
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
        r'www\.(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
        r'[a-zA-Z0-9-]+\.(?:com|net|org|edu|gov|io|co|uk|de|fr|jp|au)\b'
    ]
    
    for pattern in url_patterns:
        if re.search(pattern, message_text, re.IGNORECASE):
            return True
    
    return False

def has_excessive_repetition(message: str) -> bool:
    """Check if message has excessive character or word repetition"""
    # Check for repeated characters (like "aaaaaaa")
    for i in range(len(message) - 4):
        if all(message[i] == message[i+j] for j in range(5)):
            return True
    
    # Check for repeated words
    words = message.split()
    if len(words) > 3:
        for i in range(len(words) - 2):
            if words[i] == words[i+1] == words[i+2]:
                return True
    
    # Check for repeated patterns
    if len(message) > 10:
        for length in range(3, len(message) // 3):
            pattern = message[:length]
            if message.count(pattern) >= 3:
                return True
    
    return False

async def store_important_message(user_id: str, player_name: str, channel_id: str, 
                                  message_text: str, world_key: str, timestamp: int, 
                                  message_type: str, storage_reason: str):
    """Store important messages directly to database"""
    try:
        # Check if user exists
        try:
            user_check = db_execute(
                'SELECT id FROM users WHERE id = ?',
                (user_id,),
                fetchone=True
            )
            actual_user_id = user_id if user_check else f'guest_{user_id}'
        except:
            actual_user_id = f'guest_{user_id}'
        
        # Store with message_type and storage_reason for filtering
        db_execute(
            '''INSERT INTO chat_messages 
               (user_id, player_name, channel_id, message, world_key, timestamp, message_type)
               VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (actual_user_id, player_name, channel_id, message_text, world_key, timestamp, message_type),
            commit=True
        )
        print(f"[WebSocket] 💾 Important message stored: {storage_reason}")
        
    except Exception as e:
        print(f"[WebSocket] ❌ Failed to store important message: {e}")

def add_to_recent_history(world_key: str, channel_id: str, message_data: dict):
    """Add message to in-memory recent history"""
    history_key = f"{world_key}:{channel_id}"
    
    if history_key not in recent_chat_history:
        recent_chat_history[history_key] = []
    
    # Add message to history
    recent_chat_history[history_key].append(message_data)
    
    # Keep only last 50 messages
    if len(recent_chat_history[history_key]) > 50:
        recent_chat_history[history_key] = recent_chat_history[history_key][-50:]
    
    print(f"[WebSocket] 📝 Added to recent history: {history_key} ({len(recent_chat_history[history_key])} messages)")

async def handle_chat_history_request(websocket, data):
    """Handle requests for recent chat history"""
    world_key = data.get('worldKey')
    channel_id = data.get('channel_id', 'General_1')
    limit = min(data.get('limit', 20), 50)
    
    history_key = f"{world_key}:{channel_id}"
    
    if history_key in recent_chat_history:
        recent_messages = recent_chat_history[history_key][-limit:]
        
        await websocket.send(json.dumps({
            'type': 'chat_history',
            'world_key': world_key,
            'channel_id': channel_id,
            'messages': recent_messages,
            'count': len(recent_messages)
        }))
        
        print(f"[WebSocket] 📜 Sent {len(recent_messages)} recent messages to client")
    else:
        await websocket.send(json.dumps({
            'type': 'chat_history',
            'world_key': world_key,
            'channel_id': channel_id,
            'messages': [],
            'count': 0
        }))
        print(f"[WebSocket] 📜 No recent history found for {history_key}")

async def handle_storage_stats_request(websocket, data):
    """Handle requests for storage statistics"""
    uptime = time.time() - storage_stats['start_time']
    storage_percentage = (storage_stats['stored_messages'] / max(storage_stats['total_messages'], 1)) * 100
    
    stats_response = {
        'type': 'storage_stats',
        'total_messages': storage_stats['total_messages'],
        'stored_messages': storage_stats['stored_messages'],
        'broadcasted_messages': storage_stats['broadcasted_messages'],
        'storage_percentage': round(storage_percentage, 2),
        'uptime_seconds': round(uptime, 2),
        'active_connections': len(active_connections),
        'active_worlds': len(world_rooms),
        'recent_history_channels': len(recent_chat_history)
    }
    
    await websocket.send(json.dumps(stats_response))
    print(f"[WebSocket] 📊 Storage stats sent: {storage_percentage:.1f}% stored, {len(active_connections)} connections")

async def send_to_rest_api(api_data: dict, world_key: str, player_name: str):
    """Send message to REST API for validation and permanent storage"""
    if not AIOHTTP_AVAILABLE:
        print(f"[WebSocket] ⚠️ aiohttp not available for REST API call")
        return
        
    try:
        # Use localhost since we're on the same server
        flask_api_url = f"http://localhost:{config.get('PORT', 5000)}/api/chat/send"
        
        async with aiohttp.ClientSession() as session:
            async with session.post(flask_api_url, json=api_data, timeout=5) as response:
                if response.status == 200:
                    result = await response.json()
                    print(f"[WebSocket] ✅ REST API processed important message from {player_name}: {result.get('message', 'Success')}")
                    
                    # Check if message was flagged/blocked
                    if result.get('flagged') or result.get('blocked'):
                        print(f"[WebSocket] 🚩 Important message flagged by REST API: {result.get('reason', 'Unknown')}")
                        
                        # Send correction/deletion message to WebSocket clients
                        correction_message = {
                            'type': 'message_flagged',
                            'original_message': api_data['message'],
                            'player_name': player_name,
                            'reason': result.get('reason', 'Content filter'),
                            'timestamp': datetime.utcnow().isoformat(),
                            'world_key': world_key,
                            'message_type': api_data.get('message_type', 'normal')
                        }
                        await broadcast_to_world(world_key, correction_message)
                        
                else:
                    print(f"[WebSocket] ⚠️ REST API error {response.status} for message from {player_name}")
                    
    except asyncio.TimeoutError:
        print(f"[WebSocket] ⏰ REST API timeout for message from {player_name}")
    except Exception as e:
        print(f"[WebSocket] ❌ REST API error for message from {player_name}: {e}")

async def broadcast_to_world(world_key: str, message: dict, exclude_websocket=None):
    """Broadcast message to all clients in a world"""
    if world_key not in world_rooms:
        return
    
    disconnected_clients = []
    message_json = json.dumps(message)
    
    for websocket in world_rooms[world_key]:
        if websocket == exclude_websocket:
            continue
            
        try:
            await websocket.send(message_json)
        except websockets.exceptions.ConnectionClosed:
            disconnected_clients.append(websocket)
        except Exception as e:
            print(f"[WebSocket] Error broadcasting to client: {e}")
            disconnected_clients.append(websocket)
    
    # Clean up disconnected clients
    for websocket in disconnected_clients:
        await handle_disconnect(websocket)

async def handle_disconnect(websocket):
    """Handle client disconnection"""
    if websocket in active_connections:
        conn_info = active_connections[websocket]
        world_key = conn_info.get('world_key')
        player_name = conn_info.get('player_name', 'Unknown')
        
        # Remove from active connections
        del active_connections[websocket]
        
        # Remove from world room
        if world_key and world_key in world_rooms:
            world_rooms[world_key].discard(websocket)
            
            if not world_rooms[world_key]:
                del world_rooms[world_key]
            else:
                # Notify other players
                await broadcast_to_world(world_key, {
                    'type': 'player_disconnected',
                    'player_name': player_name,
                    'timestamp': datetime.utcnow().isoformat()
                })
        
        print(f"[WebSocket] {player_name} disconnected from world {world_key}")

async def handle_ping(websocket, data):
    """Handle ping requests"""
    await websocket.send(json.dumps({
        'type': 'pong',
        'timestamp': datetime.utcnow().isoformat()
    }))

async def handle_status_check(websocket, data):
    """Handle status check requests"""
    await websocket.send(json.dumps({
        'type': 'status_response',
        'status': 'online',
        'server': 'websocket_chat',
        'connections': len(active_connections),
        'worlds': len(world_rooms),
        'timestamp': datetime.utcnow().isoformat(),
        'storage_stats': {
            'total_messages': storage_stats['total_messages'],
            'stored_percentage': round((storage_stats['stored_messages'] / max(storage_stats['total_messages'], 1)) * 100, 2)
        }
    }))

async def send_error(websocket, error_message):
    """Send error message to client"""
    try:
        await websocket.send(json.dumps({
            'type': 'error',
            'message': error_message,
            'timestamp': datetime.utcnow().isoformat()
        }))
    except Exception as e:
        print(f"[WebSocket] Failed to send error message: {e}")

async def main():
    """Start the WebSocket server"""
    print(f"[WebSocket] Starting WebSocket Chat Server...")
    print(f"[WebSocket] Host: {WEBSOCKET_HOST}")
    print(f"[WebSocket] Port: {WEBSOCKET_PORT}")
    print(f"[WebSocket] SSL Enabled: {SSL_ENABLED}")
    print(f"[WebSocket] aiohttp Available: {AIOHTTP_AVAILABLE}")
    
    # Setup SSL context if enabled
    ssl_context = None
    if SSL_ENABLED and SSL_CERT_PATH and SSL_KEY_PATH:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(SSL_CERT_PATH, SSL_KEY_PATH)
        print(f"[WebSocket] SSL context loaded from {SSL_CERT_PATH}")
    
    try:
        # Start the WebSocket server
        server = await websockets.serve(
            handle_client,
            WEBSOCKET_HOST,
            WEBSOCKET_PORT,
            ssl=ssl_context,
            ping_interval=30,
            ping_timeout=10
        )
        
        print(f"[WebSocket] ✅ WebSocket Chat Server started successfully!")
        print(f"[WebSocket] 🌐 Listening on {'wss' if SSL_ENABLED else 'ws'}://{WEBSOCKET_HOST}:{WEBSOCKET_PORT}")
        print(f"[WebSocket] 🔄 Smart selective storage enabled - Regular chat live-only, Important messages stored permanently")
        
        # Keep the server running
        await server.wait_closed()
        
    except Exception as e:
        print(f"[WebSocket] ❌ Failed to start WebSocket server: {e}")
        raise

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"[WebSocket] Server shutdown requested")
    except Exception as e:
        print(f"[WebSocket] Server error: {e}")