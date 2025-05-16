import threading
import sqlite3
import uuid
import smtplib
import time
import json
import os
from email.message import EmailMessage
from flask import Flask, request, jsonify
import tkinter as tk
from tkinter import ttk, messagebox

# ---- Paths & Schema ----
CONFIG_PATH = 'config.json'
DB_SCHEMA = '''
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE,
  email TEXT UNIQUE,
  password TEXT
);
CREATE TABLE IF NOT EXISTS reset_tokens (
  token TEXT PRIMARY KEY,
  user_id TEXT,
  expires_at INTEGER
);
'''

# ---- Defaults ----
DEFAULT_CONFIG = {
  "DB_PATH": "auth.db",
  "HOST": "0.0.0.0",
  "PORT": 5000,
  "SMTP_HOST": "smtp.ionos.com",
  "SMTP_PORT": 587,
  "SMTP_USER": "no-reply@vespeyr.com",
  "SMTP_PASS": "",
  "RESET_URL_BASE": "https://api.vespeyr.com/auth/reset-password?token="
}

# ---- Config load/save ----
def load_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH,'r') as f:
            cfg = json.load(f)
        for k,v in DEFAULT_CONFIG.items():
            cfg.setdefault(k, v)
        return cfg
    else:
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG.copy()

def save_config(cfg):
    with open(CONFIG_PATH,'w') as f:
        json.dump(cfg, f, indent=2)

config = load_config()

# ---- DB init ----
def init_db():
    conn = sqlite3.connect(config["DB_PATH"])
    c = conn.cursor()
    for stmt in DB_SCHEMA.strip().split(';'):
        if stmt.strip():
            c.execute(stmt)
    conn.commit()
    conn.close()

# ---- Email helper ----
def send_email(to_email, subject, body):
    msg = EmailMessage()
    msg['From'] = config["SMTP_USER"]
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.set_content(body)
    with smtplib.SMTP(config["SMTP_HOST"], config["SMTP_PORT"]) as smtp:
        smtp.starttls()
        smtp.login(config["SMTP_USER"], config["SMTP_PASS"])
        smtp.send_message(msg)

# ---- Flask app ----
app = Flask(__name__)

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'ok',
        'uptime': time.time()
    }), 200

@app.route('/auth/register', methods=['POST'])
def register():
    data = request.json or {}
    for key in ('username','email','password'):
        if key not in data:
            return jsonify({'error': f'{key} required'}), 400
    user_id = str(uuid.uuid4())
    conn = sqlite3.connect(config["DB_PATH"]); c = conn.cursor()
    try:
        c.execute(
            'INSERT INTO users VALUES (?,?,?,?)',
            (user_id, data['username'], data['email'], data['password'])
        )
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({'error':'username or email already exists'}),409
    finally:
        conn.close()
    return jsonify({'id': user_id}), 201

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.json or {}
    for key in ('username','password'):
        if key not in data:
            return jsonify({'error': f'{key} required'}),400
    conn = sqlite3.connect(config["DB_PATH"]); c = conn.cursor()
    c.execute(
        'SELECT id FROM users WHERE username=? AND password=?',
        (data['username'], data['password'])
    )
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify({'error':'invalid credentials'}),401
    return jsonify({'id': row[0]}),200

@app.route('/auth/request-password-reset', methods=['POST'])
def request_reset():
    data = request.json or {}
    if 'email' not in data:
        return jsonify({'error':'email required'}),400
    conn = sqlite3.connect(config["DB_PATH"]); c = conn.cursor()
    c.execute('SELECT id FROM users WHERE email=?',(data['email'],))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({'error':'email not found'}),404
    user_id = row[0]
    token = str(uuid.uuid4())
    expires = int(time.time()) + 3600
    c.execute(
      'INSERT INTO reset_tokens VALUES (?,?,?)',
      (token, user_id, expires)
    )
    conn.commit()
    conn.close()
    link = config["RESET_URL_BASE"] + token
    send_email(data['email'],
               'Reset your Vespeyr password',
               f'Click here to reset: {link}')
    return jsonify({'message':'reset email sent'}),200

@app.route('/auth/reset-password', methods=['POST'])
def reset_password():
    data = request.json or {}
    for key in ('token','new_password'):
        if key not in data:
            return jsonify({'error':f'{key} required'}),400
    conn = sqlite3.connect(config["DB_PATH"]); c = conn.cursor()
    c.execute(
      'SELECT user_id,expires_at FROM reset_tokens WHERE token=?',
      (data['token'],)
    )
    row = c.fetchone()
    if not row or row[1] < int(time.time()):
        conn.close()
        return jsonify({'error':'invalid or expired token'}),400
    user_id = row[0]
    c.execute(
      'UPDATE users SET password=? WHERE id=?',
      (data['new_password'], user_id)
    )
    c.execute('DELETE FROM reset_tokens WHERE token=?',(data['token'],))
    conn.commit()
    conn.close()
    return jsonify({'message':'password reset successful'}),200

# ---- Server control ----
server_running = False
server_thread = None

def run_server(host, port):
    global server_running
    server_running = True
    app.run(host=host, port=port, threaded=True)
    server_running = False

def toggle_server():
    global server_thread
    if not server_running:
        # start
        for key, var in gui_vars.items():
            val = var.get()
            config[key] = int(val) if key in ("PORT","SMTP_PORT") else val
        save_config(config)
        server_thread = threading.Thread(
            target=run_server,
            args=(config["HOST"], config["PORT"]),
            daemon=True
        )
        server_thread.start()
        status_var.set(f'Running on {config["HOST"]}:{config["PORT"]}')
        btn_toggle.config(text='Stop')
    else:
        # stop
        messagebox.showinfo(
          'Cannot Stop Automatically',
          'Use CTRL+C in the console to stop the Flask server.'
        )
        # reset UI
        status_var.set('Stopped')
        btn_toggle.config(text='Start')

# ---- GUI ----
init_db()
root = tk.Tk()
root.title('Vespeyr Auth Server Console')

main = ttk.Frame(root, padding=10)
main.grid()

# build config entries
gui_vars = {}
for idx, (key, val) in enumerate(config.items()):
    ttk.Label(main, text=key+':').grid(column=0, row=idx, sticky='e')
    var = tk.StringVar(value=str(val))
    ttk.Entry(main, textvariable=var, width=40).grid(column=1, row=idx, sticky='w', pady=2)
    gui_vars[key] = var

# status + toggle button
status_var = tk.StringVar(value='Stopped')
ttk.Label(main, textvariable=status_var, foreground='blue') \
    .grid(column=0, row=len(config), columnspan=2, pady=5)

btn_toggle = ttk.Button(main, text='Start', command=toggle_server)
btn_toggle.grid(column=0, row=len(config)+1, columnspan=2, pady=10)

root.mainloop()
