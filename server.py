from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import uuid
import os
import bcrypt

sessions = {}   # sessie-token: username
posts = []      # lijst van dicts met 'username' en 'content'
USERS_FILE = 'users.json'

# Helperfuncties
def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f)

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode(), hashed_password.encode())

users = load_users()

class SimpleHandler(BaseHTTPRequestHandler):
    def _set_headers(self, status=200):
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', 'https://feestboek.onrender.com')  # Specifieke frontend toestaan
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', 'https://feestboek.onrender.com')  # Voorkomt blokkering
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        path = self.path

        try:
            data = json.loads(post_data)
        except:
            self._set_headers(400)
            self.wfile.write(json.dumps({'error': 'Invalid JSON'}).encode())
            return

        # === SIGNUP ===
        if path == '/signup':
            username = data.get('username')
            password = data.get('password')
            if not username or not password:
                self._set_headers(400)
                self.wfile.write(json.dumps({'error': 'Username and password required'}).encode())
            elif username in users:
                self._set_headers(409)
                self.wfile.write(json.dumps({'error': 'User already exists'}).encode())
            else:
                hashed_password = hash_password(password)
                users[username] = hashed_password
                save_users(users)
                self._set_headers(201)
                self.wfile.write(json.dumps({'message': 'User created'}).encode())

        # === LOGIN ===
        elif path == '/login':
            username = data.get('username')
            password = data.get('password')
            if not username or not password:
                self._set_headers(400)
                self.wfile.write(json.dumps({'error': 'Username and password required'}).encode())
            elif username in users and verify_password(password, users[username]):
                token = str(uuid.uuid4())
                sessions[token] = username
                self._set_headers(200)
                self.wfile.write(json.dumps({'message': 'Login successful', 'token': token, 'username': username}).encode())
            else:
                self._set_headers(401)
                self.wfile.write(json.dumps({'error': 'Invalid credentials'}).encode())

        # === POSTS ===
        elif path == '/posts':
            token = self.headers.get('Authorization')
            if not token or token not in sessions:
                self._set_headers(401)
                self.wfile.write(json.dumps({'error': 'Unauthorized'}).encode())
                return

            content = data.get('content')
            if content:
                username = sessions[token]
                posts.append({'username': username, 'content': content})
                self._set_headers(201)
                self.wfile.write(json.dumps({'message': 'Post toegevoegd!'}).encode())
            else:
                self._set_headers(400)
                self.wfile.write(json.dumps({'error': 'Content required'}).encode())

        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({'error': 'Not found'}).encode())

    def do_GET(self):
        if self.path == '/posts':
            self._set_headers()
            self.wfile.write(json.dumps(posts[::-1]).encode())
        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({'error': 'Not found'}).encode())

def run(server_class=HTTPServer, handler_class=SimpleHandler, port=5000):
    server_address = ('0.0.0.0', port)
    httpd = server_class(server_address, handler_class)
    print(f'Start server op http://0.0.0.0:{port}')
    httpd.serve_forever()

if __name__ == '__main__':
    run()
