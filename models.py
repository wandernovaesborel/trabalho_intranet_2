from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from database import get_db_connection
import sqlite3

class User:
    def __init__(self, username, email, password=None, password_hash=None):
        self.username = username
        self.email = email
        if password:
            self.password_hash = generate_password_hash(password)
        elif password_hash:
            self.password_hash = password_hash
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def save(self):
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                'INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)',
                (self.username, self.email, self.password_hash, datetime.now().isoformat())
            )
            user_id = cursor.lastrowid
            conn.commit()
            self._register_default_consents(user_id)
            return user_id
        except sqlite3.IntegrityError as e:
            conn.rollback()
            raise ValueError("Username or email already exists")
        finally:
            conn.close()
    
    def _register_default_consents(self, user_id):
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                'INSERT INTO consents (user_id, consent_type, consent_given, given_at) VALUES (?, ?, ?, ?)',
                (user_id, 'data_processing', 1, datetime.now().isoformat())
            )
            cursor.execute(
                'INSERT INTO consents (user_id, consent_type, consent_given, given_at) VALUES (?, ?, ?, ?)',
                (user_id, 'cookies', 0, datetime.now().isoformat())
            )
            conn.commit()
        finally:
            conn.close()
    
    @staticmethod
    def get_by_username(username):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user_data = cursor.fetchone()
        conn.close()
        
        if user_data:
            return User(
                username=user_data['username'],
                email=user_data['email'],
                password_hash=user_data['password_hash']
            ), user_data['id']  # Agora retorna (User, id)
        return None, None
    
    @staticmethod
    def get_by_id(user_id):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user_data = cursor.fetchone()
        conn.close()
        
        if user_data:
            return User(
                username=user_data['username'],
                email=user_data['email'],
                password_hash=user_data['password_hash']
            )
        return None
    
    @staticmethod
    def log_access(user_id, action, ip_address=None, user_agent=None):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO access_logs (user_id, action, ip_address, user_agent, timestamp) VALUES (?, ?, ?, ?, ?)',
            (user_id, action, ip_address, user_agent, datetime.now().isoformat())
        )
        conn.commit()
        conn.close()

class DataRequest:
    @staticmethod
    def create_request(user_id, request_type, request_data=None):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO data_requests (user_id, request_type, request_data, created_at) VALUES (?, ?, ?, ?)',
            (user_id, request_type, request_data, datetime.now().isoformat())
        )
        request_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return request_id
    
    @staticmethod
    def get_user_requests(user_id):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM data_requests WHERE user_id = ? ORDER BY created_at DESC', (user_id,))
        requests = cursor.fetchall()
        conn.close()
        return requests