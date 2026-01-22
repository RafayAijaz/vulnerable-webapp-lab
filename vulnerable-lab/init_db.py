#!/usr/bin/env python3
import sqlite3
import hashlib
import os

def init_database():
    print("Initializing database...")
    
    # Create data directory if it doesn't exist
    if not os.path.exists('data'):
        os.makedirs('data')
    
    db_path = 'data/database.db'
    
    # Remove existing database to start fresh
    if os.path.exists(db_path):
        os.remove(db_path)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            is_admin INTEGER DEFAULT 0
        )
    ''')
    
    # Create posts table
    cursor.execute('''
        CREATE TABLE posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT NOT NULL,
            content TEXT,
            public INTEGER DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Insert default users
    users = [
        ('admin', hashlib.md5('admin123'.encode()).hexdigest(), 'admin@vulnlab.com', 1),
        ('alice', hashlib.md5('password123'.encode()).hexdigest(), 'alice@example.com', 0),
        ('bob', hashlib.md5('bobpassword'.encode()).hexdigest(), 'bob@example.com', 0),
        ('test', hashlib.md5('test'.encode()).hexdigest(), 'test@example.com', 0)
    ]
    
    for user in users:
        cursor.execute("INSERT INTO users (username, password, email, is_admin) VALUES (?, ?, ?, ?)", user)
    
    # Insert sample posts
    posts = [
        (1, 'Welcome to Vulnerable Lab', 'This application contains intentional vulnerabilities for educational purposes.', 1),
        (1, 'Admin Instructions', 'Important: Keep this application isolated from production networks.', 0),
        (2, 'Hello from Alice', 'I am testing this vulnerable application.', 1),
        (3, 'Bobs Private Thoughts', 'This post should not be publicly accessible.', 0),
        (4, 'Test User Post', 'Just another test post here.', 1)
    ]
    
    for post in posts:
        cursor.execute("INSERT INTO posts (user_id, title, content, public) VALUES (?, ?, ?, ?)", post)
    
    conn.commit()
    conn.close()
    
    print("Database initialized successfully!")
    print(f"Database created at: {db_path}")
    print("Created tables: users, posts")
    print("Created users: admin, alice, bob, test")

if __name__ == '__main__':
    init_database()
