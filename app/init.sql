-- SOC-Lab Database Initialization
-- This creates sample data for SQL injection scenarios

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL,
    credential_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create sensitive_data table (for SQLi demonstration)
CREATE TABLE IF NOT EXISTS sensitive_data (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    secret_key VARCHAR(255),
    credit_card VARCHAR(20),
    ssn VARCHAR(15)
);

-- Create audit_log table
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    action VARCHAR(100),
    table_name VARCHAR(50),
    user_id INTEGER,
    old_data JSONB,
    new_data JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert sample users
INSERT INTO users (username, email, credential_hash, role) VALUES
    ('admin', 'admin@soclab.local', 'demo-hash-admin', 'admin'),
    ('john_doe', 'john@soclab.local', 'demo-hash-john', 'user'),
    ('jane_smith', 'jane@soclab.local', 'demo-hash-jane', 'user'),
    ('bob_wilson', 'bob@soclab.local', 'demo-hash-bob', 'user'),
    ('alice_jones', 'alice@soclab.local', 'demo-hash-alice', 'moderator')
ON CONFLICT (username) DO NOTHING;

-- Insert sample sensitive data
INSERT INTO sensitive_data (user_id, secret_key, credit_card, ssn) VALUES
    (1, 'demo_admin_key_12345', '4111-1111-1111-1111', '123-45-6789'),
    (2, 'demo_john_key_67890', '4222-2222-2222-2222', '234-56-7890'),
    (3, 'demo_jane_key_11111', '4333-3333-3333-3333', '345-67-8901')
ON CONFLICT DO NOTHING;

-- Create index for faster lookups
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

