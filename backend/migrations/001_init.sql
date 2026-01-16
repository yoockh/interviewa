-- INITIAL MIGRATION SCRIPT FOR USER AUTHENTICATION SYSTEM
--========================================================================
-- Tables: users
--========================================================================
CREATE TYPE user_role AS ENUM ('user', 'admin');

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT,
    role user_role NOT NULL DEFAULT 'user',

    email_verified_at TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

--========================================================================
-- Tables: sessions
--========================================================================
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    token_hash TEXT NOT NULL,
    device_name VARCHAR(100),
    device_id VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,

    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,

    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX idx_sessions_active ON sessions(user_id) WHERE revoked_at IS NULL;

--========================================================================
-- Tables: verification_tokens
--========================================================================
CREATE TYPE verification_type AS ENUM (
    'email_verify',
    'password_reset',
    'magic_login'
);

CREATE TABLE verification_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    token_hash TEXT NOT NULL,
    type verification_type NOT NULL,

    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP,

    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_verification_tokens_user_id ON verification_tokens(user_id);
CREATE INDEX idx_verification_tokens_token_hash ON verification_tokens(token_hash);
CREATE INDEX idx_verification_tokens_active ON verification_tokens(user_id) WHERE used_at IS NULL;

--========================================================================
-- Tables: mfa_secrets
--========================================================================
CREATE TABLE mfa_secrets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,

    secret TEXT NOT NULL,
    enabled_at TIMESTAMP,

    created_at TIMESTAMP DEFAULT NOW()
);

--========================================================================
-- Tables: security_logs
--========================================================================
CREATE TYPE security_action AS ENUM (
    'login_success',
    'login_failed',
    'logout',
    'password_reset',
    'mfa_failed',
    'session_revoked'
);

CREATE TABLE security_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID REFERENCES users(id),
    ip_address VARCHAR(45),
    action security_action NOT NULL,

    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_security_logs_user_id ON security_logs(user_id);
CREATE INDEX idx_security_logs_created_at ON security_logs(created_at);
