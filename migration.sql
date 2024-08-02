BEGIN;

CREATE TABLE alembic_version (
    version_num VARCHAR(32) NOT NULL, 
    CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
);

-- Running upgrade  -> 25d814bc83ed

CREATE TYPE "UserRole" AS ENUM ('ANONYMOUS', 'AUTHENTICATED', 'MANAGER', 'ADMIN');

CREATE TABLE users (
    id UUID NOT NULL, 
    nickname VARCHAR(50) NOT NULL, 
    email VARCHAR(255) NOT NULL, 
    first_name VARCHAR(100), 
    last_name VARCHAR(100), 
    bio VARCHAR(500), 
    profile_picture_url VARCHAR(255), 
    linkedin_profile_url VARCHAR(255), 
    github_profile_url VARCHAR(255), 
    role "UserRole" NOT NULL, 
    is_professional BOOLEAN, 
    professional_status_updated_at TIMESTAMP WITH TIME ZONE, 
    last_login_at TIMESTAMP WITH TIME ZONE, 
    failed_login_attempts INTEGER, 
    is_locked BOOLEAN, 
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(), 
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now(), 
    verification_token VARCHAR, 
    email_verified BOOLEAN NOT NULL, 
    hashed_password VARCHAR(255) NOT NULL, 
    PRIMARY KEY (id)
);

CREATE UNIQUE INDEX ix_users_email ON users (email);

CREATE UNIQUE INDEX ix_users_nickname ON users (nickname);

INSERT INTO alembic_version (version_num) VALUES ('25d814bc83ed') RETURNING alembic_version.version_num;

-- Running upgrade 25d814bc83ed -> e5061e49c752

CREATE TABLE users (
    id UUID NOT NULL, 
    profile_picture_url VARCHAR(255), 
    nickname VARCHAR(50) NOT NULL, 
    email VARCHAR(255) NOT NULL, 
    first_name VARCHAR(100), 
    last_name VARCHAR(100), 
    bio VARCHAR(500), 
    linkedin_profile_url VARCHAR(255), 
    github_profile_url VARCHAR(255), 
    role "UserRole" NOT NULL, 
    is_professional BOOLEAN, 
    professional_status_updated_at TIMESTAMP WITH TIME ZONE, 
    last_login_at TIMESTAMP WITH TIME ZONE, 
    failed_login_attempts INTEGER, 
    is_locked BOOLEAN, 
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(), 
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now(), 
    verification_token VARCHAR, 
    email_verified BOOLEAN NOT NULL, 
    hashed_password VARCHAR(255) NOT NULL, 
    PRIMARY KEY (id)
);

CREATE UNIQUE INDEX ix_users_email ON users (email);

CREATE UNIQUE INDEX ix_users_nickname ON users (nickname);

UPDATE alembic_version SET version_num='e5061e49c752' WHERE alembic_version.version_num = '25d814bc83ed';

-- Running upgrade e5061e49c752 -> ed9b2e857262

CREATE TABLE users (
    id UUID NOT NULL, 
    profile_picture_url VARCHAR(255), 
    nickname VARCHAR(50) NOT NULL, 
    email VARCHAR(255) NOT NULL, 
    first_name VARCHAR(100), 
    last_name VARCHAR(100), 
    bio VARCHAR(500), 
    linkedin_profile_url VARCHAR(255), 
    github_profile_url VARCHAR(255), 
    role "UserRole" NOT NULL, 
    is_professional BOOLEAN, 
    professional_status_updated_at TIMESTAMP WITH TIME ZONE, 
    last_login_at TIMESTAMP WITH TIME ZONE, 
    failed_login_attempts INTEGER, 
    is_locked BOOLEAN, 
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(), 
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now(), 
    verification_token VARCHAR, 
    email_verified BOOLEAN NOT NULL, 
    hashed_password VARCHAR(255) NOT NULL, 
    PRIMARY KEY (id)
);

CREATE UNIQUE INDEX ix_users_email ON users (email);

CREATE UNIQUE INDEX ix_users_nickname ON users (nickname);

UPDATE alembic_version SET version_num='ed9b2e857262' WHERE alembic_version.version_num = 'e5061e49c752';

COMMIT;

