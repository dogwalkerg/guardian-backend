CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  phone VARCHAR(32) UNIQUE NOT NULL,
  display_name VARCHAR(120),
  avatar_url TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS families (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(120) NOT NULL DEFAULT '我的家庭',
  owner_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS family_members (
  family_id UUID NOT NULL REFERENCES families(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role VARCHAR(32) NOT NULL DEFAULT 'parent',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (family_id, user_id)
);

CREATE TABLE IF NOT EXISTS children (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  family_id UUID NOT NULL REFERENCES families(id) ON DELETE CASCADE,
  name VARCHAR(120) NOT NULL DEFAULT '孩子',
  phone VARCHAR(32),
  avatar_url TEXT,
  active BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS devices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  child_id UUID NOT NULL REFERENCES children(id) ON DELETE CASCADE,
  device_token_hash VARCHAR(128) UNIQUE NOT NULL,
  device_name VARCHAR(120),
  brand VARCHAR(80),
  model VARCHAR(120),
  android_version VARCHAR(40),
  client_version VARCHAR(40),
  battery INTEGER,
  network_type VARCHAR(40),
  online BOOLEAN NOT NULL DEFAULT false,
  last_heartbeat_at TIMESTAMPTZ,
  last_seen_at TIMESTAMPTZ,
  permissions JSONB NOT NULL DEFAULT '{}'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS installed_apps (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  package_name VARCHAR(255) NOT NULL,
  app_name VARCHAR(255) NOT NULL,
  version_name VARCHAR(80),
  version_code VARCHAR(80),
  icon_url TEXT,
  is_system BOOLEAN NOT NULL DEFAULT false,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(device_id, package_name)
);

CREATE TABLE IF NOT EXISTS app_policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  child_id UUID NOT NULL REFERENCES children(id) ON DELETE CASCADE,
  package_name VARCHAR(255) NOT NULL,
  app_name VARCHAR(255),
  policy_type SMALLINT NOT NULL DEFAULT 1,
  daily_limit_seconds INTEGER,
  enabled BOOLEAN NOT NULL DEFAULT true,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(child_id, package_name)
);

CREATE TABLE IF NOT EXISTS app_function_policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  child_id UUID NOT NULL REFERENCES children(id) ON DELETE CASCADE,
  package_name VARCHAR(255) NOT NULL,
  function_code VARCHAR(80) NOT NULL,
  disabled BOOLEAN NOT NULL DEFAULT false,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(child_id, package_name, function_code)
);

CREATE TABLE IF NOT EXISTS control_policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  child_id UUID NOT NULL REFERENCES children(id) ON DELETE CASCADE,
  name VARCHAR(120) NOT NULL DEFAULT '默认管控策略',
  enabled BOOLEAN NOT NULL DEFAULT true,
  no_play_enabled BOOLEAN NOT NULL DEFAULT false,
  lock_enabled BOOLEAN NOT NULL DEFAULT false,
  allow_call BOOLEAN NOT NULL DEFAULT true,
  emergency_numbers JSONB NOT NULL DEFAULT '[]'::jsonb,
  periods JSONB NOT NULL DEFAULT '[]'::jsonb,
  daily_limit_seconds INTEGER,
  timezone VARCHAR(64) NOT NULL DEFAULT 'Asia/Shanghai',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(child_id)
);

CREATE TABLE IF NOT EXISTS usage_records (
  id BIGSERIAL PRIMARY KEY,
  device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  child_id UUID NOT NULL REFERENCES children(id) ON DELETE CASCADE,
  package_name VARCHAR(255) NOT NULL,
  app_name VARCHAR(255),
  started_at TIMESTAMPTZ NOT NULL,
  ended_at TIMESTAMPTZ,
  use_seconds INTEGER NOT NULL DEFAULT 0,
  day DATE NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_usage_child_day ON usage_records(child_id, day);

CREATE TABLE IF NOT EXISTS location_records (
  id BIGSERIAL PRIMARY KEY,
  device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  child_id UUID NOT NULL REFERENCES children(id) ON DELETE CASCADE,
  latitude NUMERIC(10,7) NOT NULL,
  longitude NUMERIC(10,7) NOT NULL,
  accuracy NUMERIC(10,2),
  address TEXT,
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  source VARCHAR(40)
);
CREATE INDEX IF NOT EXISTS idx_location_child_time ON location_records(child_id, recorded_at DESC);

CREATE TABLE IF NOT EXISTS commands (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  child_id UUID NOT NULL REFERENCES children(id) ON DELETE CASCADE,
  command VARCHAR(80) NOT NULL,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  status VARCHAR(32) NOT NULL DEFAULT 'queued',
  attempts INTEGER NOT NULL DEFAULT 0,
  expires_at TIMESTAMPTZ,
  sent_at TIMESTAMPTZ,
  acknowledged_at TIMESTAMPTZ,
  result JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_commands_device_status ON commands(device_id, status, created_at);

CREATE TABLE IF NOT EXISTS operation_logs (
  id BIGSERIAL PRIMARY KEY,
  family_id UUID REFERENCES families(id) ON DELETE SET NULL,
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  child_id UUID REFERENCES children(id) ON DELETE SET NULL,
  device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
  action VARCHAR(120) NOT NULL,
  detail JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS captcha_codes (
  phone VARCHAR(32) PRIMARY KEY,
  code VARCHAR(16) NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS bind_tokens (
  token VARCHAR(128) PRIMARY KEY,
  family_id UUID NOT NULL REFERENCES families(id) ON DELETE CASCADE,
  child_id UUID REFERENCES children(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
