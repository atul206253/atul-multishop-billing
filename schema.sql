PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, phone TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tenants (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, slug TEXT NOT NULL UNIQUE,
 owner_id TEXT NOT NULL, logo_data TEXT, address TEXT, phone TEXT,
 status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL,
 FOREIGN KEY(owner_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS memberships (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL, tenant_id TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('owner','operator')),
 status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('pending','active','rejected','suspended')),
 created_at TEXT NOT NULL,
 UNIQUE(user_id, tenant_id),
 FOREIGN KEY(user_id) REFERENCES users(id),
 FOREIGN KEY(tenant_id) REFERENCES tenants(id)
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at INTEGER NOT NULL,
 FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS bills (
 id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, owner_id TEXT NOT NULL,
 customer_name TEXT NOT NULL, customer_mobile TEXT, bill_date TEXT NOT NULL,
 items_json TEXT NOT NULL, extra_fee REAL NOT NULL DEFAULT 0, total REAL NOT NULL,
 payment_mode TEXT NOT NULL, utr TEXT, payment_status TEXT NOT NULL,
 created_at TEXT NOT NULL,
 FOREIGN KEY(tenant_id) REFERENCES tenants(id),
 FOREIGN KEY(owner_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_bills_tenant ON bills(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_bills_owner ON bills(owner_id, created_at DESC);
CREATE TABLE IF NOT EXISTS services (
 id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL, rate REAL NOT NULL DEFAULT 0,
 FOREIGN KEY(tenant_id) REFERENCES tenants(id)
);
CREATE TABLE IF NOT EXISTS reports (
 id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, reporter_id TEXT NOT NULL,
 subject TEXT NOT NULL, details TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
 created_at TEXT NOT NULL,
 FOREIGN KEY(tenant_id) REFERENCES tenants(id),
 FOREIGN KEY(reporter_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS audit_logs (
 id TEXT PRIMARY KEY, actor_id TEXT NOT NULL, tenant_id TEXT,
 action TEXT NOT NULL, details TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS platform_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
