-- KeepSpace DB Initial Schema

CREATE TABLE IF NOT EXISTS folders (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  parent_id TEXT REFERENCES folders(id) ON DELETE CASCADE,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS documents (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  type TEXT NOT NULL,          -- 'pdf', 'image', 'video', 'link', 'other'
  mime_type TEXT,              -- exact mime type e.g., 'application/pdf', 'image/png'
  size INTEGER,                -- size in bytes (NULL for links)
  url TEXT NOT NULL,           -- R2 storage key or external URL for links
  parent_id TEXT REFERENCES folders(id) ON DELETE CASCADE, -- NULL means root
  description TEXT,
  favorite INTEGER DEFAULT 0,  -- 0 = false, 1 = true
  thumbnail_url TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

-- Indexing for quick lookups
CREATE INDEX IF NOT EXISTS idx_folders_parent ON folders(parent_id);
CREATE INDEX IF NOT EXISTS idx_documents_parent ON documents(parent_id);
CREATE INDEX IF NOT EXISTS idx_documents_favorite ON documents(favorite);
