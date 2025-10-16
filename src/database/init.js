import Database from 'better-sqlite3';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const dbPath = join(__dirname, '../../data/threats.db');

export const db = new Database(dbPath, { verbose: console.log });

// Enable WAL mode for better concurrent access
db.pragma('journal_mode = WAL');

// Initialize database tables first
db.exec(`
  CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event_type TEXT,
    username TEXT,
    source_ip TEXT,
    destination_ip TEXT,
    status TEXT,
    message TEXT,
    raw_data TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    affected_entity TEXT,
    source_ip TEXT,
    event_count INTEGER DEFAULT 1,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    status TEXT DEFAULT 'open',
    ai_summary TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )
`);

db.exec(`
  CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);
  CREATE INDEX IF NOT EXISTS idx_logs_source_ip ON logs(source_ip);
  CREATE INDEX IF NOT EXISTS idx_logs_username ON logs(username);
  CREATE INDEX IF NOT EXISTS idx_logs_event_type ON logs(event_type);
  CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
  CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
  CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
`);

export function initializeDatabase() {
  console.log('Database initialized successfully');
}

// Prepared statements for better performance
export const insertLog = db.prepare(`
  INSERT INTO logs (timestamp, event_type, username, source_ip, destination_ip, status, message, raw_data)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`);

export const insertAlert = db.prepare(`
  INSERT INTO alerts (alert_type, severity, title, description, affected_entity, source_ip, event_count, first_seen, last_seen, ai_summary)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

export const getAlerts = db.prepare(`
  SELECT * FROM alerts
  WHERE status = ?
  ORDER BY created_at DESC
  LIMIT ? OFFSET ?
`);

export const getLogsByIP = db.prepare(`
  SELECT * FROM logs
  WHERE source_ip = ?
  ORDER BY timestamp DESC
`);

export const getRecentLogs = db.prepare(`
  SELECT * FROM logs
  ORDER BY created_at DESC
  LIMIT ?
`);
