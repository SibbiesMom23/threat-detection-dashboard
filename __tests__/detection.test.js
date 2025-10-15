import Database from 'better-sqlite3';

// Create test database and initialize before importing rules
const testDb = new Database(':memory:');
testDb.pragma('journal_mode = WAL');

// Initialize schema
testDb.exec(`
  CREATE TABLE logs (
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
  );

  CREATE TABLE alerts (
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
  );

  CREATE INDEX idx_logs_timestamp ON logs(timestamp);
  CREATE INDEX idx_logs_source_ip ON logs(source_ip);
  CREATE INDEX idx_logs_username ON logs(username);
  CREATE INDEX idx_logs_event_type ON logs(event_type);
`);

const insertLog = testDb.prepare(`
  INSERT INTO logs (timestamp, event_type, username, source_ip, destination_ip, status, message, raw_data)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`);

const insertAlert = testDb.prepare(`
  INSERT INTO alerts (alert_type, severity, title, description, affected_entity, source_ip, event_count, first_seen, last_seen, ai_summary)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

// Mock the db module for detection rules
import { jest } from '@jest/globals';
jest.unstable_mockModule('../src/database/init.js', () => ({
  db: testDb,
  insertAlert: insertAlert,
}));

const { detectBruteForce, detectOffHoursAccess } = await import('../src/detection/rules.js');

describe('Threat Detection Rules', () => {
  beforeEach(() => {
    // Clear tables before each test
    testDb.exec('DELETE FROM logs');
    testDb.exec('DELETE FROM alerts');
  });

  afterAll(() => {
    testDb.close();
  });

  describe('Brute Force Detection', () => {
    test('should detect brute force attack with 5+ failed logins from same IP', () => {
      // Insert 6 failed login attempts from same IP within 5 minutes
      // Use current time to pass the time window check
      const baseTime = new Date();
      const sourceIP = '192.168.1.100';

      for (let i = 0; i < 6; i++) {
        const timestamp = new Date(baseTime.getTime() - (60 - i) * 1000).toISOString(); // Recent timestamps
        insertLog.run(
          timestamp,
          'login',
          'admin',
          sourceIP,
          null,
          'failed',
          'Invalid credentials',
          JSON.stringify({ attempt: i + 1 })
        );
      }

      const results = detectBruteForce();

      expect(results.length).toBeGreaterThan(0);
      expect(results[0]).toMatchObject({
        source_ip: sourceIP,
        attempt_count: 6
      });
    });

    test('should NOT detect brute force with less than 5 failed logins', () => {
      const baseTime = new Date();
      const sourceIP = '192.168.1.200';

      // Only 4 failed attempts
      for (let i = 0; i < 4; i++) {
        const timestamp = new Date(baseTime.getTime() - (60 - i) * 1000).toISOString();
        insertLog.run(
          timestamp,
          'login',
          'user1',
          sourceIP,
          null,
          'failed',
          'Invalid credentials',
          JSON.stringify({ attempt: i + 1 })
        );
      }

      const results = detectBruteForce();

      expect(results.length).toBe(0);
    });

    test('should detect brute force attack on specific username', () => {
      const baseTime = new Date();
      const targetUser = 'admin';

      // 5 failed attempts from different IPs targeting same user
      for (let i = 0; i < 5; i++) {
        const timestamp = new Date(baseTime.getTime() - (60 - i) * 1000).toISOString();
        insertLog.run(
          timestamp,
          'login',
          targetUser,
          `10.0.0.${i}`,
          null,
          'failed',
          'Invalid credentials',
          JSON.stringify({ attempt: i + 1 })
        );
      }

      const results = detectBruteForce();

      expect(results.length).toBeGreaterThan(0);
      const userAlert = results.find(r => r.username === targetUser);
      expect(userAlert).toBeDefined();
      expect(userAlert.attempt_count).toBeGreaterThanOrEqual(5);
    });
  });

  describe('Off-Hours Access Detection', () => {
    test('should detect successful login at 2 AM (off-hours)', () => {
      // 2 AM login (off-hours)
      const offHoursTime = '2025-10-15T02:00:00Z';

      insertLog.run(
        offHoursTime,
        'login',
        'alice',
        '203.0.113.45',
        null,
        'success',
        'User logged in successfully',
        JSON.stringify({})
      );

      const results = detectOffHoursAccess();

      expect(results.length).toBeGreaterThan(0);
      expect(results[0]).toMatchObject({
        username: 'alice',
        source_ip: '203.0.113.45'
      });
    });

    test('should detect successful login on Sunday (weekend)', () => {
      // Sunday login
      const sundayTime = '2025-10-19T10:00:00Z'; // Sunday at 10 AM

      insertLog.run(
        sundayTime,
        'login',
        'bob',
        '198.51.100.22',
        null,
        'success',
        'User logged in successfully',
        JSON.stringify({})
      );

      const results = detectOffHoursAccess();

      expect(results.length).toBeGreaterThan(0);
      expect(results[0]).toMatchObject({
        username: 'bob'
      });
    });

    test('should NOT detect login during business hours (10 AM weekday)', () => {
      // Wednesday at 10 AM
      const businessHours = '2025-10-15T10:00:00Z';

      insertLog.run(
        businessHours,
        'login',
        'charlie',
        '172.16.0.5',
        null,
        'success',
        'User logged in successfully',
        JSON.stringify({})
      );

      const results = detectOffHoursAccess();

      expect(results.length).toBe(0);
    });

    test('should NOT detect failed login attempts (only successful logins)', () => {
      // 2 AM failed login
      const offHoursTime = '2025-10-15T02:00:00Z';

      insertLog.run(
        offHoursTime,
        'login',
        'david',
        '192.168.1.105',
        null,
        'failed', // Failed status
        'Invalid credentials',
        JSON.stringify({})
      );

      const results = detectOffHoursAccess();

      expect(results.length).toBe(0);
    });
  });
});
