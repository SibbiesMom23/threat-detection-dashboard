import { db, insertAlert } from '../database/init.js';

/**
 * Brute Force Detection
 * Detects multiple failed login attempts from the same IP or to the same username
 */
export function detectBruteForce() {
  const threshold = 5; // Failed attempts
  const timeWindow = 300; // 5 minutes in seconds

  // Check for failed logins by IP
  const ipQuery = db.prepare(`
    SELECT
      source_ip,
      COUNT(*) as attempt_count,
      MIN(timestamp) as first_attempt,
      MAX(timestamp) as last_attempt
    FROM logs
    WHERE
      (status LIKE '%fail%' OR status LIKE '%denied%' OR status LIKE '%invalid%')
      AND source_ip IS NOT NULL
      AND datetime(timestamp) > datetime('now', '-${timeWindow} seconds')
    GROUP BY source_ip
    HAVING COUNT(*) >= ?
  `);

  const ipResults = ipQuery.all(threshold);

  // Check for failed logins by username
  const userQuery = db.prepare(`
    SELECT
      username,
      source_ip,
      COUNT(*) as attempt_count,
      MIN(timestamp) as first_attempt,
      MAX(timestamp) as last_attempt
    FROM logs
    WHERE
      (status LIKE '%fail%' OR status LIKE '%denied%' OR status LIKE '%invalid%')
      AND username IS NOT NULL
      AND datetime(timestamp) > datetime('now', '-${timeWindow} seconds')
    GROUP BY username
    HAVING COUNT(*) >= ?
  `);

  const userResults = userQuery.all(threshold);

  const alerts = [];

  // Create alerts for IP-based brute force
  for (const result of ipResults) {
    const alert = insertAlert.run(
      'brute_force',
      'high',
      `Brute Force Attack Detected from ${result.source_ip}`,
      `Detected ${result.attempt_count} failed login attempts from IP ${result.source_ip} within ${timeWindow / 60} minutes`,
      result.source_ip,
      result.source_ip,
      result.attempt_count,
      result.first_attempt,
      result.last_attempt,
      null
    );
    alerts.push({ id: alert.lastInsertRowid, type: 'brute_force_ip', ...result });
  }

  // Create alerts for username-based brute force
  for (const result of userResults) {
    const alert = insertAlert.run(
      'brute_force',
      'high',
      `Brute Force Attack on Account ${result.username}`,
      `Detected ${result.attempt_count} failed login attempts for user ${result.username} within ${timeWindow / 60} minutes`,
      result.username,
      result.source_ip,
      result.attempt_count,
      result.first_attempt,
      result.last_attempt,
      null
    );
    alerts.push({ id: alert.lastInsertRowid, type: 'brute_force_user', ...result });
  }

  return alerts;
}

/**
 * Off-Hours Access Detection
 * Detects successful logins during unusual hours (configurable)
 */
export function detectOffHoursAccess() {
  // Define business hours (9 AM to 6 PM, Monday-Friday)
  const businessStartHour = 9;
  const businessEndHour = 18;

  const query = db.prepare(`
    SELECT
      username,
      source_ip,
      timestamp,
      event_type
    FROM logs
    WHERE
      (status LIKE '%success%' OR status LIKE '%accepted%' OR status = 'success')
      AND (
        CAST(strftime('%H', timestamp) AS INTEGER) < ?
        OR CAST(strftime('%H', timestamp) AS INTEGER) >= ?
        OR CAST(strftime('%w', timestamp) AS INTEGER) IN (0, 6)
      )
      AND datetime(timestamp) > datetime('now', '-1 day')
  `);

  const results = query.all(businessStartHour, businessEndHour);
  const alerts = [];

  for (const result of results) {
    const alert = insertAlert.run(
      'off_hours_access',
      'medium',
      `Off-Hours Access by ${result.username || 'Unknown User'}`,
      `Successful login detected outside business hours from IP ${result.source_ip}`,
      result.username,
      result.source_ip,
      1,
      result.timestamp,
      result.timestamp,
      null
    );
    alerts.push({ id: alert.lastInsertRowid, type: 'off_hours', ...result });
  }

  return alerts;
}

/**
 * Geographic Anomaly Detection
 * Detects suspicious IP ranges (placeholder for real geo-IP data)
 */
export function detectGeoAnomalies() {
  // Suspicious IP ranges (example: known malicious ranges, tor exit nodes, etc.)
  // In production, you'd use a proper geo-IP database or threat intelligence feed
  const suspiciousRanges = [
    '10.0.0.',    // Example: internal network accessing from outside (misconfigured)
    '192.168.',   // Private IPs appearing as source (spoofing/misconfiguration)
    '0.0.0.',     // Invalid IPs
  ];

  const alerts = [];

  for (const range of suspiciousRanges) {
    const query = db.prepare(`
      SELECT
        source_ip,
        username,
        COUNT(*) as access_count,
        MIN(timestamp) as first_seen,
        MAX(timestamp) as last_seen
      FROM logs
      WHERE
        source_ip LIKE ?
        AND datetime(timestamp) > datetime('now', '-1 day')
      GROUP BY source_ip
    `);

    const results = query.all(`${range}%`);

    for (const result of results) {
      const alert = insertAlert.run(
        'geo_anomaly',
        'medium',
        `Suspicious IP Range Detected: ${result.source_ip}`,
        `Activity detected from potentially suspicious IP range. ${result.access_count} events recorded.`,
        result.username,
        result.source_ip,
        result.access_count,
        result.first_seen,
        result.last_seen,
        null
      );
      alerts.push({ id: alert.lastInsertRowid, type: 'geo_anomaly', ...result });
    }
  }

  return alerts;
}

/**
 * Run all detection rules
 */
export function runAllDetections() {
  console.log('Running threat detection rules...');

  const bruteForceAlerts = detectBruteForce();
  const offHoursAlerts = detectOffHoursAccess();
  const geoAlerts = detectGeoAnomalies();

  const totalAlerts = bruteForceAlerts.length + offHoursAlerts.length + geoAlerts.length;

  console.log(`Detection complete: ${totalAlerts} alerts generated`);
  console.log(`  - Brute force: ${bruteForceAlerts.length}`);
  console.log(`  - Off-hours access: ${offHoursAlerts.length}`);
  console.log(`  - Geo anomalies: ${geoAlerts.length}`);

  return {
    brute_force: bruteForceAlerts,
    off_hours: offHoursAlerts,
    geo_anomaly: geoAlerts,
    total: totalAlerts
  };
}
