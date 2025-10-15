import { parse } from 'csv-parse/sync';
import fs from 'fs';

/**
 * Parse JSON log file
 * Supports both JSON array and newline-delimited JSON (NDJSON)
 */
export function parseJSON(filePath) {
  const content = fs.readFileSync(filePath, 'utf-8');

  // Try parsing as JSON array first
  try {
    const data = JSON.parse(content);
    return Array.isArray(data) ? data : [data];
  } catch (e) {
    // If that fails, try NDJSON (newline-delimited)
    return content
      .split('\n')
      .filter(line => line.trim())
      .map(line => JSON.parse(line));
  }
}

/**
 * Parse CSV log file
 * Auto-detects delimiter and header row
 */
export function parseCSV(filePath) {
  const content = fs.readFileSync(filePath, 'utf-8');

  const records = parse(content, {
    columns: true,
    skip_empty_lines: true,
    trim: true,
    bom: true
  });

  return records;
}

/**
 * Normalize log entry to standard format
 * Maps various field names to our schema
 */
export function normalizeLogEntry(entry) {
  return {
    timestamp: entry.timestamp || entry.time || entry.datetime || entry.date || new Date().toISOString(),
    event_type: entry.event_type || entry.eventType || entry.type || entry.action || 'unknown',
    username: entry.username || entry.user || entry.account || entry.userid || null,
    source_ip: entry.source_ip || entry.sourceIP || entry.src_ip || entry.ip || entry.clientIP || null,
    destination_ip: entry.destination_ip || entry.destIP || entry.dest_ip || entry.target_ip || null,
    status: entry.status || entry.result || entry.outcome || null,
    message: entry.message || entry.description || entry.msg || entry.details || null,
    raw_data: JSON.stringify(entry)
  };
}
