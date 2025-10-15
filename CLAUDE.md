# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an AI-Assisted Threat Detection Dashboard - a defensive security tool that analyzes security logs for potential threats using rule-based heuristics and optional AI-powered summarization via Claude API.

**Tech Stack:**
- Backend: Node.js + Express (ES modules)
- Database: SQLite via better-sqlite3
- AI: Anthropic Claude API (optional)
- Log formats: JSON and CSV

## Common Commands

### Development

```bash
# Start development server (auto-reload)
npm run dev

# Start production server
npm start

# Test the API
./test-api.sh
```

### Testing the System

```bash
# 1. Start the server
npm run dev

# 2. In another terminal, upload sample logs
curl -X POST http://localhost:3000/api/logs/upload \
  -F "logfile=@data/sample-logs.json"

# 3. View generated alerts
curl http://localhost:3000/api/alerts

# 4. Generate AI summary (requires ANTHROPIC_API_KEY in .env)
curl -X POST http://localhost:3000/api/analyze
```

## Architecture

### High-Level Data Flow

```
Log Files (JSON/CSV)
    ↓
API Endpoints (/api/logs/upload or /api/logs/batch)
    ↓
Parsers (src/utils/parsers.js) - normalize field names
    ↓
SQLite Database (data/threats.db)
    ├─ logs table (raw log entries)
    └─ alerts table (detected threats)
    ↓
Detection Engine (src/detection/rules.js)
    ├─ detectBruteForce()
    ├─ detectOffHoursAccess()
    └─ detectGeoAnomalies()
    ↓
Alerts API (/api/alerts) + AI Analysis (/api/analyze)
    ↓
Future: React Dashboard (Phase 2)
```

### Core Components

**1. Database Layer (`src/database/init.js`)**
- Initializes SQLite database with WAL mode
- Defines schema: `logs` and `alerts` tables
- Exports prepared statements for performance
- Creates indexes on commonly queried fields

**2. Log Ingestion (`src/api/routes.js` + `src/utils/parsers.js`)**
- Two ingestion methods: file upload (multipart) or JSON POST
- Auto-detects JSON vs CSV format
- Normalizes varying field names to standard schema
- Stores raw log data for audit trail

**3. Detection Engine (`src/detection/rules.js`)**
- Rule-based threat detection executed via SQL queries
- Each detection function:
  - Queries logs table for patterns
  - Creates alerts in alerts table
  - Returns summary of findings
- `runAllDetections()` executes all rules and returns aggregated results

**4. AI Analyst (`src/detection/aiAnalyst.js`)**
- Generates executive summaries of alerts using Claude API
- Falls back to stub summaries if no API key configured
- Designed to be extended for deeper per-alert analysis

**5. API Routes (`src/api/routes.js`)**
- RESTful endpoints for log ingestion, alert retrieval, detection
- All responses are UI-ready JSON
- Error handling middleware in main server

### Database Schema

**logs table:**
- Stores all ingested log entries
- Fields: id, timestamp, event_type, username, source_ip, destination_ip, status, message, raw_data
- Indexed by: timestamp, source_ip, username, event_type

**alerts table:**
- Stores detected threats
- Fields: id, alert_type, severity, title, description, affected_entity, source_ip, event_count, first_seen, last_seen, status, ai_summary
- Indexed by: severity, status, created_at
- Status field allows for alert lifecycle management (open/closed/investigating)

## Adding New Detection Rules

1. Create a new function in `src/detection/rules.js`:

```javascript
export function detectMyRule() {
  const query = db.prepare(`
    SELECT ... FROM logs WHERE ...
  `);
  const results = query.all();

  const alerts = [];
  for (const result of results) {
    const alert = insertAlert.run(
      'rule_type',           // alert_type
      'high',                // severity: low, medium, high, critical
      'Alert Title',         // title
      'Description...',      // description
      result.username,       // affected_entity
      result.source_ip,      // source_ip
      result.count,          // event_count
      result.first_seen,     // first_seen timestamp
      result.last_seen,      // last_seen timestamp
      null                   // ai_summary (optional)
    );
    alerts.push({ id: alert.lastInsertRowid, ...result });
  }
  return alerts;
}
```

2. Add the function to `runAllDetections()` in the same file
3. The rule will now run automatically on log ingestion and manual detection

## Extending Log Format Support

The parser in `src/utils/parsers.js` uses flexible field mapping. To support a new field name:

1. Edit `normalizeLogEntry()` to add mapping:
```javascript
source_ip: entry.source_ip || entry.sourceIP || entry.NEW_FIELD_NAME || null,
```

2. For completely custom formats, add a new parser function and register it in the upload route

## Configuration

**Environment Variables (.env):**
- `PORT`: Server port (default: 3000)
- `ANTHROPIC_API_KEY`: Optional Claude API key for AI summaries
- `NODE_ENV`: development or production

**Detection Thresholds:**
Edit constants at the top of detection functions in `src/detection/rules.js`:
- Brute force: `threshold = 5`, `timeWindow = 300` (seconds)
- Off-hours: `businessStartHour = 9`, `businessEndHour = 18`
- Geo anomalies: `suspiciousRanges` array

## Security Considerations

- This is a **defensive security tool** - all detection is passive log analysis
- Never commit `.env` with real API keys
- Database file may contain sensitive data - exclude from version control
- When adding detection rules, ensure they use parameterized queries (better-sqlite3 prepared statements)
- API has no authentication - add auth middleware before production deployment

## Code Patterns

**Database Transactions:**
For bulk inserts, always use transactions:
```javascript
const insertMany = db.transaction((entries) => {
  for (const entry of entries) {
    insertLog.run(...);
  }
});
insertMany(data);
```

**ES Modules:**
This project uses ES modules (`"type": "module"` in package.json):
- Use `import`/`export`, not `require()`
- Use `import.meta.url` for `__dirname` equivalent

**Error Handling:**
- API routes use try/catch with 500 responses
- Main server has error middleware for unhandled errors
- Detection functions log errors but don't throw
