# AI-Assisted Threat Detection Dashboard

A defensive security tool for analyzing security logs and detecting threats using rule-based heuristics and optional AI-powered summarization.

## Features

- **Log Ingestion**: Upload security logs in JSON or CSV format
- **Rule-Based Detection**: Automatic threat detection using configurable rules
  - Brute force attacks (failed login attempts)
  - Off-hours access detection
  - Geographic/IP anomaly detection
- **AI Analysis**: Optional Claude-powered threat summarization
- **RESTful API**: UI-ready endpoints for building dashboards
- **SQLite Storage**: Zero-configuration local database

## Quick Start

### Prerequisites

**For Docker:**
- Docker Desktop or Docker Engine + Docker Compose
- (Optional) Anthropic API key for AI summaries

**For Local Development:**
- Node.js 18+ and npm
- (Optional) Anthropic API key for AI summaries

### Installation

**For Docker:**
```bash
# Copy environment template (optional)
cp .env.example .env

# Add your Anthropic API key to .env if you have one
# ANTHROPIC_API_KEY=your_key_here

# Start with Docker Compose
docker-compose up -d
```

**For Local Development:**
```bash
# Install dependencies
npm install

# Install dashboard dependencies
cd dashboard && npm install && cd ..

# Copy environment template
cp .env.example .env

# (Optional) Add your Anthropic API key to .env
# ANTHROPIC_API_KEY=your_key_here
```

### Running the Full Stack

**Option 1: Docker (recommended for production)**
```bash
# Start with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```
This starts both the backend API (port 3000) and React dashboard (port 5173) in containers.

**Option 2: Local development with script**
```bash
./start-all.sh
```
This starts both components locally for development with hot-reload.

**Option 3: Start components separately**

Terminal 1 - Backend API:
```bash
npm run dev
```

Terminal 2 - React Dashboard:
```bash
cd dashboard && npm run dev
```

### Access Points

- **Backend API**: http://localhost:3000
- **SOC Dashboard**: http://localhost:5173 (local) or http://localhost:80 (Docker)
- **API Documentation**: http://localhost:3000/

## API Endpoints

### Health & Info

```bash
GET /health              # Health check
GET /                    # API documentation
GET /api/stats           # Dashboard statistics
```

### Log Management

```bash
POST /api/logs/upload    # Upload log file (multipart/form-data)
POST /api/logs/batch     # Ingest logs via JSON body
POST /api/ingest-csv     # Ingest CSV directly (raw text or "csv" field)
GET  /api/logs           # List recent logs (?limit=100)
```

### Threat Detection

```bash
GET  /api/alerts         # List alerts (?status=open&limit=50&offset=0)
POST /api/detect         # Manually trigger detection on existing logs
POST /api/analyze        # Generate AI summary of recent alerts
```

## Usage Examples

### Upload Sample Logs

**Via File Upload:**
```bash
curl -X POST http://localhost:3000/api/logs/upload \
  -F "logfile=@data/sample-logs.json"
```

**Via CSV Ingestion (raw text):**
```bash
curl -X POST http://localhost:3000/api/ingest-csv \
  -H "Content-Type: application/json" \
  -d @data/sample-failed-logins.csv
```

**Via CSV Ingestion (JSON wrapper):**
```bash
curl -X POST http://localhost:3000/api/ingest-csv \
  -H "Content-Type: application/json" \
  -d "{\"csv\":\"$(cat data/sample-failed-logins.csv | sed 's/"/\\"/g')\"}"
```

**EVTX Export Support:**
```bash
# First export Windows Event Log to CSV using evtx_dump
evtx_dump -o csv Security.evtx > security-logs.csv

# Then ingest the CSV
curl -X POST http://localhost:3000/api/ingest-csv \
  -H "Content-Type: application/json" \
  -d @security-logs.csv
```

### Get Alerts

```bash
curl http://localhost:3000/api/alerts?status=open
```

### Generate AI Summary

```bash
curl -X POST http://localhost:3000/api/analyze
```

### Run Full Test Suite

```bash
./test-api.sh
```

## Log Format

The system accepts flexible log formats and auto-maps common field names:

**JSON Example:**
```json
{
  "timestamp": "2025-10-15T14:23:42Z",
  "event_type": "login",
  "username": "admin",
  "source_ip": "192.168.1.100",
  "status": "failed",
  "message": "Invalid credentials"
}
```

**CSV Example:**
```csv
timestamp,event_type,username,source_ip,status,message
2025-10-15T14:23:42Z,login,admin,192.168.1.100,failed,Invalid credentials
```

### Supported Field Mappings

The parser normalizes various common field names:
- Timestamp: `timestamp`, `time`, `datetime`, `date`
- Event Type: `event_type`, `eventType`, `type`, `action`
- Username: `username`, `user`, `account`, `userid`
- Source IP: `source_ip`, `sourceIP`, `src_ip`, `ip`, `clientIP`
- Status: `status`, `result`, `outcome`

## Detection Rules

### Brute Force Detection
- Threshold: 5+ failed login attempts
- Time window: 5 minutes
- Tracks by both IP address and username

### Off-Hours Access
- Flags successful logins outside business hours (9 AM - 6 PM)
- Includes weekend detection
- Severity: Medium

### Geographic Anomalies
- Detects suspicious IP ranges
- Configurable blocklists
- Can be extended with geo-IP databases

## Project Structure

```
threat-detection-dashboard/
├── src/                      # Backend (Node.js + Express)
│   ├── index.js              # Express server entry point
│   ├── database/
│   │   └── init.js           # SQLite schema & queries
│   ├── detection/
│   │   ├── rules.js          # Detection engine
│   │   └── aiAnalyst.js      # AI summarization
│   ├── api/
│   │   └── routes.js         # API endpoints
│   └── utils/
│       └── parsers.js        # Log parsing utilities
├── dashboard/                # Frontend (React + Vite + Tailwind)
│   ├── src/
│   │   ├── App.jsx           # Main dashboard component
│   │   └── components/
│   │       ├── AlertsTable.jsx    # Severity-filtered table
│   │       ├── AlertsChart.jsx    # Time series visualization
│   │       └── StatsCards.jsx     # Dashboard statistics
│   └── package.json
├── data/
│   ├── sample-logs.json           # Example log data (JSON)
│   ├── sample-failed-logins.csv   # Sample CSV with brute force attempts
│   ├── sample-evtx-export.csv     # Sample Windows Event Log export
│   ├── uploads/                   # Uploaded files
│   └── threats.db                 # SQLite database (auto-created)
├── start-all.sh              # Start backend + dashboard
├── test-api.sh               # API test script
├── package.json
├── .env.example
└── README.md
```

## Development

### Adding New Detection Rules

Edit `src/detection/rules.js` and add your custom detection function:

```javascript
export function detectMyCustomRule() {
  const query = db.prepare(`...`);
  const results = query.all();

  // Create alerts
  for (const result of results) {
    insertAlert.run(/* ... */);
  }

  return alerts;
}
```

Then add it to `runAllDetections()`.

### Extending Log Parsers

Add new parsers in `src/utils/parsers.js` for custom log formats.

## Security Notes

- This is a **defensive security tool** for analyzing logs and detecting threats
- Do not expose the API directly to the internet without authentication
- Use environment variables for sensitive configuration
- The database file (`threats.db`) may contain sensitive log data
- Regularly review and tune detection thresholds for your environment

## Dashboard Features

The React dashboard (`/dashboard`) provides a SOC analyst interface with:

- **Real-time Alert Monitoring**: Auto-refreshes every 30 seconds
- **Severity Filtering**: One-click filtering by critical, high, medium, low
- **Time Series Visualization**: 24-hour alert activity chart with Recharts
- **AI-Powered Analysis**:
  - Bulk summary generation for all open alerts
  - Per-alert deep-dive analysis with related log context
- **Responsive Design**: Tailwind CSS with gradient headers and clean cards

## Future Enhancements

- Real-time log streaming via WebSocket
- Advanced ML-based anomaly detection
- Integration with SIEM tools (Splunk, ELK, etc.)
- User authentication and RBAC
- Alert notifications (email, Slack, PagerDuty)
- Alert workflow management (assign, close, escalate)
- Custom detection rule builder UI

## License

ISC

## Support

For issues or questions, please review the code and documentation. This is a lab/learning project designed to be extended for your specific security monitoring needs.
