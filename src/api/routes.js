import express from 'express';
import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { parseJSON, parseCSV, normalizeLogEntry } from '../utils/parsers.js';
import { insertLog, getAlerts, getRecentLogs, db } from '../database/init.js';
import { runAllDetections } from '../detection/rules.js';
import { generateAISummary, generateAlertSummary, summarizeAlerts } from '../detection/aiAnalyst.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const router = express.Router();

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: path.join(__dirname, '../../data/uploads'),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['.json', '.csv', '.log'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowedTypes.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Only JSON and CSV files are allowed'));
    }
  },
  limits: { fileSize: 50 * 1024 * 1024 } // 50MB limit
});

/**
 * POST /api/logs/upload
 * Upload and ingest log files (JSON or CSV)
 */
router.post('/logs/upload', upload.single('logfile'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const filePath = req.file.path;
    const ext = path.extname(req.file.originalname).toLowerCase();

    let logs = [];

    // Parse based on file type
    if (ext === '.json') {
      logs = parseJSON(filePath);
    } else if (ext === '.csv') {
      logs = parseCSV(filePath);
    } else {
      return res.status(400).json({ error: 'Unsupported file type' });
    }

    // Insert logs into database
    const insertMany = db.transaction((entries) => {
      for (const entry of entries) {
        const normalized = normalizeLogEntry(entry);
        insertLog.run(
          normalized.timestamp,
          normalized.event_type,
          normalized.username,
          normalized.source_ip,
          normalized.destination_ip,
          normalized.status,
          normalized.message,
          normalized.raw_data
        );
      }
    });

    insertMany(logs);

    // Run threat detection
    const detectionResults = runAllDetections();

    res.json({
      success: true,
      logs_ingested: logs.length,
      alerts_generated: detectionResults.total,
      detection_summary: {
        brute_force: detectionResults.brute_force.length,
        off_hours: detectionResults.off_hours.length,
        geo_anomaly: detectionResults.geo_anomaly.length
      }
    });

  } catch (error) {
    console.error('Error processing log file:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * POST /api/logs/batch
 * Ingest logs via JSON body (alternative to file upload)
 */
router.post('/logs/batch', async (req, res) => {
  try {
    const logs = Array.isArray(req.body) ? req.body : [req.body];

    const insertMany = db.transaction((entries) => {
      for (const entry of entries) {
        const normalized = normalizeLogEntry(entry);
        insertLog.run(
          normalized.timestamp,
          normalized.event_type,
          normalized.username,
          normalized.source_ip,
          normalized.destination_ip,
          normalized.status,
          normalized.message,
          normalized.raw_data
        );
      }
    });

    insertMany(logs);

    res.json({
      success: true,
      logs_ingested: logs.length
    });

  } catch (error) {
    console.error('Error ingesting logs:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * POST /api/ingest-csv
 * Ingest CSV file directly (raw CSV text in body)
 * Supports EVTX exports via evtx_dump → CSV
 */
router.post('/ingest-csv', async (req, res) => {
  try {
    // Handle different content types
    let csvText;
    if (typeof req.body === 'string') {
      csvText = req.body;
    } else if (req.body && req.body.csv) {
      csvText = req.body.csv;
    } else if (Buffer.isBuffer(req.body)) {
      csvText = req.body.toString('utf-8');
    } else {
      return res.status(400).json({ error: 'CSV data required in request body as "csv" field or raw text' });
    }

    if (!csvText || typeof csvText !== 'string') {
      return res.status(400).json({ error: 'CSV data required in request body as "csv" field or raw text' });
    }

    // Parse CSV from text
    const { parse } = await import('csv-parse/sync');
    const records = parse(csvText, {
      columns: true,
      skip_empty_lines: true,
      trim: true,
      bom: true,
      relax_column_count: true // Handle inconsistent column counts
    });

    if (!records || records.length === 0) {
      return res.status(400).json({ error: 'No valid records found in CSV' });
    }

    // Insert logs into database
    const insertMany = db.transaction((entries) => {
      for (const entry of entries) {
        const normalized = normalizeLogEntry(entry);
        insertLog.run(
          normalized.timestamp,
          normalized.event_type,
          normalized.username,
          normalized.source_ip,
          normalized.destination_ip,
          normalized.status,
          normalized.message,
          normalized.raw_data
        );
      }
    });

    insertMany(records);

    // Run threat detection
    const detectionResults = runAllDetections();

    res.json({
      success: true,
      logs_ingested: records.length,
      alerts_generated: detectionResults.total,
      detection_summary: {
        brute_force: detectionResults.brute_force.length,
        off_hours: detectionResults.off_hours.length,
        geo_anomaly: detectionResults.geo_anomaly.length
      },
      note: 'CSV ingested and analyzed. Supports EVTX exports via: evtx_dump -o csv yourfile.evtx'
    });

  } catch (error) {
    console.error('Error ingesting CSV:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * GET /api/logs
 * Retrieve recent logs
 */
router.get('/logs', (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 100;
    const logs = getRecentLogs.all(limit);

    res.json({
      success: true,
      count: logs.length,
      logs
    });

  } catch (error) {
    console.error('Error fetching logs:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * GET /api/alerts
 * Retrieve alerts with optional filtering and pagination
 */
router.get('/alerts', (req, res) => {
  try {
    const status = req.query.status || 'open';
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;

    const alerts = getAlerts.all(status, limit, offset);

    res.json({
      success: true,
      count: alerts.length,
      alerts
    });

  } catch (error) {
    console.error('Error fetching alerts:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * POST /api/detect
 * Manually trigger threat detection on existing logs
 */
router.post('/detect', async (req, res) => {
  try {
    const results = runAllDetections();

    res.json({
      success: true,
      alerts_generated: results.total,
      detection_summary: {
        brute_force: results.brute_force.length,
        off_hours: results.off_hours.length,
        geo_anomaly: results.geo_anomaly.length
      },
      details: results
    });

  } catch (error) {
    console.error('Error running detection:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * POST /api/analyze
 * Generate AI summary of recent alerts
 */
router.post('/analyze', async (req, res) => {
  try {
    const recentAlerts = getAlerts.all('open', 20, 0);

    if (recentAlerts.length === 0) {
      return res.json({
        success: true,
        summary: 'No open alerts to analyze.'
      });
    }

    const summary = await generateAISummary(recentAlerts);

    res.json({
      success: true,
      alerts_analyzed: recentAlerts.length,
      summary
    });

  } catch (error) {
    console.error('Error generating AI summary:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * GET /api/alerts/:id/analyze
 * Generate deep-dive AI analysis for a specific alert
 */
router.get('/alerts/:id/analyze', async (req, res) => {
  try {
    const alertId = parseInt(req.params.id);

    if (isNaN(alertId)) {
      return res.status(400).json({ error: 'Invalid alert ID' });
    }

    const analysis = await generateAlertSummary(alertId);

    res.json({
      success: true,
      alert_id: alertId,
      analysis
    });

  } catch (error) {
    console.error('Error analyzing alert:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * GET /api/stats
 * Get dashboard statistics
 */
router.get('/stats', (req, res) => {
  try {
    const stats = {
      total_logs: db.prepare('SELECT COUNT(*) as count FROM logs').get().count,
      total_alerts: db.prepare('SELECT COUNT(*) as count FROM alerts').get().count,
      open_alerts: db.prepare('SELECT COUNT(*) as count FROM alerts WHERE status = ?').get('open').count,
      critical_alerts: db.prepare('SELECT COUNT(*) as count FROM alerts WHERE severity = ? AND status = ?').get('critical', 'open').count,
      high_alerts: db.prepare('SELECT COUNT(*) as count FROM alerts WHERE severity = ? AND status = ?').get('high', 'open').count,
      recent_activity: getRecentLogs.all(10)
    };

    res.json({
      success: true,
      stats
    });

  } catch (error) {
    console.error('Error fetching stats:', error);
    res.status(500).json({ error: error.message });
  }
});

export default router;
