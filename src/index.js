import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { initializeDatabase } from './database/init.js';
import apiRoutes from './api/routes.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Initialize database
initializeDatabase();

// Routes
app.use('/api', apiRoutes);

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'Threat Detection Dashboard',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    service: 'AI-Assisted Threat Detection Dashboard',
    version: '1.0.0',
    endpoints: {
      health: 'GET /health',
      stats: 'GET /api/stats',
      logs: {
        upload: 'POST /api/logs/upload (multipart/form-data)',
        batch: 'POST /api/logs/batch (JSON)',
        list: 'GET /api/logs?limit=100'
      },
      alerts: {
        list: 'GET /api/alerts?status=open&limit=50&offset=0',
        analyze_single: 'GET /api/alerts/:id/analyze'
      },
      detection: {
        run: 'POST /api/detect',
        analyze: 'POST /api/analyze'
      }
    }
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(err.status || 500).json({
    error: err.message || 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════════════════╗
║   AI-Assisted Threat Detection Dashboard                 ║
║   Version: 1.0.0                                          ║
╚═══════════════════════════════════════════════════════════╝

Server running on: http://localhost:${PORT}
Environment: ${process.env.NODE_ENV || 'development'}

API Endpoints:
  Health Check:     GET  http://localhost:${PORT}/health
  Dashboard Stats:  GET  http://localhost:${PORT}/api/stats
  Upload Logs:      POST http://localhost:${PORT}/api/logs/upload
  List Alerts:      GET  http://localhost:${PORT}/api/alerts
  Run Detection:    POST http://localhost:${PORT}/api/detect
  AI Analysis:      POST http://localhost:${PORT}/api/analyze
  Deep-Dive Alert:  GET  http://localhost:${PORT}/api/alerts/:id/analyze

Ready to detect threats!
  `);
});

export default app;
