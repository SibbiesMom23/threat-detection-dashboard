/**
 * AI Analyst - Generates threat summaries using Claude API
 */

import dotenv from 'dotenv';
import { db } from '../database/init.js';
dotenv.config();

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
const ANTHROPIC_API_URL = 'https://api.anthropic.com/v1/messages';
const MODEL = 'claude-3-5-sonnet-20241022';

/**
 * Generate AI summary for a set of alerts
 * @param {Array} alerts - Array of alert objects
 * @returns {Promise<string>} AI-generated summary
 */
export async function generateAISummary(alerts) {
  // If no API key, return stub response
  if (!ANTHROPIC_API_KEY || ANTHROPIC_API_KEY === 'your_api_key_here') {
    return generateStubSummary(alerts);
  }

  try {
    const prompt = buildAnalystPrompt(alerts);

    const response = await fetch(ANTHROPIC_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: MODEL,
        max_tokens: 1024,
        messages: [{
          role: 'user',
          content: prompt
        }]
      })
    });

    if (!response.ok) {
      const errorBody = await response.text();
      console.error('Anthropic API error:', response.status, response.statusText, errorBody);
      return generateStubSummary(alerts);
    }

    const data = await response.json();

    // Validate response structure
    if (!data.content || !data.content[0] || !data.content[0].text) {
      console.error('Unexpected API response structure:', data);
      return generateStubSummary(alerts);
    }

    return data.content[0].text;

  } catch (error) {
    console.error('Error calling Anthropic API:', error.message);
    return generateStubSummary(alerts);
  }
}

/**
 * Build the analyst prompt for Claude
 */
function buildAnalystPrompt(alerts) {
  const alertsSummary = alerts.map(a =>
    `- [${a.severity.toUpperCase()}] ${a.title}: ${a.description}`
  ).join('\n');

  return `You are a cybersecurity analyst reviewing threat detection alerts. Analyze the following alerts and provide a concise executive summary.

Alerts detected:
${alertsSummary}

Provide:
1. Overall threat level (Low/Medium/High/Critical)
2. Key findings (2-3 bullets)
3. Recommended immediate actions

Keep the response concise and actionable.`;
}

/**
 * Generate a stub summary when AI is not available
 */
function generateStubSummary(alerts) {
  const severityCounts = alerts.reduce((acc, alert) => {
    acc[alert.severity] = (acc[alert.severity] || 0) + 1;
    return acc;
  }, {});

  const totalEvents = alerts.reduce((sum, a) => sum + (a.event_count || 1), 0);

  let threatLevel = 'Low';
  if (severityCounts.critical > 0) threatLevel = 'Critical';
  else if (severityCounts.high > 0) threatLevel = 'High';
  else if (severityCounts.medium > 0) threatLevel = 'Medium';

  return `[AI Analyst Summary - Stub Mode]

Overall Threat Level: ${threatLevel}

Key Findings:
• ${alerts.length} distinct threat pattern(s) detected
• ${totalEvents} total security events analyzed
• Severity breakdown: ${Object.entries(severityCounts).map(([k,v]) => `${v} ${k}`).join(', ')}

Recommended Actions:
• Review high-severity alerts immediately
• Investigate source IPs for potential blocking
• Consider implementing rate limiting for affected services

Note: Connect your Anthropic API key in .env to enable full AI analysis.`;
}

/**
 * Alias for generateAISummary for consistency
 * @param {Array} alerts - Array of alert objects
 * @returns {Promise<string>} AI-generated summary
 */
export async function summarizeAlerts(alerts) {
  return generateAISummary(alerts);
}

/**
 * Generate AI summary for a single alert with related log context
 * @param {number} alertId - The alert ID to analyze
 * @returns {Promise<string>} AI-generated detailed analysis
 */
export async function generateAlertSummary(alertId) {
  // Fetch the alert
  const alert = db.prepare('SELECT * FROM alerts WHERE id = ?').get(alertId);

  if (!alert) {
    return 'Alert not found';
  }

  // If no API key, return stub
  if (!ANTHROPIC_API_KEY || ANTHROPIC_API_KEY === 'your_api_key_here') {
    return `[Detailed analysis for alert #${alertId} - AI not configured]\n\n${alert.title}\n${alert.description}`;
  }

  try {
    // Fetch related logs
    let relatedLogs = [];
    if (alert.source_ip) {
      relatedLogs = db.prepare(`
        SELECT * FROM logs
        WHERE source_ip = ?
        ORDER BY timestamp DESC
        LIMIT 20
      `).all(alert.source_ip);
    } else if (alert.affected_entity) {
      relatedLogs = db.prepare(`
        SELECT * FROM logs
        WHERE username = ?
        ORDER BY timestamp DESC
        LIMIT 20
      `).all(alert.affected_entity);
    }

    // Build detailed prompt
    const logsContext = relatedLogs.length > 0
      ? relatedLogs.map(log =>
          `[${log.timestamp}] ${log.event_type} - User: ${log.username || 'N/A'}, IP: ${log.source_ip || 'N/A'}, Status: ${log.status}, Msg: ${log.message}`
        ).join('\n')
      : 'No related logs found';

    const prompt = `You are a cybersecurity analyst conducting a deep-dive investigation into a security alert.

Alert Details:
- Type: ${alert.alert_type}
- Severity: ${alert.severity}
- Title: ${alert.title}
- Description: ${alert.description}
- Affected Entity: ${alert.affected_entity || 'N/A'}
- Source IP: ${alert.source_ip || 'N/A'}
- Event Count: ${alert.event_count}
- Time Range: ${alert.first_seen} to ${alert.last_seen}

Related Log Entries:
${logsContext}

Provide a detailed security analysis including:
1. Attack pattern identification
2. Potential impact assessment
3. Recommended investigation steps
4. Suggested remediation actions

Be specific and actionable.`;

    const response = await fetch(ANTHROPIC_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: MODEL,
        max_tokens: 2048,
        messages: [{
          role: 'user',
          content: prompt
        }]
      })
    });

    if (!response.ok) {
      const errorBody = await response.text();
      console.error('Anthropic API error:', response.status, response.statusText, errorBody);
      return `[Analysis failed - API error]\n\n${alert.title}\n${alert.description}`;
    }

    const data = await response.json();

    if (!data.content || !data.content[0] || !data.content[0].text) {
      console.error('Unexpected API response structure:', data);
      return `[Analysis failed - Invalid response]\n\n${alert.title}\n${alert.description}`;
    }

    return data.content[0].text;

  } catch (error) {
    console.error('Error analyzing alert:', error.message);
    return `[Analysis failed - ${error.message}]\n\n${alert.title}\n${alert.description}`;
  }
}
