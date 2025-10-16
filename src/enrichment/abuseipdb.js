import dotenv from 'dotenv';
import { db } from '../database/init.js';

dotenv.config();

const ABUSEIPDB_API_KEY = process.env.ABUSEIPDB_API_KEY;
const API_BASE_URL = 'https://api.abuseipdb.com/api/v2';
const CACHE_TTL_DAYS = 7; // Cache IP reputation for 7 days

/**
 * Get or create the IP reputation cache prepared statements
 */
const getIPReputation = db.prepare(`
  SELECT * FROM ip_reputation
  WHERE ip_address = ?
  AND datetime(last_checked) > datetime('now', '-${CACHE_TTL_DAYS} days')
`);

const insertIPReputation = db.prepare(`
  INSERT INTO ip_reputation (ip_address, abuse_confidence_score, country_code, usage_type, is_whitelisted, total_reports, last_checked, raw_data)
  VALUES (?, ?, ?, ?, ?, ?, datetime('now'), ?)
`);

const updateIPReputation = db.prepare(`
  UPDATE ip_reputation
  SET abuse_confidence_score = ?,
      country_code = ?,
      usage_type = ?,
      is_whitelisted = ?,
      total_reports = ?,
      last_checked = datetime('now'),
      raw_data = ?
  WHERE ip_address = ?
`);

/**
 * Fetch IP reputation from AbuseIPDB API
 * @param {string} ipAddress - IP address to check
 * @returns {Object} IP reputation data
 */
async function fetchFromAbuseIPDB(ipAddress) {
  if (!ABUSEIPDB_API_KEY) {
    console.warn('AbuseIPDB API key not configured, using stub data');
    return generateStubReputation(ipAddress);
  }

  try {
    const url = `${API_BASE_URL}/check?ipAddress=${encodeURIComponent(ipAddress)}&maxAgeInDays=90&verbose=true`;

    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Key': ABUSEIPDB_API_KEY,
        'Accept': 'application/json'
      }
    });

    if (!response.ok) {
      if (response.status === 429) {
        console.warn('AbuseIPDB rate limit exceeded, using stub data');
        return generateStubReputation(ipAddress);
      }
      throw new Error(`AbuseIPDB API error: ${response.status} ${response.statusText}`);
    }

    const result = await response.json();

    if (result.data) {
      return {
        ip_address: ipAddress,
        abuse_confidence_score: result.data.abuseConfidenceScore || 0,
        country_code: result.data.countryCode || null,
        usage_type: result.data.usageType || null,
        is_whitelisted: result.data.isWhitelisted || false,
        total_reports: result.data.totalReports || 0,
        raw_data: JSON.stringify(result.data)
      };
    }

    return generateStubReputation(ipAddress);

  } catch (error) {
    console.error(`Error fetching IP reputation for ${ipAddress}:`, error.message);
    return generateStubReputation(ipAddress);
  }
}

/**
 * Generate stub reputation data for testing without API key
 * @param {string} ipAddress - IP address to generate stub data for
 * @returns {Object} Stub reputation data
 */
function generateStubReputation(ipAddress) {
  // Private/internal IP ranges get low scores
  const isPrivate = ipAddress.startsWith('10.') ||
                    ipAddress.startsWith('192.168.') ||
                    ipAddress.startsWith('172.16.') ||
                    ipAddress.startsWith('172.17.') ||
                    ipAddress.startsWith('172.18.') ||
                    ipAddress.startsWith('172.19.') ||
                    ipAddress.startsWith('172.2') ||
                    ipAddress.startsWith('172.30.') ||
                    ipAddress.startsWith('172.31.');

  // External IPs get varying scores for testing
  const octets = ipAddress.split('.');
  const lastOctet = parseInt(octets[3] || 0);

  let abuseScore = 0;
  let totalReports = 0;

  if (!isPrivate) {
    // External IPs: vary score based on last octet
    if (lastOctet > 200) {
      abuseScore = 75 + (lastOctet % 25); // High risk
      totalReports = 50 + (lastOctet % 50);
    } else if (lastOctet > 100) {
      abuseScore = 25 + (lastOctet % 25); // Medium risk
      totalReports = 10 + (lastOctet % 20);
    } else {
      abuseScore = lastOctet % 15; // Low risk
      totalReports = lastOctet % 5;
    }
  }

  return {
    ip_address: ipAddress,
    abuse_confidence_score: abuseScore,
    country_code: isPrivate ? null : 'US',
    usage_type: isPrivate ? 'Data Center/Web Hosting/Transit' : 'Residential',
    is_whitelisted: isPrivate,
    total_reports: totalReports,
    raw_data: JSON.stringify({
      ipAddress,
      abuseConfidenceScore: abuseScore,
      totalReports,
      countryCode: isPrivate ? null : 'US',
      usageType: isPrivate ? 'Data Center/Web Hosting/Transit' : 'Residential',
      isWhitelisted: isPrivate,
      stub: true,
      note: 'Generated stub data - configure ABUSEIPDB_API_KEY for real data'
    })
  };
}

/**
 * Get IP reputation with caching
 * Checks local cache first, then fetches from AbuseIPDB if needed
 * @param {string} ipAddress - IP address to check
 * @returns {Object} IP reputation data
 */
export async function getIPReputationWithCache(ipAddress) {
  if (!ipAddress) {
    return null;
  }

  // Check cache first
  const cached = getIPReputation.get(ipAddress);
  if (cached) {
    console.log(`IP reputation cache hit for ${ipAddress}`);
    return cached;
  }

  // Fetch fresh data
  console.log(`Fetching IP reputation for ${ipAddress}...`);
  const reputation = await fetchFromAbuseIPDB(ipAddress);

  // Store in cache
  try {
    // Check if IP already exists (but is stale)
    const existing = db.prepare('SELECT ip_address FROM ip_reputation WHERE ip_address = ?').get(ipAddress);

    if (existing) {
      updateIPReputation.run(
        reputation.abuse_confidence_score,
        reputation.country_code,
        reputation.usage_type,
        reputation.is_whitelisted ? 1 : 0,
        reputation.total_reports,
        reputation.raw_data,
        ipAddress
      );
    } else {
      insertIPReputation.run(
        ipAddress,
        reputation.abuse_confidence_score,
        reputation.country_code,
        reputation.usage_type,
        reputation.is_whitelisted ? 1 : 0,
        reputation.total_reports,
        reputation.raw_data
      );
    }
  } catch (error) {
    console.error(`Error caching IP reputation for ${ipAddress}:`, error.message);
  }

  return reputation;
}

/**
 * Enrich multiple IPs in batch (useful for bulk log processing)
 * @param {Array<string>} ipAddresses - Array of IP addresses to enrich
 * @returns {Object} Map of IP addresses to reputation data
 */
export async function enrichIPsBatch(ipAddresses) {
  const uniqueIPs = [...new Set(ipAddresses.filter(ip => ip))];
  const results = {};

  for (const ip of uniqueIPs) {
    results[ip] = await getIPReputationWithCache(ip);

    // Rate limiting: wait 250ms between API calls to avoid hitting limits
    // (AbuseIPDB free tier: 1000 requests/day = ~41/hour = 1 every 1.5 seconds safe)
    if (ABUSEIPDB_API_KEY) {
      await new Promise(resolve => setTimeout(resolve, 250));
    }
  }

  return results;
}

/**
 * Get risk level based on abuse confidence score
 * @param {number} score - Abuse confidence score (0-100)
 * @returns {string} Risk level (low, medium, high, critical)
 */
export function getRiskLevel(score) {
  if (score >= 75) return 'critical';
  if (score >= 50) return 'high';
  if (score >= 25) return 'medium';
  return 'low';
}

/**
 * Clear stale cache entries older than TTL
 */
export function clearStaleCache() {
  const result = db.prepare(`
    DELETE FROM ip_reputation
    WHERE datetime(last_checked) <= datetime('now', '-${CACHE_TTL_DAYS} days')
  `).run();

  console.log(`Cleared ${result.changes} stale IP reputation cache entries`);
  return result.changes;
}
