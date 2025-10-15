import { useState, useEffect } from 'react';
import AlertsTable from './components/AlertsTable';
import AlertsChart from './components/AlertsChart';
import StatsCards from './components/StatsCards';

const API_BASE_URL = 'http://localhost:3000/api';

function App() {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({});
  const [loading, setLoading] = useState(true);
  const [analyzing, setAnalyzing] = useState(false);
  const [aiSummary, setAiSummary] = useState(null);
  const [error, setError] = useState(null);

  // Fetch alerts and stats on mount
  useEffect(() => {
    fetchData();
    // Auto-refresh every 30 seconds
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, []);

  const fetchData = async () => {
    try {
      setLoading(true);
      const [alertsRes, statsRes] = await Promise.all([
        fetch(`${API_BASE_URL}/alerts?status=open&limit=100`),
        fetch(`${API_BASE_URL}/stats`)
      ]);

      const alertsData = await alertsRes.json();
      const statsData = await statsRes.json();

      setAlerts(alertsData.alerts || []);
      setStats(statsData.stats || {});
      setError(null);
    } catch (err) {
      setError('Failed to fetch data. Make sure the backend server is running on port 3000.');
      console.error('Error fetching data:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateSummary = async () => {
    try {
      setAnalyzing(true);
      setAiSummary(null);

      const response = await fetch(`${API_BASE_URL}/analyze`, {
        method: 'POST'
      });

      const data = await response.json();
      setAiSummary(data.summary);
    } catch (err) {
      setError('Failed to generate AI summary');
      console.error('Error generating summary:', err);
    } finally {
      setAnalyzing(false);
    }
  };

  const handleAnalyzeAlert = async (alertId) => {
    try {
      setAnalyzing(true);

      const response = await fetch(`${API_BASE_URL}/alerts/${alertId}/analyze`);
      const data = await response.json();

      // Show analysis in a modal or alert
      alert(`Alert #${alertId} Analysis:\n\n${data.analysis}`);
    } catch (err) {
      setError('Failed to analyze alert');
      console.error('Error analyzing alert:', err);
    } finally {
      setAnalyzing(false);
    }
  };

  if (loading && alerts.length === 0) {
    return (
      <div className="min-h-screen bg-gray-100 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600 mx-auto"></div>
          <p className="mt-4 text-gray-600">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-100">
      {/* Header */}
      <header className="bg-gradient-to-r from-indigo-600 to-purple-600 text-white shadow-lg">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold">SOC Analyst Dashboard</h1>
              <p className="mt-1 text-indigo-100">AI-Assisted Threat Detection & Analysis</p>
            </div>
            <button
              onClick={fetchData}
              disabled={loading}
              className="px-4 py-2 bg-white text-indigo-600 rounded-lg font-medium hover:bg-indigo-50 transition-colors disabled:opacity-50"
            >
              {loading ? 'Refreshing...' : 'Refresh'}
            </button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {error && (
          <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-lg">
            <p className="text-red-800">{error}</p>
          </div>
        )}

        {/* Stats Cards */}
        <div className="mb-6">
          <StatsCards stats={stats} />
        </div>

        {/* Chart */}
        <div className="mb-6">
          <AlertsChart alerts={alerts} />
        </div>

        {/* AI Summary Section */}
        <div className="mb-6 bg-white rounded-lg shadow-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xl font-bold text-gray-900">AI Threat Analysis</h2>
            <button
              onClick={handleGenerateSummary}
              disabled={analyzing || alerts.length === 0}
              className="px-6 py-2.5 bg-gradient-to-r from-indigo-600 to-purple-600 text-white rounded-lg font-medium hover:from-indigo-700 hover:to-purple-700 transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
            >
              {analyzing ? (
                <>
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                  Analyzing...
                </>
              ) : (
                <>
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
                  </svg>
                  Generate Summary
                </>
              )}
            </button>
          </div>

          {aiSummary ? (
            <div className="prose max-w-none">
              <pre className="bg-gray-50 p-4 rounded-lg border border-gray-200 whitespace-pre-wrap text-sm">
                {aiSummary}
              </pre>
            </div>
          ) : (
            <p className="text-gray-500 text-center py-8">
              Click "Generate Summary" to get an AI-powered analysis of current threats
            </p>
          )}
        </div>

        {/* Alerts Table */}
        <AlertsTable alerts={alerts} onAnalyze={handleAnalyzeAlert} />
      </main>

      {/* Footer */}
      <footer className="bg-white border-t border-gray-200 mt-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <p className="text-center text-gray-500 text-sm">
            Threat Detection Dashboard v1.0.0 | Alerts auto-refresh every 30s
          </p>
        </div>
      </footer>
    </div>
  );
}

export default App;
