import { useState } from 'react';
import { formatDistanceToNow } from 'date-fns';

const severityColors = {
  critical: 'bg-red-100 text-red-800 border-red-200',
  high: 'bg-orange-100 text-orange-800 border-orange-200',
  medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  low: 'bg-blue-100 text-blue-800 border-blue-200',
};

const severityBadges = {
  critical: 'bg-red-600 text-white',
  high: 'bg-orange-600 text-white',
  medium: 'bg-yellow-600 text-white',
  low: 'bg-blue-600 text-white',
};

export default function AlertsTable({ alerts, onAnalyze }) {
  const [selectedSeverity, setSelectedSeverity] = useState('all');
  const [expandedAlert, setExpandedAlert] = useState(null);

  const filteredAlerts = selectedSeverity === 'all'
    ? alerts
    : alerts.filter(alert => alert.severity === selectedSeverity);

  const severityCounts = alerts.reduce((acc, alert) => {
    acc[alert.severity] = (acc[alert.severity] || 0) + 1;
    return acc;
  }, {});

  return (
    <div className="bg-white rounded-lg shadow-lg">
      {/* Header with filters */}
      <div className="p-4 border-b border-gray-200">
        <div className="flex items-center justify-between">
          <h2 className="text-xl font-bold text-gray-900">Security Alerts</h2>
          <div className="text-sm text-gray-500">
            {filteredAlerts.length} of {alerts.length} alerts
          </div>
        </div>

        {/* Severity filters */}
        <div className="flex gap-2 mt-4 flex-wrap">
          <button
            onClick={() => setSelectedSeverity('all')}
            className={`px-4 py-2 rounded-lg font-medium transition-colors ${
              selectedSeverity === 'all'
                ? 'bg-gray-800 text-white'
                : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
            }`}
          >
            All ({alerts.length})
          </button>
          {['critical', 'high', 'medium', 'low'].map(severity => (
            <button
              key={severity}
              onClick={() => setSelectedSeverity(severity)}
              className={`px-4 py-2 rounded-lg font-medium transition-colors capitalize ${
                selectedSeverity === severity
                  ? severityBadges[severity]
                  : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
              }`}
            >
              {severity} ({severityCounts[severity] || 0})
            </button>
          ))}
        </div>
      </div>

      {/* Alerts list */}
      <div className="divide-y divide-gray-200">
        {filteredAlerts.length === 0 ? (
          <div className="p-8 text-center text-gray-500">
            No alerts found
          </div>
        ) : (
          filteredAlerts.map(alert => (
            <div
              key={alert.id}
              className={`p-4 hover:bg-gray-50 transition-colors border-l-4 ${
                severityColors[alert.severity] || 'border-gray-200'
              }`}
            >
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-3">
                    <span className={`px-2.5 py-1 rounded-full text-xs font-semibold uppercase ${
                      severityBadges[alert.severity]
                    }`}>
                      {alert.severity}
                    </span>
                    <span className="px-2.5 py-1 rounded-full text-xs font-medium bg-gray-100 text-gray-700">
                      {alert.alert_type.replace(/_/g, ' ')}
                    </span>
                    <span className="text-xs text-gray-500">
                      {formatDistanceToNow(new Date(alert.created_at), { addSuffix: true })}
                    </span>
                  </div>

                  <h3 className="mt-2 text-base font-semibold text-gray-900">
                    {alert.title}
                  </h3>

                  <p className="mt-1 text-sm text-gray-600">
                    {alert.description}
                  </p>

                  <div className="mt-3 flex gap-4 text-sm">
                    {alert.source_ip && (
                      <div>
                        <span className="text-gray-500">Source IP:</span>{' '}
                        <span className="font-mono font-medium text-gray-900">{alert.source_ip}</span>
                      </div>
                    )}
                    {alert.affected_entity && (
                      <div>
                        <span className="text-gray-500">Target:</span>{' '}
                        <span className="font-medium text-gray-900">{alert.affected_entity}</span>
                      </div>
                    )}
                    <div>
                      <span className="text-gray-500">Events:</span>{' '}
                      <span className="font-medium text-gray-900">{alert.event_count}</span>
                    </div>
                  </div>
                </div>

                <div className="ml-4 flex gap-2">
                  <button
                    onClick={() => setExpandedAlert(expandedAlert === alert.id ? null : alert.id)}
                    className="px-3 py-1.5 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50"
                  >
                    {expandedAlert === alert.id ? 'Hide' : 'Details'}
                  </button>
                  <button
                    onClick={() => onAnalyze(alert.id)}
                    className="px-3 py-1.5 text-sm font-medium text-white bg-indigo-600 rounded-md hover:bg-indigo-700"
                  >
                    Analyze
                  </button>
                </div>
              </div>

              {/* Expanded details */}
              {expandedAlert === alert.id && (
                <div className="mt-4 p-4 bg-gray-50 rounded-lg">
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="font-medium text-gray-700">First Seen:</span>
                      <div className="text-gray-900">{new Date(alert.first_seen).toLocaleString()}</div>
                    </div>
                    <div>
                      <span className="font-medium text-gray-700">Last Seen:</span>
                      <div className="text-gray-900">{new Date(alert.last_seen).toLocaleString()}</div>
                    </div>
                    <div>
                      <span className="font-medium text-gray-700">Status:</span>
                      <div className="text-gray-900 capitalize">{alert.status}</div>
                    </div>
                    <div>
                      <span className="font-medium text-gray-700">Alert ID:</span>
                      <div className="text-gray-900 font-mono">#{alert.id}</div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
