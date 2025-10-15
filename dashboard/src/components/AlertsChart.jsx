import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { format, parseISO, startOfHour, subHours } from 'date-fns';

export default function AlertsChart({ alerts }) {
  // Group alerts by hour and severity
  const chartData = prepareChartData(alerts);

  return (
    <div className="bg-white rounded-lg shadow-lg p-6">
      <h3 className="text-lg font-bold text-gray-900 mb-4">Alert Activity (Last 24 Hours)</h3>
      <ResponsiveContainer width="100%" height={250}>
        <LineChart data={chartData}>
          <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
          <XAxis
            dataKey="time"
            stroke="#6b7280"
            style={{ fontSize: '12px' }}
          />
          <YAxis
            stroke="#6b7280"
            style={{ fontSize: '12px' }}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: '#fff',
              border: '1px solid #e5e7eb',
              borderRadius: '8px',
              padding: '8px'
            }}
          />
          <Legend />
          <Line
            type="monotone"
            dataKey="critical"
            stroke="#dc2626"
            strokeWidth={2}
            dot={{ fill: '#dc2626', r: 4 }}
            name="Critical"
          />
          <Line
            type="monotone"
            dataKey="high"
            stroke="#ea580c"
            strokeWidth={2}
            dot={{ fill: '#ea580c', r: 4 }}
            name="High"
          />
          <Line
            type="monotone"
            dataKey="medium"
            stroke="#ca8a04"
            strokeWidth={2}
            dot={{ fill: '#ca8a04', r: 4 }}
            name="Medium"
          />
          <Line
            type="monotone"
            dataKey="low"
            stroke="#2563eb"
            strokeWidth={2}
            dot={{ fill: '#2563eb', r: 4 }}
            name="Low"
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

function prepareChartData(alerts) {
  const now = new Date();
  const hours = [];

  // Create 24 hour buckets
  for (let i = 23; i >= 0; i--) {
    const hour = startOfHour(subHours(now, i));
    hours.push({
      time: format(hour, 'HH:mm'),
      timestamp: hour.getTime(),
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    });
  }

  // Count alerts by hour and severity
  alerts.forEach(alert => {
    const alertTime = new Date(alert.created_at);
    const alertHour = startOfHour(alertTime).getTime();

    const bucket = hours.find(h => h.timestamp === alertHour);
    if (bucket) {
      const severity = alert.severity || 'low';
      bucket[severity] = (bucket[severity] || 0) + 1;
    }
  });

  return hours;
}
