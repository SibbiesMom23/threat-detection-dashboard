export default function StatsCards({ stats }) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      <StatCard
        title="Total Alerts"
        value={stats.total_alerts || 0}
        bgColor="bg-gray-100"
        textColor="text-gray-900"
      />
      <StatCard
        title="Critical"
        value={stats.critical_alerts || 0}
        bgColor="bg-red-100"
        textColor="text-red-800"
      />
      <StatCard
        title="High"
        value={stats.high_alerts || 0}
        bgColor="bg-orange-100"
        textColor="text-orange-800"
      />
      <StatCard
        title="Open Alerts"
        value={stats.open_alerts || 0}
        bgColor="bg-blue-100"
        textColor="text-blue-800"
      />
    </div>
  );
}

function StatCard({ title, value, bgColor, textColor }) {
  return (
    <div className={`${bgColor} rounded-lg shadow p-6`}>
      <div className="text-sm font-medium text-gray-600 uppercase tracking-wide">
        {title}
      </div>
      <div className={`mt-2 text-3xl font-bold ${textColor}`}>
        {value}
      </div>
    </div>
  );
}
