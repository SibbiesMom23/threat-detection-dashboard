# SOC Analyst Dashboard

React + Vite + Tailwind dashboard for the AI-Assisted Threat Detection system.

## Features

- **Severity-Filtered Alerts Table**: Filter alerts by severity (critical, high, medium, low)
- **Time Series Chart**: Visualize alert activity over the last 24 hours
- **AI Summary Generation**: Generate Claude-powered threat analysis with one click
- **Real-time Updates**: Auto-refreshes every 30 seconds
- **Individual Alert Analysis**: Deep-dive AI analysis for specific alerts

## Quick Start

```bash
# Install dependencies
npm install

# Start development server (requires backend on port 3000)
npm run dev

# Build for production
npm run build
```

## Prerequisites

The backend API must be running on `http://localhost:3000`. Start it with:

```bash
cd ..
npm run dev
```

Then access the dashboard at `http://localhost:5173`

## Usage

1. **View Alerts**: Browse all security alerts with severity indicators
2. **Filter by Severity**: Click severity badges to filter alerts
3. **Generate Summary**: Click "Generate Summary" for AI-powered threat analysis
4. **Analyze Individual Alerts**: Click "Analyze" on any alert for detailed investigation
5. **Auto-Refresh**: Dashboard updates automatically every 30 seconds

## Tech Stack

- **React 19**: UI framework
- **Vite**: Build tool and dev server
- **Tailwind CSS**: Utility-first styling
- **Recharts**: Data visualization
- **date-fns**: Date formatting
