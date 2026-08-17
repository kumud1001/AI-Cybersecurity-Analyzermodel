import { useEffect, useState } from "react";
import axios from "axios";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer
} from "recharts";

const API_URL = "http://127.0.0.1:8000";

function App() {
  const [stats, setStats] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

  const loadDashboard = async () => {
    try {
      setLoading(true);

      const [statsResponse, alertsResponse] = await Promise.all([
        axios.get(`${API_URL}/api/dashboard/stats`),
        axios.get(`${API_URL}/api/alerts`)
      ]);

      setStats(statsResponse.data);
      setAlerts(alertsResponse.data.alerts || []);

    } catch (error) {
      console.error("Dashboard error:", error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDashboard();
  }, []);

  if (loading) {
    return <h2>Loading AI Cybersecurity Dashboard...</h2>;
  }

  const severityData = [
    {
      name: "Critical",
      count: stats?.severity?.critical || 0
    },
    {
      name: "High",
      count: stats?.severity?.high || 0
    },
    {
      name: "Medium",
      count: stats?.severity?.medium || 0
    },
    {
      name: "Low",
      count: stats?.severity?.low || 0
    }
  ];

  return (
    <div className="dashboard">

      <header>
        <h1>🛡️ AI Cybersecurity Analyzer</h1>
        <p>XGBoost Network Intrusion Detection Dashboard</p>

        <button onClick={loadDashboard}>
          🔄 Refresh
        </button>
      </header>

      <section className="cards">

        <div className="card">
          <h3>Total Alerts</h3>
          <strong>{stats?.total_alerts || 0}</strong>
        </div>

        <div className="card critical">
          <h3>Critical</h3>
          <strong>{stats?.severity?.critical || 0}</strong>
        </div>

        <div className="card high">
          <h3>High</h3>
          <strong>{stats?.severity?.high || 0}</strong>
        </div>

        <div className="card medium">
          <h3>Medium</h3>
          <strong>{stats?.severity?.medium || 0}</strong>
        </div>

        <div className="card low">
          <h3>Low</h3>
          <strong>{stats?.severity?.low || 0}</strong>
        </div>

      </section>

      <section className="chart-section">

        <h2>Alert Severity</h2>

        <ResponsiveContainer width="100%" height={300}>
          <BarChart data={severityData}>

            <CartesianGrid strokeDasharray="3 3" />

            <XAxis dataKey="name" />

            <YAxis allowDecimals={false} />

            <Tooltip />

            <Bar
              dataKey="count"
              fill="#2563eb"
            />

          </BarChart>
        </ResponsiveContainer>

      </section>

      <section className="alerts">

        <h2>Security Alerts</h2>

        {alerts.length === 0 ? (
          <p>No security alerts found.</p>
        ) : (
          <table>

            <thead>
              <tr>
                <th>ID</th>
                <th>Attack Type</th>
                <th>Confidence</th>
                <th>Severity</th>
                <th>Risk Score</th>
                <th>Source</th>
                <th>Time</th>
              </tr>
            </thead>

            <tbody>

              {alerts.map((alert) => (

                <tr key={alert.id}>

                  <td>{alert.id}</td>

                  <td>{alert.attack_type}</td>

                  <td>
                    {(alert.confidence * 100).toFixed(2)}%
                  </td>

                  <td>
                    <span className={`severity ${alert.severity}`}>
                      {alert.severity}
                    </span>
                  </td>

                  <td>
                    {alert.risk_score}
                  </td>

                  <td>
                    {alert.source}
                  </td>

                  <td>
                    {new Date(alert.created_at).toLocaleString()}
                  </td>

                </tr>

              ))}

            </tbody>

          </table>
        )}

      </section>

    </div>
  );
}

export default App;