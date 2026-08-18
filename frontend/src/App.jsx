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

  const [analysisLoading, setAnalysisLoading] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [analysisError, setAnalysisError] = useState("");

  const [flow, setFlow] = useState({
    destination_port: 80,
    flow_duration: 1000,
    total_fwd_packets: 10,
    total_backward_packets: 8,
    total_length_of_fwd_packets: 500,
    total_length_of_bwd_packets: 400,
    flow_bytes_s: 900,
    flow_packets_s: 18,
    syn_flag_count: 1,
    ack_flag_count: 10,
    fin_flag_count: 1,
    rst_flag_count: 0,
    average_packet_size: 50
  });

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

  const interval = setInterval(() => {
    loadDashboard();
  }, 5000);

  return () => {
    clearInterval(interval);
  };
}, []);

  const handleFlowChange = (event) => {
    const { name, value } = event.target;

    setFlow((previous) => ({
      ...previous,
      [name]: Number(value)
    }));
  };

  const analyzeNetwork = async (event) => {
    event.preventDefault();

    try {
      setAnalysisLoading(true);
      setAnalysisError("");
      setAnalysisResult(null);

      const response = await axios.post(
        `${API_URL}/api/analyze`,
        flow
      );

      setAnalysisResult(response.data);

      // Refresh dashboard so the newly
      // saved alert appears immediately.
      await loadDashboard();

    } catch (error) {
      console.error("Network analysis error:", error);

      setAnalysisError(
        error.response?.data?.detail ||
        "Unable to analyze network traffic."
      );

    } finally {
      setAnalysisLoading(false);
    }
  };

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

      {/* ================================================= */}
      {/* NETWORK TRAFFIC ANALYZER */}
      {/* ================================================= */}

      <section className="analyzer">

        <h2>🔍 Network Traffic Analyzer</h2>

        <p>
          Enter network-flow information and let the XGBoost
          model analyze the traffic.
        </p>

        <form onSubmit={analyzeNetwork}>

          <div className="form-grid">

            <div>
              <label>Destination Port</label>
              <input
                type="number"
                name="destination_port"
                value={flow.destination_port}
                onChange={handleFlowChange}
              />
            </div>

            <div>
              <label>Flow Duration</label>
              <input
                type="number"
                name="flow_duration"
                value={flow.flow_duration}
                onChange={handleFlowChange}
              />
            </div>

            <div>
              <label>Forward Packets</label>
              <input
                type="number"
                name="total_fwd_packets"
                value={flow.total_fwd_packets}
                onChange={handleFlowChange}
              />
            </div>

            <div>
              <label>Backward Packets</label>
              <input
                type="number"
                name="total_backward_packets"
                value={flow.total_backward_packets}
                onChange={handleFlowChange}
              />
            </div>

            <div>
              <label>Forward Bytes</label>
              <input
                type="number"
                name="total_length_of_fwd_packets"
                value={flow.total_length_of_fwd_packets}
                onChange={handleFlowChange}
              />
            </div>

            <div>
              <label>Backward Bytes</label>
              <input
                type="number"
                name="total_length_of_bwd_packets"
                value={flow.total_length_of_bwd_packets}
                onChange={handleFlowChange}
              />
            </div>

            <div>
              <label>Flow Bytes/s</label>
              <input
                type="number"
                name="flow_bytes_s"
                value={flow.flow_bytes_s}
                onChange={handleFlowChange}
              />
            </div>

            <div>
              <label>Flow Packets/s</label>
              <input
                type="number"
                name="flow_packets_s"
                value={flow.flow_packets_s}
                onChange={handleFlowChange}
              />
            </div>

            <div>
              <label>SYN Flags</label>
              <input
                type="number"
                name="syn_flag_count"
                value={flow.syn_flag_count}
                onChange={handleFlowChange}
              />
            </div>

            <div>
              <label>ACK Flags</label>
              <input
                type="number"
                name="ack_flag_count"
                value={flow.ack_flag_count}
                onChange={handleFlowChange}
              />
            </div>

            <div>
              <label>FIN Flags</label>
              <input
                type="number"
                name="fin_flag_count"
                value={flow.fin_flag_count}
                onChange={handleFlowChange}
              />
            </div>

            <div>
              <label>RST Flags</label>
              <input
                type="number"
                name="rst_flag_count"
                value={flow.rst_flag_count}
                onChange={handleFlowChange}
              />
            </div>

            <div>
              <label>Average Packet Size</label>
              <input
                type="number"
                name="average_packet_size"
                value={flow.average_packet_size}
                onChange={handleFlowChange}
              />
            </div>

          </div>

          <button
            type="submit"
            disabled={analysisLoading}
          >
            {analysisLoading
              ? "Analyzing..."
              : "🧠 Analyze Network Traffic"}
          </button>

        </form>

        {analysisError && (
          <div className="analysis-error">
            ❌ {analysisError}
          </div>
        )}

        {analysisResult && (
          <div className="analysis-result">

            <h3>Analysis Result</h3>

            <div className="result-grid">

              <div>
                <strong>Attack Type</strong>
                <span>
                  {analysisResult.prediction.attack_type}
                </span>
              </div>

              <div>
                <strong>Confidence</strong>
                <span>
                  {(analysisResult.prediction.confidence * 100).toFixed(2)}%
                </span>
              </div>

              <div>
                <strong>Severity</strong>
                <span>
                  {analysisResult.prediction.severity}
                </span>
              </div>

              <div>
                <strong>Risk Score</strong>
                <span>
                  {analysisResult.prediction.risk_score}
                </span>
              </div>

              <div>
                <strong>Predicted Class</strong>
                <span>
                  {analysisResult.prediction.predicted_class}
                </span>
              </div>

              <div>
                <strong>Database</strong>
                <span>
                  {analysisResult.database?.saved
                    ? `Saved — Alert #${analysisResult.database.alert_id}`
                    : "Not saved"}
                </span>
              </div>

            </div>

            <h4>Top Predictions</h4>

            <table>

              <thead>
                <tr>
                  <th>Attack Type</th>
                  <th>Probability</th>
                </tr>
              </thead>

              <tbody>
                {analysisResult.prediction.top_predictions.map(
                  (prediction, index) => (
                    <tr key={index}>
                      <td>{prediction.attack_type}</td>
                      <td>
                        {(prediction.probability * 100).toFixed(3)}%
                      </td>
                    </tr>
                  )
                )}
              </tbody>

            </table>

          </div>
        )}

      </section>

      {/* ================================================= */}
      {/* DASHBOARD CARDS */}
      {/* ================================================= */}

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

      {/* ================================================= */}
      {/* CHART */}
      {/* ================================================= */}

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

      {/* ================================================= */}
      {/* ALERT TABLE */}
      {/* ================================================= */}

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