import React from "react";
import { Bar, Pie } from "react-chartjs-2";
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  BarElement
} from "chart.js";

// Register chart elements
ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement);

const Dashboard = ({ logs = [] }) => {
  // Count logs by severity
  const counts = [0, 0, 0]; // [Low, Medium, High]
  logs.forEach(log => {
    if (log.overall_severity === 0) counts[0]++;
    else if (log.overall_severity === 1) counts[1]++;
    else counts[2]++;
  });

  const barData = {
    labels: ["Low", "Medium", "High"],
    datasets: [
      {
        label: "Threat Count",
        data: counts,
        backgroundColor: ["#2ecc71", "#f1c40f", "#e74c3c"]
      }
    ]
  };

  const pieData = {
    labels: ["Low", "Medium", "High"],
    datasets: [
      {
        data: counts,
        backgroundColor: ["#2ecc71", "#f1c40f", "#e74c3c"]
      }
    ]
  };

  return (
    <div>
      <h2>Threat Severity Charts</h2>
      <div style={{ width: "600px", marginBottom: "20px" }}>
        <Bar data={barData} />
      </div>
      <div style={{ width: "400px" }}>
        <Pie data={pieData} />
      </div>
    </div>
  );
};

export default Dashboard;
