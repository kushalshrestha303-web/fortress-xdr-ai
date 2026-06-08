import React from 'react';

export default function Dashboard() {
  return (
    <div className="min-h-screen bg-gray-900 text-white p-8">
      <div className="max-w-7xl mx-auto">
        <h1 className="text-4xl font-bold mb-8">Security Operations Dashboard</h1>
        
        {/* Metrics Grid */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
            <p className="text-gray-400 mb-2">Total Alerts</p>
            <p className="text-4xl font-bold text-blue-400">1,247</p>
          </div>
          
          <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
            <p className="text-gray-400 mb-2">Critical Alerts</p>
            <p className="text-4xl font-bold text-red-400">12</p>
          </div>
          
          <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
            <p className="text-gray-400 mb-2">Open Incidents</p>
            <p className="text-4xl font-bold text-yellow-400">3</p>
          </div>
          
          <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
            <p className="text-gray-400 mb-2">Threat Score</p>
            <p className="text-4xl font-bold text-green-400">72</p>
          </div>
        </div>
        
        {/* Alerts Table */}
        <div className="bg-gray-800 p-6 rounded-lg border border-gray-700 mb-8">
          <h2 className="text-2xl font-bold mb-4">Recent Alerts</h2>
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="text-left p-2">Time</th>
                <th className="text-left p-2">Severity</th>
                <th className="text-left p-2">Source</th>
                <th className="text-left p-2">Message</th>
                <th className="text-left p-2">Action</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-gray-700 hover:bg-gray-700">
                <td className="p-2">10:30:45</td>
                <td className="p-2"><span className="bg-red-600 px-2 py-1 rounded">Critical</span></td>
                <td className="p-2">Wazuh</td>
                <td className="p-2">Brute Force Attack Detected</td>
                <td className="p-2"><button className="text-blue-400 hover:text-blue-300">Investigate</button></td>
              </tr>
              <tr className="border-b border-gray-700 hover:bg-gray-700">
                <td className="p-2">10:28:12</td>
                <td className="p-2"><span className="bg-yellow-600 px-2 py-1 rounded">High</span></td>
                <td className="p-2">Suricata</td>
                <td className="p-2">Suspicious PowerShell Execution</td>
                <td className="p-2"><button className="text-blue-400 hover:text-blue-300">Investigate</button></td>
              </tr>
            </tbody>
          </table>
        </div>
        
        {/* Quick Actions */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <button className="bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 px-6 rounded-lg">
            🔍 Threat Hunt
          </button>
          <button className="bg-green-600 hover:bg-green-700 text-white font-bold py-3 px-6 rounded-lg">
            📊 Generate Report
          </button>
          <button className="bg-purple-600 hover:bg-purple-700 text-white font-bold py-3 px-6 rounded-lg">
            🤖 AI Analysis
          </button>
        </div>
      </div>
    </div>
  );
}
