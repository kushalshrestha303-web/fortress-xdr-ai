import React from 'react';

export default function Home() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-between p-24">
      <div className="z-10 w-full max-w-5xl items-center justify-between font-mono text-sm">
        <h1 className="text-4xl font-bold mb-8">🛡️ Fortress XDR AI</h1>
        <p className="text-xl mb-4">Enterprise Security Operations Center</p>
        <p className="text-lg text-gray-600 mb-8">
          Real-time threat detection, AI investigation, and automated response.
        </p>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-12">
          <div className="p-6 bg-blue-50 rounded-lg border border-blue-200">
            <h2 className="text-2xl font-bold mb-2">🔍 Monitoring</h2>
            <p className="text-gray-700">Real-time security event monitoring from multiple sources</p>
          </div>
          
          <div className="p-6 bg-green-50 rounded-lg border border-green-200">
            <h2 className="text-2xl font-bold mb-2">🤖 AI Analysis</h2>
            <p className="text-gray-700">Intelligent threat analysis and investigation</p>
          </div>
          
          <div className="p-6 bg-purple-50 rounded-lg border border-purple-200">
            <h2 className="text-2xl font-bold mb-2">📊 Reporting</h2>
            <p className="text-gray-700">Comprehensive security and compliance reports</p>
          </div>
        </div>
        
        <div className="flex gap-4">
          <a
            href="/dashboard"
            className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
          >
            Go to Dashboard
          </a>
          <a
            href="/docs"
            className="px-6 py-3 bg-gray-600 text-white rounded-lg hover:bg-gray-700"
          >
            API Documentation
          </a>
        </div>
      </div>
    </main>
  );
}
