import { useState } from 'react'

function Scan() {
  const [host, setHost] = useState('')
  const [port, setPort] = useState('80')
  const [scanning, setScanning] = useState(false)
  const [results, setResults] = useState<any>(null)

  const startScan = async () => {
    setScanning(true)
    try {
      const resp = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targets: [{ host, port: parseInt(port), scheme: 'http' }],
        }),
      })
      const data = await resp.json()
      setResults(data)
    } catch (err) {
      console.error(err)
    } finally {
      setScanning(false)
    }
  }

  return (
    <div>
      <h2 style={{ marginBottom: '2rem' }}>New Scan</h2>
      <div style={{ background: '#1a1a1a', borderRadius: '8px', padding: '1.5rem', border: '1px solid #333', maxWidth: '600px' }}>
        <div style={{ marginBottom: '1rem' }}>
          <label style={{ display: 'block', color: '#888', marginBottom: '0.5rem' }}>Target Host</label>
          <input
            value={host}
            onChange={e => setHost(e.target.value)}
            placeholder="127.0.0.1"
            style={{ width: '100%', padding: '0.75rem', background: '#0a0a0a', border: '1px solid #333', borderRadius: '4px', color: '#e0e0e0', fontSize: '1rem' }}
          />
        </div>
        <div style={{ marginBottom: '1.5rem' }}>
          <label style={{ display: 'block', color: '#888', marginBottom: '0.5rem' }}>Port</label>
          <input
            value={port}
            onChange={e => setPort(e.target.value)}
            placeholder="80"
            style={{ width: '100%', padding: '0.75rem', background: '#0a0a0a', border: '1px solid #333', borderRadius: '4px', color: '#e0e0e0', fontSize: '1rem' }}
          />
        </div>
        <button
          onClick={startScan}
          disabled={scanning || !host}
          style={{ width: '100%', padding: '0.75rem', background: scanning ? '#333' : '#ff4444', color: 'white', border: 'none', borderRadius: '4px', fontSize: '1rem', cursor: scanning ? 'not-allowed' : 'pointer' }}
        >
          {scanning ? 'Scanning...' : 'Start Scan'}
        </button>
      </div>
      {results && (
        <div style={{ marginTop: '2rem' }}>
          <h3>Results</h3>
          <p style={{ color: '#888' }}>Found {results.summary?.total || 0} vulnerabilities</p>
          <pre style={{ background: '#111', padding: '1rem', borderRadius: '4px', overflow: 'auto', maxHeight: '400px' }}>
            {JSON.stringify(results, null, 2)}
          </pre>
        </div>
      )}
    </div>
  )
}

export default Scan
