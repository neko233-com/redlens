import { useEffect, useState } from 'react'

interface Health {
  status: string
}

interface ScannersResponse {
  scanners: string[]
}

function Dashboard() {
  const [health, setHealth] = useState<Health | null>(null)
  const [scanners, setScanners] = useState<string[]>([])

  useEffect(() => {
    fetch('/api/health').then(r => r.json()).then(setHealth)
    fetch('/api/scanners').then(r => r.json()).then((data: ScannersResponse) => setScanners(data.scanners))
  }, [])

  return (
    <div>
      <h2 style={{ marginBottom: '2rem' }}>Dashboard</h2>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1.5rem' }}>
        <div style={{ background: '#1a1a1a', borderRadius: '8px', padding: '1.5rem', border: '1px solid #333' }}>
          <h3 style={{ color: '#888', fontSize: '0.9rem', textTransform: 'uppercase', marginBottom: '0.5rem' }}>System Status</h3>
          <p style={{ fontSize: '1.5rem', color: health?.status === 'ok' ? '#44ff44' : '#ff4444' }}>
            {health?.status || 'Checking...'}
          </p>
        </div>
        <div style={{ background: '#1a1a1a', borderRadius: '8px', padding: '1.5rem', border: '1px solid #333' }}>
          <h3 style={{ color: '#888', fontSize: '0.9rem', textTransform: 'uppercase', marginBottom: '0.5rem' }}>Available Scanners</h3>
          <ul style={{ listStyle: 'none', padding: 0 }}>
            {scanners.map(s => (
              <li key={s} style={{ padding: '0.5rem 0', borderBottom: '1px solid #222' }}>{s}</li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  )
}

export default Dashboard
