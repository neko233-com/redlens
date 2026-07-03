import { BrowserRouter, Routes, Route, Link } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import Scan from './pages/Scan'
import Reports from './pages/Reports'

function App() {
  return (
    <BrowserRouter>
      <div style={{ minHeight: '100vh', background: '#0a0a0a', color: '#e0e0e0' }}>
        <nav style={{ background: '#1a1a1a', padding: '1rem 2rem', display: 'flex', gap: '2rem', alignItems: 'center', borderBottom: '1px solid #333' }}>
          <h1 style={{ color: '#ff4444', fontSize: '1.5rem' }}>redlens</h1>
          <Link to="/" style={{ color: '#888', textDecoration: 'none' }}>Dashboard</Link>
          <Link to="/scan" style={{ color: '#888', textDecoration: 'none' }}>Scan</Link>
          <Link to="/reports" style={{ color: '#888', textDecoration: 'none' }}>Reports</Link>
        </nav>
        <main style={{ padding: '2rem' }}>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/scan" element={<Scan />} />
            <Route path="/reports" element={<Reports />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}

export default App
