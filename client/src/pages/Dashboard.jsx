import { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { api } from '../api/client';

export default function Dashboard() {
  const [searchParams] = useSearchParams();
  const [subscriptions, setSubscriptions] = useState([]);
  const [selected, setSelected] = useState(new Set());
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(null);
  const [ghosting, setGhosting] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    const token = searchParams.get('token');
    if (token) {
      localStorage.setItem('ghosted_token', token);
      window.history.replaceState({}, '', '/dashboard');
    }
  }, [searchParams]);

  const startScan = async () => {
    setScanning(true);
    setError(null);
    try {
      const { scanId } = await api('/scan/start', { method: 'POST' });

      const poll = setInterval(async () => {
        const status = await api(`/scan/status/${scanId}`);
        setScanProgress(status);
        if (status.status === 'completed' || status.status === 'failed') {
          clearInterval(poll);
          setScanning(false);
          if (status.status === 'completed') {
            const subs = await api('/scan/subscriptions');
            setSubscriptions(subs);
          } else {
            setError('Scan failed. Please try again.');
          }
        }
      }, 2000);
    } catch (err) {
      setScanning(false);
      setError(err.message);
    }
  };

  const toggleSub = (id) => {
    setSelected(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const toggleAll = () => {
    const ghostable = subscriptions.filter(s => s.status !== 'no-unsub');
    if (selected.size === ghostable.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(ghostable.map(s => s.id)));
    }
  };

  const ghostSelected = async () => {
    setGhosting(true);
    setError(null);
    try {
      const data = await api('/ghost', {
        method: 'POST',
        body: JSON.stringify({ subscriptionIds: Array.from(selected) }),
      });
      setResults(data.summary);
      setSelected(new Set());
      const subs = await api('/scan/subscriptions');
      setSubscriptions(subs);
    } catch (err) {
      setError(err.message);
    } finally {
      setGhosting(false);
    }
  };

  if (results) {
    return (
      <div className="summary">
        <h2>Done!</h2>
        <p><span className="summary-stat">{results.ghosted}</span> subscriptions ghosted</p>
        <p><span className="summary-stat">{results.totalArchived}</span> emails archived</p>
        {results.failed > 0 && <p>{results.failed} failed (may need manual unsubscribe)</p>}
        <button className="btn-primary" onClick={() => setResults(null)} style={{ marginTop: '1.5rem' }}>
          Back to list
        </button>
      </div>
    );
  }

  if (scanning) {
    const progress = scanProgress
      ? Math.round((scanProgress.processed_messages / Math.max(scanProgress.total_messages, 1)) * 100)
      : 0;
    return (
      <div className="loading">
        <h2>Scanning your email...</h2>
        <p>Checking the last 6 months for subscriptions</p>
        <div className="progress-bar">
          <div className="progress-fill" style={{ width: `${progress}%` }} />
        </div>
        <p>{scanProgress?.processed_messages || 0} emails processed</p>
      </div>
    );
  }

  if (subscriptions.length === 0) {
    return (
      <div style={{ textAlign: 'center', marginTop: '4rem' }}>
        <h2>Ready to scan</h2>
        <p style={{ color: '#888', margin: '1rem 0' }}>
          We'll check your last 6 months of email for subscriptions.
        </p>
        <button className="btn-primary" onClick={startScan}>Scan my email</button>
        {error && <p className="error">{error}</p>}
      </div>
    );
  }

  const ghostable = subscriptions.filter(s => s.status === 'active');
  const noUnsub = subscriptions.filter(s => s.status === 'no-unsub');
  const alreadyGhosted = subscriptions.filter(s => s.status === 'ghosted');

  return (
    <div>
      <h2>Your Subscriptions</h2>
      <p style={{ color: '#888', marginBottom: '1rem' }}>
        {ghostable.length} active &middot; {alreadyGhosted.length} ghosted &middot; {noUnsub.length} no unsubscribe option
      </p>

      {ghostable.length > 0 && (
        <>
          <button className="toggle-all" onClick={toggleAll}>
            {selected.size === ghostable.length ? 'Deselect All' : 'Select All'}
          </button>

          <div className="subscription-list">
            {ghostable.map(sub => (
              <div key={sub.id} className="sub-item">
                <input
                  type="checkbox"
                  checked={selected.has(sub.id)}
                  onChange={() => toggleSub(sub.id)}
                />
                <label onClick={() => toggleSub(sub.id)}>
                  <div className="sub-name">{sub.sender_name || sub.sender_email}</div>
                  <div className="sub-meta">{sub.sender_email}</div>
                </label>
                <div className="sub-count">{sub.email_count}</div>
              </div>
            ))}
          </div>

          {selected.size > 0 && (
            <button className="btn-ghost" onClick={ghostSelected} disabled={ghosting}>
              {ghosting ? 'Ghosting...' : <>{'\uD83D\uDC7B'} Ghost them ({selected.size})</>}
            </button>
          )}
        </>
      )}

      {noUnsub.length > 0 && (
        <>
          <h3 style={{ marginTop: '2rem', color: '#f59e0b' }}>No unsubscribe option</h3>
          <p style={{ color: '#888', fontSize: '0.9rem', marginBottom: '0.5rem' }}>
            Mark these as spam in Gmail manually.
          </p>
          <div className="subscription-list">
            {noUnsub.map(sub => (
              <div key={sub.id} className="sub-item no-unsub">
                <label>
                  <div className="sub-name">{sub.sender_name || sub.sender_email}</div>
                  <div className="sub-meta">No unsubscribe header found</div>
                </label>
                <div className="sub-count">{sub.email_count}</div>
              </div>
            ))}
          </div>
        </>
      )}

      {error && <p className="error">{error}</p>}
    </div>
  );
}
