import { useState, useEffect } from 'react';
import { getActivities, getMetrics, getIntegrity } from '../api';
import ActivityDetails from './ActivityDetails';

export default function Dashboard() {
    const [activities, setActivities] = useState([]);
    const [metrics, setMetrics] = useState(null);
    const [integrity, setIntegrity] = useState(null);
    const [selectedActivity, setSelectedActivity] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        const fetchData = async () => {
            try {
                const [acts, mets, int] = await Promise.all([
                    getActivities(),
                    getMetrics(),
                    getIntegrity()
                ]);
                setActivities(acts);
                setMetrics(mets);
                setIntegrity(int);
            } catch (err) {
                setError(err.message);
            } finally {
                setLoading(false);
            }
        };

        fetchData();
        // Poll every 5 seconds for live updates
        const interval = setInterval(fetchData, 5000);
        return () => clearInterval(interval);
    }, []);

    const getConfidenceColor = (level) => {
        switch (level?.toUpperCase()) {
            case 'HIGH': return 'var(--color-high)';
            case 'MEDIUM': return 'var(--color-medium)';
            default: return 'var(--color-low)';
        }
    };

    if (loading && !activities.length) return <div className="loading">Loading ForensiTrace Dashboard...</div>;
    if (error) return <div className="error">Error: {error}</div>;

    return (
        <div className="dashboard">
            <header className="header">
                <h1>ForensiTrace Correlation Engine</h1>
                <div className="status-bars">
                    <div className="metric-box">
                        <span className="label">Agent CPU:</span>
                        <span className="value">{metrics?.avg_cpu_percent}%</span>
                    </div>
                    <div className="metric-box">
                        <span className="label">Agent RAM:</span>
                        <span className="value">{metrics?.avg_memory_mb} MB</span>
                    </div>
                    <div className={`metric-box ${integrity?.intact ? 'intact' : 'tampered'}`}>
                        <span className="label">DB Chain:</span>
                        <span className="value">{integrity?.intact ? 'VERIFIED' : 'COMPROMISED'}</span>
                    </div>
                </div>
            </header>

            <main className="main-content">
                <div className="activities-pane">
                    <h2>Reconstructed Activities</h2>
                    {activities.length === 0 ? (
                        <p>No activities detected yet.</p>
                    ) : (
                        <ul className="activity-list">
                            {activities.map(act => (
                                <li 
                                    key={act.id} 
                                    className={`activity-row ${selectedActivity?.id === act.id ? 'selected' : ''}`}
                                    onClick={() => setSelectedActivity(act)}
                                    style={{ borderLeft: `4px solid ${getConfidenceColor(act.confidence_level)}` }}
                                >
                                    <div className="activity-header">
                                        <strong>{act.title}</strong>
                                        <span 
                                            className="badge" 
                                            style={{ backgroundColor: getConfidenceColor(act.confidence_level) }}
                                        >
                                            {act.confidence_level}
                                        </span>
                                    </div>
                                    <div className="activity-meta">
                                        <span>{new Date(act.timestamp_start).toLocaleString()}</span>
                                        <span>Score: {act.confidence_score.toFixed(2)}</span>
                                    </div>
                                </li>
                            ))}
                        </ul>
                    )}
                </div>

                <ActivityDetails activity={selectedActivity} />
            </main>
        </div>
    );
}
