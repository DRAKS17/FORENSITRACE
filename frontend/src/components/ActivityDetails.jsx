import { useState, useEffect } from 'react';
import { getActivityEvidence } from '../api';

export default function ActivityDetails({ activity }) {
    const [evidence, setEvidence] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        if (!activity) return;

        setLoading(true);
        getActivityEvidence(activity.id)
            .then(data => setEvidence(data))
            .catch(err => setError(err.message))
            .finally(() => setLoading(false));
    }, [activity]);

    if (!activity) {
        return <div className="details-pane empty">Select an activity to view details</div>;
    }

    const handleExport = () => {
        window.open(`http://localhost:8000/api/v1/activities/${activity.id}/export`, '_blank');
    };

    return (
        <div className="details-pane">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <h2>Activity Details</h2>
                <button 
                    onClick={handleExport}
                    style={{
                        padding: '0.5rem 1rem',
                        backgroundColor: 'var(--accent-color)',
                        color: 'white',
                        border: 'none',
                        borderRadius: '4px',
                        cursor: 'pointer',
                        fontWeight: 'bold'
                    }}
                >
                    Export Forensic Report (PDF)
                </button>
            </div>
            <div className="narrative-box">
                <p>{activity.narrative}</p>
            </div>

            <h3>Evidence Provenance</h3>
            {loading ? (
                <p>Loading evidence...</p>
            ) : error ? (
                <p className="error">{error}</p>
            ) : (
                <div className="evidence-timeline">
                    {evidence.map((ev, index) => (
                        <div key={ev.id} className="evidence-item">
                            <div className="evidence-badge">{index + 1}</div>
                            <div className="evidence-content">
                                <strong>{ev.source.toUpperCase()} - {ev.action.toUpperCase()}</strong>
                                <div>{new Date(ev.timestamp).toLocaleString()}</div>
                                <div className="entity-text">{ev.entity}</div>
                                <pre className="raw-data">{JSON.stringify(ev.raw_data, null, 2)}</pre>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}
