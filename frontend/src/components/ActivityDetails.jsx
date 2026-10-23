import { useState, useEffect } from 'react';
import { getActivityDetail, getExportPdfUrl } from '../api';

export default function ActivityDetails({ activity, onClose }) {
    const [detail, setDetail] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [expandedRaw, setExpandedRaw] = useState({});

    useEffect(() => {
        if (!activity) return;

        setLoading(true);
        setError(null);
        getActivityDetail(activity.id)
            .then(data => setDetail(data))
            .catch(err => setError(err.message))
            .finally(() => setLoading(false));
    }, [activity]);

    if (!activity) {
        return (
            <div className="detail-empty">
                <div className="empty-prompt">
                    <h3>No Activity Selected</h3>
                    <p>Select any correlated event sequence to inspect its evidence chain and export formal reports.</p>
                </div>
            </div>
        );
    }

    const toggleRaw = (evId) => {
        setExpandedRaw(prev => ({
            ...prev,
            [evId]: !prev[evId]
        }));
    };

    const handleExport = () => {
        window.open(getExportPdfUrl(activity.id), '_blank');
    };

    const act = detail?.activity || activity;
    const evidenceItems = detail?.evidence || [];

    const getConfidenceClass = (level) => {
        switch (level?.toUpperCase()) {
            case 'HIGH': return 'high';
            case 'MEDIUM': return 'medium';
            default: return 'low';
        }
    };

    const getSourceTag = (src) => {
        const s = src?.toLowerCase();
        if (s === 'usb') return 'usb';
        if (s === 'fs') return 'fs';
        if (s === 'eventlog') return 'eventlog';
        return 'default';
    };

    return (
        <div className="detail-view">
            {/* Header & Export Action */}
            <div className="detail-head">
                <div className="detail-title-col">
                    <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                        <span className={`conf-pill ${getConfidenceClass(act.confidence_level)}`}>
                            {act.confidence_level} ({act.confidence_score.toFixed(2)})
                        </span>
                        <span className="row-rule">RULE: {act.rule_name}</span>
                    </div>
                    <h2>{act.title}</h2>
                    <div className="detail-meta-row">
                        <span>Timeframe: {new Date(act.timestamp_start).toISOString()} &rarr; {new Date(act.timestamp_end).toISOString()}</span>
                    </div>
                </div>

                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                    <button className="btn-export-pdf" onClick={handleExport} title="Download forensic PDF report">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                            <polyline points="14 2 14 8 20 8"></polyline>
                            <line x1="12" y1="18" x2="12" y2="12"></line>
                            <line x1="9" y1="15" x2="15" y2="15"></line>
                        </svg>
                        Export Report (PDF)
                    </button>
                    {onClose && (
                        <button 
                            onClick={onClose}
                            style={{ background: 'transparent', border: 'none', color: 'var(--muted)', cursor: 'pointer', fontSize: '18px' }}
                            title="Close pane"
                        >
                            &times;
                        </button>
                    )}
                </div>
            </div>

            {/* Narrative Explanation */}
            <div className="narrative-card">
                <div className="narrative-head">Forensic Threat Narrative</div>
                <p className="narrative-body">{act.narrative}</p>
            </div>

            {/* Provenance Chain */}
            <div className="provenance-section">
                <div className="provenance-header-row">
                    <h3>Cross-Source Evidence Chain</h3>
                    <span className="count-tag">{evidenceItems.length} Linked Artifacts</span>
                </div>

                {loading ? (
                    <div style={{ padding: '1rem', color: 'var(--muted)' }}>Auditing evidence links...</div>
                ) : error ? (
                    <div style={{ color: 'var(--negative)', padding: '1rem' }}>Failed to retrieve provenance: {error}</div>
                ) : evidenceItems.length === 0 ? (
                    <p style={{ color: 'var(--muted)' }}>No underlying evidence links captured.</p>
                ) : (
                    <div className="stepped-chain">
                        {evidenceItems.map((item, index) => {
                            const ev = item.event;
                            const isExpanded = !!expandedRaw[ev.id];
                            return (
                                <div key={ev.id} className="step-row">
                                    <div className="step-spine">
                                        <div className="step-node">{index + 1}</div>
                                        {index < evidenceItems.length - 1 && <div className="step-connector"></div>}
                                    </div>

                                    <div className="step-card">
                                        <div className="step-top">
                                            <span className={`source-tag ${getSourceTag(ev.source)}`}>
                                                {ev.source.toUpperCase()}
                                            </span>
                                            <span className="action-label">{ev.action}</span>
                                            <span className="step-time">
                                                {new Date(ev.timestamp).toLocaleTimeString()} ({new Date(ev.timestamp).toISOString()})
                                            </span>
                                        </div>

                                        <div className="step-target">
                                            <code>{ev.entity}</code>
                                        </div>

                                        <div className="reason-callout">
                                            <strong>Provenance Link:</strong> {item.reason}
                                        </div>

                                        <div className="raw-toggle-bar">
                                            <button 
                                                className="btn-raw"
                                                onClick={() => toggleRaw(ev.id)}
                                            >
                                                {isExpanded ? 'Hide Raw Telemetry' : 'Show Raw Telemetry'}
                                            </button>
                                            <span className="hash-digest" title={ev.record_hash}>
                                                SHA-256: {ev.record_hash.substring(0, 16)}...
                                            </span>
                                        </div>

                                        {isExpanded && (
                                            <pre className="raw-json-viewer">
                                                {JSON.stringify(ev.raw_data || ev.details, null, 2)}
                                            </pre>
                                        )}
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                )}
            </div>
        </div>
    );
}
