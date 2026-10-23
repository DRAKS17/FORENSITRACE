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
            .then(data => {
                setDetail(data);
            })
            .catch(err => setError(err.message))
            .finally(() => setLoading(false));
    }, [activity]);

    if (!activity) {
        return (
            <div className="details-pane empty">
                <div className="empty-state">
                    <span className="empty-icon">&#128269;</span>
                    <h3>Select an Activity</h3>
                    <p>Click on any correlated forensic activity from the list or timeline to inspect its evidence provenance and export formal reports.</p>
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
            case 'HIGH': return 'badge-high';
            case 'MEDIUM': return 'badge-medium';
            default: return 'badge-low';
        }
    };

    const getSourceClass = (src) => {
        const s = src?.toLowerCase();
        if (s === 'usb') return 'source-usb';
        if (s === 'fs') return 'source-fs';
        if (s === 'eventlog') return 'source-eventlog';
        return 'source-default';
    };

    return (
        <div className="details-pane">
            <div className="details-header">
                <div className="details-header-title">
                    <div className="tag-row">
                        <span className={`badge ${getConfidenceClass(act.confidence_level)}`}>
                            {act.confidence_level} CONFIDENCE ({act.confidence_score.toFixed(2)})
                        </span>
                        <span className="rule-tag">RULE: {act.rule_name}</span>
                    </div>
                    <h2>{act.title}</h2>
                    <div className="meta-time">
                        <span>Observed: {new Date(act.timestamp_start).toLocaleString()} &rarr; {new Date(act.timestamp_end).toLocaleString()}</span>
                    </div>
                </div>

                <div className="details-actions">
                    <button className="btn btn-export" onClick={handleExport} title="Download formal PDF with cryptographic assurance">
                        &#128196; Export PDF Report
                    </button>
                    {onClose && (
                        <button className="btn btn-close" onClick={onClose} title="Close drawer">
                            &times;
                        </button>
                    )}
                </div>
            </div>

            <div className="narrative-box">
                <div className="narrative-label">&#128220; Reconstructed Threat Narrative</div>
                <p className="narrative-text">{act.narrative}</p>
            </div>

            <div className="evidence-section">
                <div className="section-title-bar">
                    <h3>Evidence Provenance &amp; Cross-Source Chain</h3>
                    <span className="count-pill">{evidenceItems.length} Verified Artifacts</span>
                </div>

                {loading ? (
                    <div className="loading-evidence">Auditing evidence chain...</div>
                ) : error ? (
                    <div className="error-box">Error loading provenance: {error}</div>
                ) : evidenceItems.length === 0 ? (
                    <p className="empty-evidence">No linked evidence events found.</p>
                ) : (
                    <div className="evidence-timeline">
                        {evidenceItems.map((item, index) => {
                            const ev = item.event;
                            const isExpanded = !!expandedRaw[ev.id];
                            return (
                                <div key={ev.id} className="evidence-item">
                                    <div className="evidence-step-indicator">
                                        <div className="step-number">{index + 1}</div>
                                        {index < evidenceItems.length - 1 && <div className="step-line"></div>}
                                    </div>

                                    <div className="evidence-body">
                                        <div className="evidence-top-row">
                                            <span className={`source-badge ${getSourceClass(ev.source)}`}>
                                                {ev.source.toUpperCase()}
                                            </span>
                                            <span className="action-tag">{ev.action}</span>
                                            <span className="time-tag">{new Date(ev.timestamp).toLocaleTimeString()} ({new Date(ev.timestamp).toISOString()})</span>
                                            <span className="ev-id-badge">ID #{ev.id}</span>
                                        </div>

                                        <div className="entity-box">
                                            <strong>Target:</strong> <code>{ev.entity}</code>
                                        </div>

                                        <div className="reason-box">
                                            <span className="reason-label">&#9888; Provenance Reason:</span>
                                            <span className="reason-text">{item.reason}</span>
                                        </div>

                                        <div className="raw-toggle-row">
                                            <button 
                                                className="btn-toggle-raw"
                                                onClick={() => toggleRaw(ev.id)}
                                            >
                                                {isExpanded ? 'Hide Raw Telemetry &and;' : 'View Raw Telemetry &or;'}
                                            </button>
                                            <span className="hash-preview" title={ev.record_hash}>
                                                SHA-256: {ev.record_hash.substring(0, 16)}...
                                            </span>
                                        </div>

                                        {isExpanded && (
                                            <pre className="raw-data-block">
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
