import { useState, useEffect } from 'react';
import { getActivities, getMetrics, getIntegrity, triggerCorrelation } from '../api';
import ActivityDetails from './ActivityDetails';
import TimelineView from './TimelineView';

export default function Dashboard() {
    const [activities, setActivities] = useState([]);
    const [metrics, setMetrics] = useState(null);
    const [integrity, setIntegrity] = useState(null);
    const [selectedActivity, setSelectedActivity] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [activeTab, setActiveTab] = useState('activities'); // 'activities' | 'timeline'
    const [confidenceFilter, setConfidenceFilter] = useState('ALL');
    const [searchQuery, setSearchQuery] = useState('');
    const [correlating, setCorrelating] = useState(false);

    const refreshData = async () => {
        try {
            const [acts, mets, int] = await Promise.all([
                getActivities(),
                getMetrics(),
                getIntegrity()
            ]);
            setActivities(acts);
            setMetrics(mets);
            setIntegrity(int);
            if (selectedActivity) {
                const updated = acts.find(a => a.id === selectedActivity.id);
                if (updated) setSelectedActivity(updated);
            }
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        refreshData();
        const interval = setInterval(refreshData, 4000);
        return () => clearInterval(interval);
    }, []);

    const handleRunCorrelation = async () => {
        setCorrelating(true);
        try {
            await triggerCorrelation();
            await refreshData();
        } catch (err) {
            alert('Failed to trigger correlation: ' + err.message);
        } finally {
            setCorrelating(false);
        }
    };

    const filteredActivities = activities.filter(act => {
        if (confidenceFilter !== 'ALL' && act.confidence_level.toUpperCase() !== confidenceFilter.toUpperCase()) {
            return false;
        }
        if (searchQuery.trim()) {
            const query = searchQuery.toLowerCase();
            const matchTitle = act.title.toLowerCase().includes(query);
            const matchNarrative = act.narrative.toLowerCase().includes(query);
            const matchRule = act.rule_name.toLowerCase().includes(query);
            const matchId = String(act.id).includes(query);
            if (!matchTitle && !matchNarrative && !matchRule && !matchId) {
                return false;
            }
        }
        return true;
    });

    const getConfidenceClass = (level) => {
        switch (level?.toUpperCase()) {
            case 'HIGH': return 'high';
            case 'MEDIUM': return 'medium';
            default: return 'low';
        }
    };

    return (
        <div className="dashboard-root">
            {/* Top Shell: Brand & Telemetry Header */}
            <header className="dashboard-header">
                <div className="brand-section">
                    <div className="brand-symbol" title="ForensiTrace Core">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                        </svg>
                    </div>
                    <div className="brand-text">
                        <h1>ForensiTrace <span className="version-tag">PROTOTYPE</span></h1>
                        <p>Cross-Source Correlation Engine for Windows Endpoint Forensics</p>
                    </div>
                </div>

                <div className="system-telemetry-strip">
                    {/* Agent CPU Metric */}
                    <div className="metric-cell">
                        <span className="metric-label">Agent CPU</span>
                        <div className="metric-value-row">
                            <span className="metric-num">{metrics?.avg_cpu_percent !== undefined ? metrics.avg_cpu_percent.toFixed(2) : '0.00'}</span>
                            <span className="metric-unit">%</span>
                        </div>
                    </div>

                    {/* Agent RAM Metric */}
                    <div className="metric-cell">
                        <span className="metric-label">Agent RAM</span>
                        <div className="metric-value-row">
                            <span className="metric-num">{metrics?.avg_memory_mb !== undefined ? metrics.avg_memory_mb.toFixed(1) : '0.0'}</span>
                            <span className="metric-unit">MB</span>
                        </div>
                    </div>

                    {/* Cryptographic Hash Chain Status */}
                    <div className="metric-cell">
                        <span className="metric-label">Hash Chain</span>
                        <div className="metric-value-row">
                            <span className={`chain-badge ${integrity?.intact ? 'verified' : 'tampered'}`}>
                                <span className="status-dot"></span>
                                {integrity?.intact ? 'VERIFIED' : 'TAMPERED'}
                            </span>
                            <span className="metric-unit">({integrity?.total_records ?? 0} recs)</span>
                        </div>
                    </div>

                    {/* Manual Correlation Trigger */}
                    <button 
                        className="btn-run-correlate"
                        onClick={handleRunCorrelation}
                        disabled={correlating}
                        title="Analyze recent event stream with rule engine"
                    >
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <polyline points="23 4 23 10 17 10"></polyline>
                            <polyline points="1 20 1 14 7 14"></polyline>
                            <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path>
                        </svg>
                        {correlating ? 'Analyzing...' : 'Run Correlation'}
                    </button>
                </div>
            </header>

            {/* Sub-Header: Underline Navigation & Filters */}
            <div className="tab-control-bar">
                <nav className="tab-nav">
                    <button 
                        className={`tab-item ${activeTab === 'activities' ? 'active' : ''}`}
                        onClick={() => setActiveTab('activities')}
                    >
                        Reconstructed Activities <span className="tab-count">({activities.length})</span>
                    </button>
                    <button 
                        className={`tab-item ${activeTab === 'timeline' ? 'active' : ''}`}
                        onClick={() => setActiveTab('timeline')}
                    >
                        Forensic Timeline Stream
                    </button>
                </nav>

                {activeTab === 'activities' && (
                    <div className="filter-toolbar">
                        <input 
                            type="text" 
                            className="search-field"
                            placeholder="Filter activities, paths, rules, IDs..."
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                        />
                        <div className="confidence-selector">
                            {['ALL', 'HIGH', 'MEDIUM', 'LOW'].map(lvl => (
                                <button
                                    key={lvl}
                                    className={`conf-opt ${confidenceFilter === lvl ? 'active' : ''}`}
                                    onClick={() => setConfidenceFilter(lvl)}
                                >
                                    {lvl}
                                </button>
                            ))}
                        </div>
                    </div>
                )}
            </div>

            {/* Main Workbench */}
            <main className="workbench">
                {activeTab === 'activities' ? (
                    <div className="workbench-split">
                        {/* Activities Master List */}
                        <aside className="activity-master">
                            <div className="master-header">
                                <span>Correlated Threat Sequence</span>
                                <span>{filteredActivities.length} items</span>
                            </div>

                            {loading && !activities.length ? (
                                <div className="master-header">Loading telemetry stream...</div>
                            ) : filteredActivities.length === 0 ? (
                                <div style={{ padding: '2rem 1rem', textAlign: 'center', color: 'var(--muted)' }}>
                                    <p>No activities match current filters.</p>
                                </div>
                            ) : (
                                <div className="activity-feed">
                                    {filteredActivities.map(act => {
                                        const isSelected = selectedActivity?.id === act.id;
                                        return (
                                            <div
                                                key={act.id}
                                                className={`activity-row ${isSelected ? 'selected' : ''}`}
                                                onClick={() => setSelectedActivity(act)}
                                            >
                                                <div className="row-top">
                                                    <span className={`conf-pill ${getConfidenceClass(act.confidence_level)}`}>
                                                        {act.confidence_level} ({act.confidence_score.toFixed(2)})
                                                    </span>
                                                    <span className="row-rule">{act.rule_name}</span>
                                                </div>

                                                <h4 className="row-title">{act.title}</h4>
                                                <p className="row-snippet">{act.narrative}</p>

                                                <div className="row-footer">
                                                    <span>{new Date(act.timestamp_start).toLocaleTimeString()}</span>
                                                    <span>{act.evidence_event_ids?.length || 0} evidence links</span>
                                                </div>
                                            </div>
                                        );
                                    })}
                                </div>
                            )}
                        </aside>

                        {/* Evidence Provenance Detail Drawer */}
                        <section className="evidence-detail">
                            <ActivityDetails 
                                activity={selectedActivity} 
                                onClose={() => setSelectedActivity(null)}
                            />
                        </section>
                    </div>
                ) : (
                    <TimelineView onSelectActivity={(act) => {
                        setSelectedActivity(act);
                        setActiveTab('activities');
                    }} />
                )}
            </main>
        </div>
    );
}
