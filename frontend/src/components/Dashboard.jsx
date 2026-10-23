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
            // If currently selected activity exists, update its reference if it changed
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
            case 'HIGH': return 'badge-high';
            case 'MEDIUM': return 'badge-medium';
            default: return 'badge-low';
        }
    };

    return (
        <div className="dashboard-root">
            {/* Top Navigation & Status Bar */}
            <header className="dashboard-header">
                <div className="brand-section">
                    <div className="logo-shield">&#128737;</div>
                    <div>
                        <h1>ForensiTrace <span className="version-pill">v2.0 Phase 3</span></h1>
                        <p className="subtitle">Lightweight Cross-Source Correlation Engine for Windows Endpoint Forensics</p>
                    </div>
                </div>

                <div className="system-telemetry-strip">
                    {/* Metrics: CPU */}
                    <div className="metric-card">
                        <span className="metric-label">Agent CPU</span>
                        <div className="metric-val-row">
                            <span className="metric-number">{metrics?.avg_cpu_percent ?? '0.0'}%</span>
                            <span className="metric-sub">avg</span>
                        </div>
                    </div>

                    {/* Metrics: RAM */}
                    <div className="metric-card">
                        <span className="metric-label">Agent RAM</span>
                        <div className="metric-val-row">
                            <span className="metric-number">{metrics?.avg_memory_mb ?? '0.0'}</span>
                            <span className="metric-sub">MB</span>
                        </div>
                    </div>

                    {/* Cryptographic Hash Chain Status */}
                    <div className={`metric-card integrity-card ${integrity?.intact ? 'verified' : 'tampered'}`}>
                        <span className="metric-label">Hash Chain</span>
                        <div className="metric-val-row">
                            <span className="integrity-indicator">
                                {integrity?.intact ? '&#10004; VERIFIED' : '&#9888; TAMPERED'}
                            </span>
                            <span className="metric-sub">{integrity?.total_records ?? 0} recs</span>
                        </div>
                    </div>

                    {/* Manual Correlation Trigger */}
                    <button 
                        className={`btn btn-correlate ${correlating ? 'spinning' : ''}`}
                        onClick={handleRunCorrelation}
                        disabled={correlating}
                        title="Analyze recent event stream with rule engine"
                    >
                        {correlating ? 'Correlating...' : '&#9881; Run Correlation'}
                    </button>
                </div>
            </header>

            {/* Navigation Tabs */}
            <div className="tab-control-bar">
                <div className="tab-buttons">
                    <button 
                        className={`tab-btn ${activeTab === 'activities' ? 'active' : ''}`}
                        onClick={() => setActiveTab('activities')}
                    >
                        &#128065; Reconstructed Activities ({activities.length})
                    </button>
                    <button 
                        className={`tab-btn ${activeTab === 'timeline' ? 'active' : ''}`}
                        onClick={() => setActiveTab('timeline')}
                    >
                        &#128197; Forensic Timeline Stream
                    </button>
                </div>

                {activeTab === 'activities' && (
                    <div className="filter-controls">
                        <input 
                            type="text" 
                            className="search-input"
                            placeholder="Filter activities, paths, rules, IDs..."
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                        />
                        <div className="confidence-toggles">
                            {['ALL', 'HIGH', 'MEDIUM', 'LOW'].map(lvl => (
                                <button
                                    key={lvl}
                                    className={`btn-toggle-lvl ${confidenceFilter === lvl ? 'active' : ''} ${lvl.toLowerCase()}`}
                                    onClick={() => setConfidenceFilter(lvl)}
                                >
                                    {lvl}
                                </button>
                            ))}
                        </div>
                    </div>
                )}
            </div>

            {/* Main Workbench Split View */}
            <main className="workbench">
                {activeTab === 'activities' ? (
                    <div className="workbench-split">
                        {/* Activities List Left Pane */}
                        <div className="activities-master-pane">
                            <div className="pane-header-info">
                                <span>Showing {filteredActivities.length} of {activities.length} activities</span>
                            </div>

                            {loading && !activities.length ? (
                                <div className="loading-state">Initializing ForensiTrace telemetry pipeline...</div>
                            ) : filteredActivities.length === 0 ? (
                                <div className="empty-state">
                                    <p>No activities match the current filter criteria.</p>
                                    <button className="btn btn-secondary" onClick={() => { setConfidenceFilter('ALL'); setSearchQuery(''); }}>
                                        Clear Filters
                                    </button>
                                </div>
                            ) : (
                                <div className="activity-cards-list">
                                    {filteredActivities.map(act => {
                                        const isSelected = selectedActivity?.id === act.id;
                                        return (
                                            <div
                                                key={act.id}
                                                className={`activity-card ${isSelected ? 'selected' : ''}`}
                                                onClick={() => setSelectedActivity(act)}
                                            >
                                                <div className="card-top">
                                                    <span className={`badge ${getConfidenceClass(act.confidence_level)}`}>
                                                        {act.confidence_level} ({act.confidence_score.toFixed(2)})
                                                    </span>
                                                    <span className="card-rule">{act.rule_name}</span>
                                                </div>

                                                <h4 className="card-title">{act.title}</h4>
                                                <p className="card-narrative-preview">{act.narrative}</p>

                                                <div className="card-footer">
                                                    <span className="card-time">{new Date(act.timestamp_start).toLocaleTimeString()}</span>
                                                    <span className="evidence-count-badge">
                                                        {act.evidence_event_ids?.length || 0} evidence links
                                                    </span>
                                                </div>
                                            </div>
                                        );
                                    })}
                                </div>
                            )}
                        </div>

                        {/* Evidence Provenance Right Drawer / Details Pane */}
                        <div className="evidence-detail-pane">
                            <ActivityDetails 
                                activity={selectedActivity} 
                                onClose={() => setSelectedActivity(null)}
                            />
                        </div>
                    </div>
                ) : (
                    <div className="timeline-wrapper">
                        <TimelineView onSelectActivity={(act) => {
                            setSelectedActivity(act);
                            setActiveTab('activities');
                        }} />
                    </div>
                )}
            </main>
        </div>
    );
}
