import { useState, useEffect } from 'react';
import { getTimeline } from '../api';

export default function TimelineView({ onSelectActivity }) {
    const [timelineItems, setTimelineItems] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [filterType, setFilterType] = useState('all');

    useEffect(() => {
        const fetchTimeline = () => {
            getTimeline()
                .then(data => setTimelineItems(data))
                .catch(err => setError(err.message))
                .finally(() => setLoading(false));
        };

        fetchTimeline();
        const interval = setInterval(fetchTimeline, 5000);
        return () => clearInterval(interval);
    }, []);

    const filtered = timelineItems.filter(item => {
        if (filterType === 'activities') return item.item_type === 'activity';
        if (filterType === 'events') return item.item_type === 'event';
        return true;
    });

    if (loading && !timelineItems.length) {
        return <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--muted)' }}>Loading chronological telemetry stream...</div>;
    }

    if (error) {
        return <div style={{ padding: '2rem', color: 'var(--negative)' }}>Timeline Error: {error}</div>;
    }

    return (
        <div className="timeline-pane">
            <div className="timeline-nav-row">
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <h3>Chronological Forensic Axis</h3>
                    <span className="count-tag">({filtered.length} entries)</span>
                </div>
                <div className="filter-segments">
                    <button 
                        className={`seg-btn ${filterType === 'all' ? 'active' : ''}`}
                        onClick={() => setFilterType('all')}
                    >
                        All
                    </button>
                    <button 
                        className={`seg-btn ${filterType === 'activities' ? 'active' : ''}`}
                        onClick={() => setFilterType('activities')}
                    >
                        Activities Only
                    </button>
                    <button 
                        className={`seg-btn ${filterType === 'events' ? 'active' : ''}`}
                        onClick={() => setFilterType('events')}
                    >
                        Raw Events Only
                    </button>
                </div>
            </div>

            {filtered.length === 0 ? (
                <p style={{ textAlign: 'center', color: 'var(--muted)', padding: '3rem' }}>No entries found for the selected filter.</p>
            ) : (
                <div className="timeline-feed">
                    {filtered.map(item => {
                        const isAct = item.item_type === 'activity';
                        const timeStr = new Date(item.timestamp).toLocaleTimeString();
                        const dateStr = new Date(item.timestamp).toLocaleDateString();
                        const confClass = item.confidence_level?.toLowerCase() || '';

                        return (
                            <div 
                                key={item.id}
                                className={`timeline-entry ${isAct ? `entry-act ${confClass}` : ''}`}
                                onClick={() => {
                                    if (isAct && onSelectActivity) {
                                        onSelectActivity({
                                            id: item.ref_id,
                                            title: item.title,
                                            narrative: item.description,
                                            confidence_level: item.confidence_level,
                                            confidence_score: item.confidence_score,
                                            timestamp_start: item.timestamp,
                                            timestamp_end: item.timestamp,
                                            rule_name: item.rule_name || 'CORRELATED'
                                        });
                                    }
                                }}
                            >
                                <div className="entry-time-col">
                                    <span className="time-clock">{timeStr}</span>
                                    <span className="time-day">{dateStr}</span>
                                </div>

                                <div className="entry-body">
                                    <div className="entry-lead">
                                        <span className={`entry-source-pill ${isAct ? 'act' : item.source}`}>
                                            {isAct ? 'CORRELATED ACTIVITY' : item.source?.toUpperCase()}
                                        </span>
                                        {isAct && item.confidence_level && (
                                            <span className={`conf-pill ${confClass}`}>
                                                {item.confidence_level}
                                            </span>
                                        )}
                                        <strong className="entry-title-text">{item.title}</strong>
                                    </div>
                                    <p className="entry-desc-text">{item.description}</p>
                                </div>
                            </div>
                        );
                    })}
                </div>
            )}
        </div>
    );
}
