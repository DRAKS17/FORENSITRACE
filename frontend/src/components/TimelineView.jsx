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
        return <div className="timeline-loading">Loading forensic timeline stream...</div>;
    }

    if (error) {
        return <div className="error-box">Timeline Error: {error}</div>;
    }

    return (
        <div className="timeline-container">
            <div className="timeline-toolbar">
                <div className="timeline-title-row">
                    <h3>Chronological Forensic Axis</h3>
                    <span className="count-pill">{filtered.length} Timeline Points</span>
                </div>
                <div className="timeline-filters">
                    <button 
                        className={`btn-filter ${filterType === 'all' ? 'active' : ''}`}
                        onClick={() => setFilterType('all')}
                    >
                        All Telemetry
                    </button>
                    <button 
                        className={`btn-filter ${filterType === 'activities' ? 'active' : ''}`}
                        onClick={() => setFilterType('activities')}
                    >
                        Reconstructed Activities
                    </button>
                    <button 
                        className={`btn-filter ${filterType === 'events' ? 'active' : ''}`}
                        onClick={() => setFilterType('events')}
                    >
                        Raw Events
                    </button>
                </div>
            </div>

            {filtered.length === 0 ? (
                <p className="empty-timeline">No chronological entries captured yet.</p>
            ) : (
                <div className="timeline-stream">
                    {filtered.map(item => {
                        const isAct = item.item_type === 'activity';
                        const timeStr = new Date(item.timestamp).toLocaleTimeString();
                        const dateStr = new Date(item.timestamp).toLocaleDateString();

                        return (
                            <div 
                                key={item.id}
                                className={`timeline-card ${isAct ? 'timeline-act' : 'timeline-ev'} ${isAct ? `conf-${item.confidence_level?.toLowerCase()}` : ''}`}
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
                                <div className="timeline-marker"></div>
                                <div className="timeline-content">
                                    <div className="timeline-time-col">
                                        <span className="time-val">{timeStr}</span>
                                        <span className="date-val">{dateStr}</span>
                                    </div>
                                    <div className="timeline-info-col">
                                        <div className="timeline-header-line">
                                            <span className={`pill-type ${isAct ? 'pill-act' : 'pill-ev'}`}>
                                                {isAct ? 'ACTIVITY' : item.source?.toUpperCase()}
                                            </span>
                                            {isAct && item.confidence_level && (
                                                <span className={`pill-conf conf-${item.confidence_level.toLowerCase()}`}>
                                                    {item.confidence_level}
                                                </span>
                                            )}
                                            <strong className="timeline-item-title">{item.title}</strong>
                                        </div>
                                        <p className="timeline-item-desc">{item.description}</p>
                                    </div>
                                </div>
                            </div>
                        );
                    })}
                </div>
            )}
        </div>
    );
}
