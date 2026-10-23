/**
 * ForensiTrace - Frontend API Service Module
 * Interfaces with the FastAPI backend at http://localhost:8000
 */

const BASE_URL = 'http://localhost:8000/api/v1';

export async function getActivities(confidenceLevel = null) {
    const url = confidenceLevel
        ? `${BASE_URL}/activities?confidence_level=${encodeURIComponent(confidenceLevel)}`
        : `${BASE_URL}/activities`;
    const response = await fetch(url);
    if (!response.ok) {
        throw new Error(`Failed to fetch activities: ${response.statusText}`);
    }
    return response.json();
}

export async function getActivityDetail(id) {
    const response = await fetch(`${BASE_URL}/activities/${id}`);
    if (!response.ok) {
        throw new Error(`Failed to fetch activity details for #${id}`);
    }
    return response.json();
}

export async function getActivityEvidence(id) {
    const response = await fetch(`${BASE_URL}/activities/${id}/evidence`);
    if (!response.ok) {
        throw new Error(`Failed to fetch evidence for activity #${id}`);
    }
    return response.json();
}

export async function getTimeline() {
    const response = await fetch(`${BASE_URL}/timeline`);
    if (!response.ok) {
        throw new Error('Failed to fetch forensic timeline');
    }
    return response.json();
}

export async function getMetrics() {
    const response = await fetch(`${BASE_URL}/metrics`);
    if (!response.ok) {
        throw new Error('Failed to fetch agent metrics');
    }
    return response.json();
}

export async function getIntegrity() {
    const response = await fetch(`${BASE_URL}/integrity`);
    if (!response.ok) {
        throw new Error('Failed to fetch database integrity status');
    }
    return response.json();
}

export async function triggerCorrelation() {
    const response = await fetch(`${BASE_URL}/correlate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    });
    if (!response.ok) {
        throw new Error('Failed to execute correlation engine');
    }
    return response.json();
}

export function getExportPdfUrl(id) {
    return `${BASE_URL}/activities/${id}/export`;
}
