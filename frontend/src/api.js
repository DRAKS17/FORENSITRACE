const BASE_URL = 'http://localhost:8000/api/v1';

export async function getActivities() {
    const response = await fetch(`${BASE_URL}/activities`);
    if (!response.ok) {
        throw new Error('Failed to fetch activities');
    }
    return response.json();
}

export async function getActivityEvidence(id) {
    const response = await fetch(`${BASE_URL}/activities/${id}/evidence`);
    if (!response.ok) {
        throw new Error('Failed to fetch evidence');
    }
    return response.json();
}

export async function getMetrics() {
    const response = await fetch(`${BASE_URL}/metrics`);
    if (!response.ok) {
        throw new Error('Failed to fetch metrics');
    }
    return response.json();
}

export async function getIntegrity() {
    const response = await fetch(`${BASE_URL}/integrity`);
    if (!response.ok) {
        throw new Error('Failed to fetch integrity status');
    }
    return response.json();
}
