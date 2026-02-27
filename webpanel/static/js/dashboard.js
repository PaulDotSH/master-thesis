// Dashboard page logic
document.addEventListener('DOMContentLoaded', async () => {
    await loadStats();
    await loadCharts();
});

async function loadStats() {
    try {
        const stats = await Api.getStats();
        
        document.getElementById('total-crates').textContent = formatNumber(stats.total_crates);
        document.getElementById('total-scanned').textContent = formatNumber(stats.total_scanned);
        document.getElementById('total-dependencies').textContent = formatNumber(stats.total_dependencies);
        document.getElementById('malicious-count').textContent = formatNumber(stats.malicious_count);
        document.getElementById('high-risk-count').textContent = formatNumber(stats.high_risk_count);
        document.getElementById('vulnerabilities-count').textContent = formatNumber(stats.vulnerabilities_count);
        document.getElementById('secrets-found').textContent = formatNumber(stats.secrets_found);
        document.getElementById('typosquat-count').textContent = formatNumber(stats.typosquat_count);
    } catch (error) {
        console.error('Failed to load stats:', error);
    }
}

async function loadCharts() {
    const chartColors = {
        success: 'rgba(78, 204, 163, 0.8)',
        warning: 'rgba(255, 201, 60, 0.8)',
        danger: 'rgba(233, 69, 96, 0.8)',
        info: 'rgba(108, 180, 238, 0.8)',
        purple: 'rgba(163, 122, 255, 0.8)',
        teal: 'rgba(20, 194, 215, 0.8)'
    };

    const chartDefaults = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                labels: {
                    color: '#a0a0a0'
                }
            }
        },
        scales: {
            x: {
                ticks: { color: '#a0a0a0' },
                grid: { color: 'rgba(255,255,255,0.1)' }
            },
            y: {
                ticks: { color: '#a0a0a0' },
                grid: { color: 'rgba(255,255,255,0.1)' }
            }
        }
    };

    // Risk Distribution Chart
    try {
        const riskData = await Api.getRiskDistribution();
        new Chart(document.getElementById('riskChart'), {
            type: 'doughnut',
            data: {
                labels: riskData.map(d => d.range),
                datasets: [{
                    data: riskData.map(d => d.count),
                    backgroundColor: [chartColors.success, chartColors.warning, chartColors.danger, chartColors.purple]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: { color: '#a0a0a0' }
                    }
                }
            }
        });
    } catch (error) {
        console.error('Failed to load risk chart:', error);
    }

    // Severity Distribution Chart
    try {
        const severityData = await Api.getSeverityDistribution();
        const severityLabels = severityData.map(d => {
            if (d.severity === null) return 'Unknown';
            if (d.severity <= 3) return 'Low';
            if (d.severity <= 6) return 'Medium';
            return 'High';
        });
        new Chart(document.getElementById('severityChart'), {
            type: 'bar',
            data: {
                labels: severityLabels,
                datasets: [{
                    label: 'Vulnerabilities',
                    data: severityData.map(d => d.count),
                    backgroundColor: severityData.map(d => {
                        if (d.severity === null) return chartColors.info;
                        if (d.severity <= 3) return chartColors.success;
                        if (d.severity <= 6) return chartColors.warning;
                        return chartColors.danger;
                    })
                }]
            },
            options: {
                ...chartDefaults,
                plugins: {
                    legend: { display: false }
                }
            }
        });
    } catch (error) {
        console.error('Failed to load severity chart:', error);
    }

    // Build.rs Stats Chart
    try {
        const buildRsData = await Api.getBuildRsStats();
        new Chart(document.getElementById('buildRsChart'), {
            type: 'bar',
            data: {
                labels: ['Network Calls', 'Link Directive', 'Process Spawning', 'Raw IP', 'Free TLDs'],
                datasets: [{
                    label: 'Crates with Flag',
                    data: [
                        buildRsData.network_calls,
                        buildRsData.link_directive,
                        buildRsData.process_spawning,
                        buildRsData.raw_ip,
                        buildRsData.free_tlds
                    ],
                    backgroundColor: [
                        chartColors.danger,
                        chartColors.warning,
                        chartColors.danger,
                        chartColors.danger,
                        chartColors.warning
                    ]
                }]
            },
            options: {
                ...chartDefaults,
                indexAxis: 'y',
                plugins: {
                    legend: { display: false }
                }
            }
        });
    } catch (error) {
        console.error('Failed to load build.rs chart:', error);
    }

    // Top Downloaded Chart
    try {
        const topDownloaded = await Api.getTopDownloaded();
        new Chart(document.getElementById('downloadsChart'), {
            type: 'bar',
            data: {
                labels: topDownloaded.map(d => d.name),
                datasets: [{
                    label: 'Downloads',
                    data: topDownloaded.map(d => d.downloads),
                    backgroundColor: chartColors.info
                }]
            },
            options: {
                ...chartDefaults,
                indexAxis: 'y',
                plugins: {
                    legend: { display: false }
                }
            }
        });
    } catch (error) {
        console.error('Failed to load downloads chart:', error);
    }

    // Gitleaks Rules Chart
    try {
        const gitleaksData = await Api.getGitleaksRules();
        new Chart(document.getElementById('gitleaksChart'), {
            type: 'bar',
            data: {
                labels: gitleaksData.map(d => d.rule_id),
                datasets: [{
                    label: 'Secrets Found',
                    data: gitleaksData.map(d => d.count),
                    backgroundColor: chartColors.purple
                }]
            },
            options: {
                ...chartDefaults,
                plugins: {
                    legend: { display: false }
                }
            }
        });
    } catch (error) {
        console.error('Failed to load gitleaks chart:', error);
    }
}
