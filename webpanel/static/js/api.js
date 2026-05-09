// API utility functions
const API_BASE = '';

class Api {
    static async get(endpoint, params = {}) {
        const url = new URL(endpoint, window.location.origin);
        Object.entries(params).forEach(([key, value]) => {
            if (value !== null && value !== undefined && value !== '') {
                url.searchParams.append(key, value);
            }
        });
        
        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`API Error: ${response.status} ${response.statusText}`);
        }
        return response.json();
    }

    // Dashboard stats
    static async getStats() {
        return this.get('/api/stats');
    }

    static async getSeverityDistribution() {
        return this.get('/api/stats/severity');
    }

    static async getRiskDistribution() {
        return this.get('/api/stats/risk');
    }

    static async getBuildRsStats() {
        return this.get('/api/stats/build-rs');
    }

    static async getTopDownloaded() {
        return this.get('/api/stats/top-downloaded');
    }

    static async getGitleaksRules() {
        return this.get('/api/stats/gitleaks-rules');
    }

    // Crates
    static async getCrates(params = {}) {
        return this.get('/api/crates', params);
    }

    static async getCrate(id) {
        return this.get(`/api/crates/${id}`);
    }

    static async getCrateByName(name) {
        return this.get(`/api/crates/name/${encodeURIComponent(name)}`);
    }

    // Dependencies
    static async getDependencies(params = {}) {
        return this.get('/api/dependencies', params);
    }

    // Scan Results
    static async getScanResults(params = {}) {
        return this.get('/api/scan-results', params);
    }

    static async getScanResult(id) {
        return this.get(`/api/scan-results/${id}`);
    }

    // Cargo Audit (Vulnerabilities)
    static async getCargoAudit(params = {}) {
        return this.get('/api/cargo-audit', params);
    }

    // Gitleaks (Secrets)
    static async getGitleaks(params = {}) {
        return this.get('/api/gitleaks', params);
    }

    // Analysis metrics
    static async getMetrics(params = {}) {
        return this.get('/api/metrics', params);
    }

    // Typosquat
    static async getTyposquat(params = {}) {
        return this.get('/api/typosquat', params);
    }
}

// Utility functions
function formatNumber(num) {
    if (num === null || num === undefined) return '-';
    if (num >= 1000000) {
        return (num / 1000000).toFixed(1) + 'M';
    }
    if (num >= 1000) {
        return (num / 1000).toFixed(1) + 'K';
    }
    return num.toLocaleString();
}

function formatDate(dateStr) {
    if (!dateStr) return '-';
    const date = new Date(dateStr);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    });
}

function getRiskClass(score) {
    if (score <= 30) return 'success';
    if (score <= 60) return 'warning';
    return 'danger';
}

function getSeverityLabel(severity) {
    if (severity === null || severity === undefined) return { label: 'Unknown', class: 'info' };
    if (severity <= 3) return { label: 'Low', class: 'success' };
    if (severity <= 6) return { label: 'Medium', class: 'warning' };
    return { label: 'High', class: 'danger' };
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function truncate(text, maxLength = 50) {
    if (!text || text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...';
}

// Table class for reusable paginated tables
class DataTable {
    constructor(options) {
        this.containerId = options.containerId;
        this.fetchData = options.fetchData;
        this.columns = options.columns;
        this.filters = options.filters || [];
        this.defaultSort = options.defaultSort || 'id';
        this.defaultSortDesc = options.defaultSortDesc ?? true;
        
        this.page = 1;
        this.perPage = 50;
        this.sortBy = this.defaultSort;
        this.sortDesc = this.defaultSortDesc;
        this.filterValues = {};
        this.data = [];
        this.total = 0;
        
        this.init();
    }

    init() {
        this.render();
        this.bindEvents();
        this.loadData();
    }

    render() {
        const container = document.getElementById(this.containerId);
        const tableRef = `window['${this.containerId}Table']`;
        container.innerHTML = `
            <div class="table-header">
                <h2>${this.containerId.replace('-', ' ').replace(/\b\w/g, l => l.toUpperCase())}</h2>
                <div class="filters">
                    ${this.filters.map(f => this.renderFilter(f)).join('')}
                    <button onclick="${tableRef}.applyFilters()">Apply</button>
                    <button class="secondary" onclick="${tableRef}.resetFilters()">Reset</button>
                </div>
            </div>
            <div class="table-scroll">
                <table>
                    <thead>
                        <tr>
                            ${this.columns.map(col => `
                                <th data-sort="${col.key}" class="${this.sortBy === col.key ? (this.sortDesc ? 'sorted-desc' : 'sorted-asc') : ''}">
                                    ${col.label}
                                </th>
                            `).join('')}
                        </tr>
                    </thead>
                    <tbody id="${this.containerId}-body">
                        <tr><td colspan="${this.columns.length}" class="loading">Loading data</td></tr>
                    </tbody>
                </table>
            </div>
            <div class="pagination">
                <div class="pagination-info">
                    <span id="${this.containerId}-info">Showing 0 of 0</span>
                </div>
                <div class="pagination-controls">
                    <button onclick="${tableRef}.goToPage(1)" id="${this.containerId}-first">First</button>
                    <button onclick="${tableRef}.prevPage()" id="${this.containerId}-prev">Prev</button>
                    <span id="${this.containerId}-pages"></span>
                    <button onclick="${tableRef}.nextPage()" id="${this.containerId}-next">Next</button>
                    <button onclick="${tableRef}.goToPage(${tableRef}.totalPages)" id="${this.containerId}-last">Last</button>
                    <select onchange="${tableRef}.changePerPage(this.value)">
                        <option value="25">25</option>
                        <option value="50" selected>50</option>
                        <option value="100">100</option>
                    </select>
                </div>
            </div>
        `;
    }

    renderFilter(filter) {
        if (filter.type === 'text') {
            return `
                <div class="filter-group">
                    <label>${filter.label}</label>
                    <input type="text" id="${this.containerId}-filter-${filter.key}" placeholder="${filter.placeholder || ''}">
                </div>
            `;
        }
        if (filter.type === 'select') {
            return `
                <div class="filter-group">
                    <label>${filter.label}</label>
                    <select id="${this.containerId}-filter-${filter.key}">
                        <option value="">All</option>
                        ${filter.options.map(opt => `<option value="${opt.value}">${opt.label}</option>`).join('')}
                    </select>
                </div>
            `;
        }
        if (filter.type === 'number') {
            return `
                <div class="filter-group">
                    <label>${filter.label}</label>
                    <input type="number" id="${this.containerId}-filter-${filter.key}" placeholder="${filter.placeholder || ''}">
                </div>
            `;
        }
        return '';
    }

    bindEvents() {
        const container = document.getElementById(this.containerId);
        container.querySelectorAll('th[data-sort]').forEach(th => {
            th.addEventListener('click', () => this.sort(th.dataset.sort));
        });
    }

    async loadData() {
        const tbody = document.getElementById(`${this.containerId}-body`);
        tbody.innerHTML = `<tr><td colspan="${this.columns.length}" class="loading">Loading data</td></tr>`;

        try {
            const params = {
                page: this.page,
                per_page: this.perPage,
                sort_by: this.sortBy,
                sort_desc: this.sortDesc,
                ...this.filterValues
            };

            const response = await this.fetchData(params);
            this.data = response.data;
            this.total = response.total;
            this.totalPages = response.total_pages;

            this.renderData();
            this.updatePagination();
        } catch (error) {
            console.error('Failed to load data:', error);
            tbody.innerHTML = `<tr><td colspan="${this.columns.length}" class="empty-state">Failed to load data: ${error.message}</td></tr>`;
        }
    }

    renderData() {
        const tbody = document.getElementById(`${this.containerId}-body`);
        
        if (this.data.length === 0) {
            tbody.innerHTML = `<tr><td colspan="${this.columns.length}" class="empty-state">No data found</td></tr>`;
            return;
        }

        tbody.innerHTML = this.data.map(row => `
            <tr>
                ${this.columns.map(col => `<td>${col.render ? col.render(row[col.key], row) : escapeHtml(String(row[col.key] ?? ''))}</td>`).join('')}
            </tr>
        `).join('');
    }

    updatePagination() {
        const info = document.getElementById(`${this.containerId}-info`);
        const start = (this.page - 1) * this.perPage + 1;
        const end = Math.min(this.page * this.perPage, this.total);
        info.textContent = `Showing ${start}-${end} of ${this.total.toLocaleString()}`;

        document.getElementById(`${this.containerId}-first`).disabled = this.page === 1;
        document.getElementById(`${this.containerId}-prev`).disabled = this.page === 1;
        document.getElementById(`${this.containerId}-next`).disabled = this.page >= this.totalPages;
        document.getElementById(`${this.containerId}-last`).disabled = this.page >= this.totalPages;

        // Page numbers
        const pagesContainer = document.getElementById(`${this.containerId}-pages`);
        let pagesHtml = '';
        const maxPages = 5;
        let startPage = Math.max(1, this.page - Math.floor(maxPages / 2));
        let endPage = Math.min(this.totalPages, startPage + maxPages - 1);
        startPage = Math.max(1, endPage - maxPages + 1);

        const tableRef = `window['${this.containerId}Table']`;
        for (let i = startPage; i <= endPage; i++) {
            pagesHtml += `<button onclick="${tableRef}.goToPage(${i})" class="${i === this.page ? 'active' : ''}">${i}</button>`;
        }
        pagesContainer.innerHTML = pagesHtml;

        // Update sort headers
        const container = document.getElementById(this.containerId);
        container.querySelectorAll('th[data-sort]').forEach(th => {
            th.classList.remove('sorted-asc', 'sorted-desc');
            if (th.dataset.sort === this.sortBy) {
                th.classList.add(this.sortDesc ? 'sorted-desc' : 'sorted-asc');
            }
        });
    }

    sort(column) {
        if (this.sortBy === column) {
            this.sortDesc = !this.sortDesc;
        } else {
            this.sortBy = column;
            this.sortDesc = true;
        }
        this.page = 1;
        this.loadData();
    }

    goToPage(page) {
        this.page = Math.max(1, Math.min(page, this.totalPages));
        this.loadData();
    }

    prevPage() {
        this.goToPage(this.page - 1);
    }

    nextPage() {
        this.goToPage(this.page + 1);
    }

    changePerPage(value) {
        this.perPage = parseInt(value);
        this.page = 1;
        this.loadData();
    }

    applyFilters() {
        this.filterValues = {};
        this.filters.forEach(filter => {
            const el = document.getElementById(`${this.containerId}-filter-${filter.key}`);
            if (el && el.value) {
                this.filterValues[filter.key] = el.value;
            }
        });
        this.page = 1;
        this.loadData();
    }

    resetFilters() {
        this.filters.forEach(filter => {
            const el = document.getElementById(`${this.containerId}-filter-${filter.key}`);
            if (el) el.value = '';
        });
        this.filterValues = {};
        this.page = 1;
        this.loadData();
    }
}

// Export for global use
window.Api = Api;
window.DataTable = DataTable;
window.formatNumber = formatNumber;
window.formatDate = formatDate;
window.getRiskClass = getRiskClass;
window.getSeverityLabel = getSeverityLabel;
window.escapeHtml = escapeHtml;
window.truncate = truncate;
