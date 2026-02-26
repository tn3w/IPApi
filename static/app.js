const API_BASE = window.location.origin;
let map = null;
let mapTileLayer = null;
let errorCount = 0;
let feedsConfig = null;

document.addEventListener('DOMContentLoaded', initializeApp);

async function initializeApp() {
    await loadFeedsConfig();
    setupEventListeners();
    checkURLParams();
    setupHistoryNavigation();
    setupThemeWatcher();
}

function setupThemeWatcher() {
    const darkModeQuery = window.matchMedia('(prefers-color-scheme: dark)');
    darkModeQuery.addEventListener('change', () => {
        if (map && mapTileLayer) {
            updateMapTheme();
        }
    });
}

function updateMapTheme() {
    if (!map || !mapTileLayer) return;

    const useDarkMode = window.matchMedia('(prefers-color-scheme: dark)').matches;
    const tileUrl = useDarkMode
        ? 'https://cartodb-basemaps-{s}.global.ssl.fastly.net/dark_all/{z}/{x}/{y}.png'
        : 'https://cartodb-basemaps-{s}.global.ssl.fastly.net/light_all/{z}/{x}/{y}.png';

    map.removeLayer(mapTileLayer);
    mapTileLayer = L.tileLayer(tileUrl, {
        attribution:
            '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> | &copy; <a href="https://carto.com/attributions">CARTO</a>',
        maxZoom: 19,
    }).addTo(map);
}

async function loadFeedsConfig() {
    try {
        const response = await fetch('https://raw.githubusercontent.com/tn3w/IPBlocklist/refs/heads/master/feeds.json');
        feedsConfig = await response.json();
    } catch (error) {
        console.error('Failed to load feeds.json:', error);
        feedsConfig = [];
    }
}

function processFeedsData(data) {
    if (!feedsConfig) return data;

    const hasProxyType = !!data.proxy_type;
    if (hasProxyType) {
        data.proxy_type = mapProxyType(data.proxy_type);
    }

    if (!data.blocklists || data.blocklists.length === 0) {
        if (hasProxyType) {
            data.reputation_score = 0.3;
            data.threat_type = 'anonymizer';
        }
        return data;
    }

    const feedsMap = createFeedsMap();
    const { flags, scores } = processBlocklists(data.blocklists, feedsMap, hasProxyType);

    const reputationScore = calculateReputationScore(scores);
    const threatType = findMaxThreatCategory(scores);

    return { ...data, ...flags, reputation_score: reputationScore, threat_type: threatType };
}

function mapProxyType(code) {
    const types = {
        PUB: 'Public Proxy',
        WEB: 'Web Proxy',
        VPN: 'VPN',
        DCH: 'Data Center/Hosting/Transit',
        SES: 'Search Engine Spider',
        TOR: 'Tor Exit Node',
        RES: 'Residential Proxy',
    };
    return types[code] || code;
}

function createFeedsMap() {
    const map = {};
    feedsConfig.forEach((feed) => (map[feed.name] = feed));
    return map;
}

function processBlocklists(blocklists, feedsMap, hasProxyType) {
    const flags = {};
    const scores = {
        anonymizer: hasProxyType ? [0.3] : [],
        attacks: [],
        botnet: [],
        compromised: [],
        infrastructure: [],
        malware: [],
        spam: [],
    };

    blocklists.forEach((listName) => {
        const feed = feedsMap[listName];
        if (!feed) return;

        if (feed.flags) {
            feed.flags.forEach((flag) => (flags[flag] = true));
        }

        if (feed.provider_name) {
            flags.vpn_provider = feed.provider_name;
        }

        const baseScore = feed.base_score || 0.5;
        if (feed.categories) {
            feed.categories.forEach((category) => {
                if (scores[category]) scores[category].push(baseScore);
            });
        }
    });

    return { flags, scores };
}

function calculateReputationScore(scores) {
    let total = 0.0;

    Object.values(scores).forEach((categoryScores) => {
        if (categoryScores.length === 0) return;

        categoryScores.sort((a, b) => b - a);

        let combined = 1.0;
        categoryScores.forEach((score) => (combined *= 1.0 - score));
        total += 1.0 - combined;
    });

    return Math.min(total / 1.5, 1.0);
}

function findMaxThreatCategory(scores) {
    let maxCategory = null;
    let maxScore = 0;

    Object.entries(scores).forEach(([category, categoryScores]) => {
        if (categoryScores.length === 0) return;

        categoryScores.sort((a, b) => b - a);
        let combined = 1.0;
        categoryScores.forEach((score) => (combined *= 1.0 - score));
        const score = 1.0 - combined;

        if (score > maxScore) {
            maxScore = score;
            maxCategory = category;
        }
    });

    return maxCategory;
}

function setupEventListeners() {
    setupSearchListeners('searchBtn', 'ipInput');
    setupSearchListeners('searchBtnSmall', 'ipInputSmall');
    setupBrandNavigation();
    setupQuickActions();
}

function setupSearchListeners(buttonId, inputId) {
    const button = document.getElementById(buttonId);
    const input = document.getElementById(inputId);

    if (button) button.addEventListener('click', () => performSearch(input.value));
    if (input) {
        input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') performSearch(input.value);
        });
    }
}

function setupBrandNavigation() {
    const navBrand = document.querySelector('.nav-brand');
    if (!navBrand) return;

    navBrand.style.cursor = 'pointer';
    navBrand.addEventListener('click', () => {
        showHero();
        window.history.pushState({ view: 'hero' }, '', window.location.pathname);
    });
}

function setupQuickActions() {
    const myIpBtn = document.getElementById('myIpBtn');
    const exampleBtn = document.getElementById('exampleBtn');
    const luckyBtn = document.getElementById('luckyBtn');

    if (myIpBtn) myIpBtn.addEventListener('click', getMyIP);
    if (exampleBtn) exampleBtn.addEventListener('click', () => performSearch('8.8.8.8'));
    if (luckyBtn) luckyBtn.addEventListener('click', getRandomIP);
}

function checkURLParams() {
    const params = new URLSearchParams(window.location.search);
    const q = params.get('q');
    if (q) performSearch(q);
}

function setupHistoryNavigation() {
    window.addEventListener('popstate', (e) => {
        if (e.state?.q) {
            performSearch(e.state.q, false);
        } else {
            showHero();
        }
    });
}

async function performSearch(query, updateHistory = true) {
    if (!query?.trim()) {
        showNotification('Please enter an IP address or domain');
        return;
    }

    showLoader();

    try {
        const trimmedQuery = query.trim();
        const url = `${API_BASE}/api/${encodeURIComponent(trimmedQuery)}`;
        const response = await fetch(url);
        let data = await response.json();

        if (!response.ok) throw new Error(data.error || 'Lookup failed');

        const searchCount = response.headers.get('x-search-count');
        const serverTimeUs = response.headers.get('x-server-time-us');
        const cacheStatus = response.headers.get('x-cache-status');

        data = processFeedsData(data);

        const isHostname = !isIPAddress(trimmedQuery) && trimmedQuery !== 'me';
        displayResults(
            data,
            searchCount,
            serverTimeUs,
            cacheStatus,
            isHostname ? trimmedQuery : null
        );
        errorCount = 0;

        if (updateHistory) updateBrowserHistory(trimmedQuery);
    } catch (error) {
        errorCount++;
        const suffix = errorCount > 1 ? ` (${errorCount})` : '';
        showNotification(`Error: ${error.message}${suffix}`, 'error');
    } finally {
        hideLoader();
    }
}

function isIPAddress(str) {
    const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6Pattern = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
    return ipv4Pattern.test(str) || ipv6Pattern.test(str);
}

function updateBrowserHistory(query) {
    const url = new URL(window.location);
    url.searchParams.set('q', query);
    history.pushState({ q: query }, '', url);
}

async function getMyIP() {
    showLoader();
    try {
        const url = `${API_BASE}/api/me`;
        const response = await fetch(url);
        let data = await response.json();

        if (!response.ok) throw new Error(data.error || 'Failed to get your IP');

        if (data.ip) performSearch(data.ip);
    } catch (error) {
        showNotification(`Error: ${error.message}`, 'error');
        hideLoader();
    }
}

function getRandomIP() {
    const octets = Array.from({ length: 4 }, () => Math.floor(Math.random() * 256));
    performSearch(octets.join('.'));
}

function displayResults(data, searchCount, serverTimeUs, cacheStatus, originalQuery) {
    showResults();

    const displayIP = data.ipv4 || data.ipv6 || 'N/A';

    updateElement('ipDisplay', (el) => (el.textContent = displayIP));
    updateElement('ipInputSmall', (el) => (el.value = originalQuery || displayIP));

    displayBadges(data);
    displayHostname(data, displayIP);
    displayPerformanceMetrics(searchCount, serverTimeUs, cacheStatus);

    const isPublic = ['public', 'ipv4_mapped'].includes(data.classification);

    if (isPublic) {
        displayPublicIPData(data, displayIP);
    } else {
        showNonPublicMessage(data);
    }
}

function updateElement(id, callback) {
    const element = document.getElementById(id);
    if (element) callback(element);
}

function displayHostname(data, displayIP) {
    const hostname = document.getElementById('hostname');
    if (!hostname) return;

    hostname.textContent = data.hostname || 'No hostname';

    const existingVersions = hostname.parentNode.querySelector('.ip-versions');
    if (existingVersions) existingVersions.remove();

    if (data.ipv4 && data.ipv6) {
        const versionText = data.type === 4 ? `IPv6: ${data.ipv6}` : `IPv4: ${data.ipv4}`;
        const versionDiv = createIPVersionDiv(versionText);
        hostname.parentNode.insertBefore(versionDiv, hostname.nextSibling);
    }
}

function displayPerformanceMetrics(searchCount, serverTimeUs, cacheStatus) {
    const container = document.getElementById('performanceMetrics');
    if (!container) return;

    if (!searchCount || !serverTimeUs) {
        container.style.display = 'none';
        return;
    }

    const count = parseInt(searchCount, 10);
    const timeUs = parseInt(serverTimeUs, 10);
    const timeMs = (timeUs / 1000).toFixed(2);
    const timePerEntryUs = count > 0 ? (timeUs / count).toFixed(2) : '0.00';
    const cacheText = cacheStatus === 'hit' ? ' [cached]' : '';

    container.textContent = `Searched through ${count.toLocaleString()} entries in ${timeMs} ms (${timePerEntryUs} μs/entry)${cacheText}`;
    container.style.display = 'block';
}

function createIPVersionDiv(text) {
    const div = document.createElement('div');
    div.className = 'ip-versions';
    div.style.cssText =
        'font-size:0.9rem;color:var(--text-dim);margin-top:0.5rem;text-align:center';
    div.textContent = text;
    return div;
}

function displayPublicIPData(data, displayIP) {
    const detailsContainer = document.querySelector('.results-details');
    if (!detailsContainer) return;

    detailsContainer.innerHTML = '';

    const locationCard = createDataCard('Location', 'locationDetails');
    const networkCard = createDataCard('Network', 'networkDetails');
    const securityCard = createDataCard('Security', 'securityDetails');

    detailsContainer.appendChild(locationCard);
    detailsContainer.appendChild(networkCard);
    detailsContainer.appendChild(securityCard);

    displayLocation(data);
    displayNetwork(data);
    displaySecurity(data);
    displayFormats(data);

    const hasValidCoords = isValidCoordinate(data.latitude) && isValidCoordinate(data.longitude);
    const mapContainer = document.querySelector('.results-map-container');

    if (!mapContainer) return;

    mapContainer.style.display = 'block';

    if (hasValidCoords) {
        initMap(data.latitude, data.longitude, displayIP);
    } else {
        showNoCoordinatesMessage();
    }
}

function createDataCard(title, contentId) {
    const card = document.createElement('div');
    card.className = 'data-card';

    const iconSvgs = {
        Location:
            '<path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/>',
        Network:
            '<rect x="2" y="7" width="20" height="14" rx="2" ry="2"/><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/>',
        Security:
            '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    };

    card.innerHTML = `
        <div class="card-header">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                ${iconSvgs[title]}
            </svg>
            <h3 class="card-title">${title}</h3>
        </div>
        <div class="card-content" id="${contentId}"></div>
    `;

    return card;
}

function showNoCoordinatesMessage() {
    const mapElement = document.getElementById('map');
    if (!mapElement) return;

    mapElement.innerHTML = '';
    const container = createCenteredContainer();
    const message = document.createElement('p');
    message.style.cssText = 'color:var(--text-dim);line-height:1.6;max-width:400px';
    message.textContent = 'Geographic coordinates are not available for this IP address.';
    container.appendChild(message);
    mapElement.appendChild(container);
}

function createCenteredContainer() {
    const div = document.createElement('div');
    div.style.cssText =
        'height:100%;display:flex;align-items:center;justify-content:center;padding:2rem;text-align:center;background:var(--surface)';
    return div;
}

function displayBadges(data) {
    const container = document.getElementById('ipBadges');
    if (!container) return;

    container.innerHTML = '';

    const version = data.type === 6 ? 'IPv6' : 'IPv4';
    addBadge(container, version, 'primary');

    if (data.is_eu) addBadge(container, 'EU');

    const securityBadges = [
        ['is_vpn', 'VPN'],
        ['is_proxy', 'Proxy'],
        ['is_datacenter', 'Data Center'],
        ['is_tor', 'Tor'],
        ['is_cdn', 'CDN'],
        ['is_cloud', 'Cloud'],
        ['is_anycast', 'Anycast'],
    ];

    securityBadges.forEach(([key, label]) => {
        if (data[key]) addBadge(container, label);
    });

    updateClassification(data.classification);
}

function updateClassification(classification) {
    const element = document.getElementById('classification');
    if (!element || !classification) return;

    const text =
        classification === 'ipv4_mapped'
            ? 'IPv4 mapped'
            : classification.charAt(0).toUpperCase() + classification.slice(1);
    element.textContent = text;
    element.classList.toggle('non-public', classification !== 'public');
}

function addBadge(container, text, className = '') {
    const badge = document.createElement('span');
    badge.className = `badge ${className}`.trim();
    badge.textContent = text;
    container.appendChild(badge);
}

function displayLocation(data) {
    const container = document.getElementById('locationDetails');
    if (!container) return;

    container.innerHTML = '';

    const continentText = formatWithCode(data.continent_name, data.continent_code);
    const countryText = formatWithCode(data.country_name, data.country_code);
    const regionText = formatWithCode(data.region, data.region_code);

    addDataRow(container, 'Continent', continentText);
    addDataRow(container, 'Country', countryText);
    addDataRow(container, 'Region', regionText);
    if (data.is_eu !== undefined) addDataRow(container, 'Is EU', data.is_eu ? 'Yes' : 'No');
    addDataRow(container, 'City', data.city);
    addDataRow(container, 'District', data.district);
    addDataRow(container, 'Postal Code', data.postal_code);

    if (data.timezone) {
        addDataRow(container, 'Timezone', data.timezone);
        addDataRow(container, 'Timezone Abbreviation', data.timezone_abbr);
        if (data.utc_offset !== undefined) addDataRow(container, 'UTC Offset', data.utc_offset);
        addDataRow(container, 'UTC Mark', data.utc_offset_str);
        if (data.dst_active !== undefined)
            addDataRow(container, 'DST Active', data.dst_active ? 'Yes' : 'No');
    }

    addDataRow(container, 'Currency', data.currency);
    if (isValidCoordinate(data.latitude)) addDataRow(container, 'Latitude', data.latitude);
    if (isValidCoordinate(data.longitude)) addDataRow(container, 'Longitude', data.longitude);
}

function formatWithCode(name, code) {
    if (!name) return null;
    return code ? `${name} (${code})` : name;
}

function displayNetwork(data) {
    const container = document.getElementById('networkDetails');
    if (!container) return;

    container.innerHTML = '';

    addDataRow(container, 'ASN', data.asn);
    addDataRow(container, 'AS Name', data.as_name);
    addDataRow(container, 'ISP', data.isp);
    addDataRow(container, 'Domain', data.domain);
    addDataRow(container, 'Prefix', data.cidr);
    addDataRow(container, 'Date Allocated', data.date_allocated);
    addDataRow(container, 'RIR', data.rir);
    addDataRow(container, 'Abuse Contact', data.abuse_contact);
    addDataRow(container, 'RPKI', formatRPKI(data));
    addDataRow(container, 'Anycast', data.is_anycast ? 'Yes' : 'No');
}

function formatRPKI(data) {
    if (!data.rpki_status) return null;

    const formats = {
        valid: `Valid (${data.rpki_roa_count || 0} ROA found)`,
        unknown: 'Unknown',
        invalid_asn: 'Invalid ASN',
        invalid_length: 'Invalid length',
    };

    return formats[data.rpki_status] || data.rpki_status;
}

function displaySecurity(data) {
    const container = document.getElementById('securityDetails');
    if (!container) return;

    container.innerHTML = '';

    const flags = [
        ['is_anycast', 'Anycast'],
        ['is_botnet', 'Botnet'],
        ['is_brute_force', 'Brute Force'],
        ['is_c2_server', 'C2 Server'],
        ['is_cdn', 'CDN'],
        ['is_cloud', 'Cloud'],
        ['is_compromised', 'Compromised'],
        ['is_datacenter', 'Data Center'],
        ['is_forum_spammer', 'Forum Spammer'],
        ['is_isp', 'ISP'],
        ['is_malware', 'Malware'],
        ['is_mobile', 'Mobile'],
        ['is_phishing', 'Phishing'],
        ['is_proxy', 'Proxy'],
        ['is_scanner', 'Scanner'],
        ['is_spammer', 'Spammer'],
        ['is_tor', 'Tor Exit Node'],
        ['is_vpn', 'VPN'],
        ['is_web_attacker', 'Web Attacker'],
    ];

    flags.forEach(([key, label]) => {
        if (data[key] === true) addDataRow(container, label, 'Yes');
    });

    if (data.proxy_type) addDataRow(container, 'Proxy Type', data.proxy_type);

    const provider = data.vpn_provider || data.provider;
    if (provider) addDataRow(container, 'Provider', provider);

    const fraudScore =
        data.reputation_score !== undefined && data.reputation_score !== null
            ? data.reputation_score.toFixed(2)
            : '0.00';
    addDataRow(container, 'Fraud Score', fraudScore);

    const threatType = data.threat_type || 'None';
    addDataRow(container, 'Threat Type', threatType);
}

function displayFormats(data) {
    const container = document.getElementById('formatDetails');
    if (!container) return;

    container.innerHTML = '';

    if (data.type === 4 && data.ipv4) {
        displayIPv4Formats(container, data.ipv4);
    } else if (data.type === 6 && data.ipv6) {
        displayIPv6Formats(container, data.ipv6);
    }
}

function displayIPv4Formats(container, ip) {
    try {
        addDataRow(container, 'Decimal', ipv4ToInt(ip).toString());
        addDataRow(container, 'Hexadecimal', '0x' + ipv4ToHex(ip));
        addDataRow(container, 'Binary', ipv4ToBinary(ip));
        addDataRow(container, 'Dotted Binary', ipv4ToDottedBinary(ip));
        addDataRow(container, 'Dotted Hex', ipv4ToDottedHex(ip));
        addDataRow(container, 'Dotted Octal', ipv4ToDottedOctal(ip));
        addDataRow(container, 'IPv6 Mapped', ipv4ToIPv6Mapped(ip));
    } catch (err) {
        console.error('Error calculating IPv4 formats:', err);
    }
}

function displayIPv6Formats(container, ip) {
    try {
        addDataRow(container, 'Expanded', expandIPv6(ip));
        addDataRow(container, 'Compressed', compressIPv6(ip));
        addDataRow(container, 'Hexadecimal', '0x' + ipv6ToHex(ip));
    } catch (err) {
        console.error('Error calculating IPv6 formats:', err);
    }
}

function ipv4ToInt(ip) {
    return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

function ipv4ToHex(ip) {
    return ipv4ToInt(ip).toString(16).padStart(8, '0');
}

function ipv4ToBinary(ip) {
    return ipv4ToInt(ip).toString(2).padStart(32, '0');
}

function ipv4ToDottedBinary(ip) {
    return ip
        .split('.')
        .map((octet) => parseInt(octet, 10).toString(2).padStart(8, '0'))
        .join('.');
}

function ipv4ToDottedHex(ip) {
    return ip
        .split('.')
        .map((octet) => parseInt(octet, 10).toString(16).padStart(2, '0'))
        .join('.');
}

function ipv4ToDottedOctal(ip) {
    return ip
        .split('.')
        .map((octet) => parseInt(octet, 10).toString(8).padStart(3, '0'))
        .join('.');
}

function ipv4ToIPv6Mapped(ip) {
    const hex = ip
        .split('.')
        .map((octet) => parseInt(octet, 10).toString(16).padStart(2, '0'))
        .join('');
    return `::ffff:${hex.slice(0, 4)}:${hex.slice(4, 8)}`;
}

function expandIPv6(ip) {
    const doubleColonCount = (ip.match(/::/g) || []).length;
    if (doubleColonCount > 1) throw new Error('Invalid IPv6 address');

    if (doubleColonCount === 1) {
        const parts = ip.split('::');
        const left = parts[0] ? parts[0].split(':') : [];
        const right = parts[1] ? parts[1].split(':') : [];
        const missing = 8 - left.length - right.length;
        const middle = Array(missing).fill('0000');
        const expanded = [...left, ...middle, ...right];
        return expanded.map((part) => part.padStart(4, '0')).join(':');
    }
    return ip
        .split(':')
        .map((part) => part.padStart(4, '0'))
        .join(':');
}

function compressIPv6(ip) {
    const expanded = expandIPv6(ip);
    const parts = expanded.split(':');

    const longestRun = findLongestZeroRun(parts);

    if (longestRun.length >= 2) {
        return buildCompressedIPv6(parts, longestRun);
    }

    return parts.map((p) => p.replace(/^0+/, '') || '0').join(':');
}

function findLongestZeroRun(parts) {
    let longestRun = { start: -1, length: 0 };
    let currentRun = { start: -1, length: 0 };

    for (let i = 0; i < parts.length; i++) {
        if (parts[i] === '0000') {
            if (currentRun.length === 0) currentRun.start = i;
            currentRun.length++;
        } else if (currentRun.length > 0) {
            if (currentRun.length > longestRun.length) longestRun = { ...currentRun };
            currentRun = { start: -1, length: 0 };
        }
    }

    if (currentRun.length > longestRun.length) longestRun = { ...currentRun };
    return longestRun;
}

function buildCompressedIPv6(parts, longestRun) {
    const before = parts.slice(0, longestRun.start);
    const after = parts.slice(longestRun.start + longestRun.length);

    const formatPart = (p) => p.replace(/^0+/, '') || '0';

    if (before.length === 0 && after.length === 0) return '::';
    if (before.length === 0) return '::' + after.map(formatPart).join(':');
    if (after.length === 0) return before.map(formatPart).join(':') + '::';
    return before.map(formatPart).join(':') + '::' + after.map(formatPart).join(':');
}

function ipv6ToHex(ip) {
    return expandIPv6(ip).replace(/:/g, '');
}

function isValidCoordinate(coord) {
    if (coord === undefined || coord === null) return false;
    const num = parseFloat(coord);
    return !isNaN(num) && num !== 0;
}

function addDataRow(container, label, value) {
    if (value === undefined || value === null || value === '') return;

    const row = document.createElement('div');
    row.className = 'data-row';

    const labelEl = document.createElement('div');
    labelEl.className = 'data-label';
    labelEl.textContent = label;

    const valueEl = document.createElement('div');
    valueEl.className = 'data-value';
    valueEl.textContent = value;

    row.appendChild(labelEl);
    row.appendChild(valueEl);
    container.appendChild(row);
}

function initMap(lat, lng, ip) {
    const mapContainer = document.getElementById('map');
    if (!mapContainer) return;

    if (map) map.remove();

    const useDarkMode = window.matchMedia('(prefers-color-scheme: dark)').matches;
    const tileUrl = useDarkMode
        ? 'https://cartodb-basemaps-{s}.global.ssl.fastly.net/dark_all/{z}/{x}/{y}.png'
        : 'https://cartodb-basemaps-{s}.global.ssl.fastly.net/light_all/{z}/{x}/{y}.png';

    map = L.map('map').setView([lat, lng], 10);

    mapTileLayer = L.tileLayer(tileUrl, {
        attribution:
            '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> | &copy; <a href="https://carto.com/attributions">CARTO</a>',
        maxZoom: 19,
    }).addTo(map);

    const customIcon = L.divIcon({
        className: 'custom-marker',
        html: `<svg width="32" height="32" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z" fill="var(--primary)" stroke="var(--primary-dark)" stroke-width="2"/>
            <circle cx="12" cy="10" r="3" fill="white"/>
        </svg>`,
        iconSize: [32, 32],
        iconAnchor: [16, 32],
        popupAnchor: [0, -32],
    });

    L.marker([lat, lng], { icon: customIcon })
        .addTo(map)
        .bindPopup(`<b>${ip}</b><br>Lat: ${lat}<br>Lng: ${lng}`)
        .openPopup();
}

function showHero() {
    toggleView('hero', 'flex', 'results', 'none');
}

function showResults() {
    toggleView('results', 'block', 'hero', 'none');
}

function toggleView(showId, showDisplay, hideId, hideDisplay) {
    const showEl = document.getElementById(showId);
    const hideEl = document.getElementById(hideId);

    if (showEl) {
        showEl.classList.remove('hidden');
        showEl.style.display = showDisplay;
    }
    if (hideEl) {
        hideEl.classList.add('hidden');
        hideEl.style.display = hideDisplay;
    }
}

function showLoader() {
    const loader = document.getElementById('loader');
    if (loader) loader.classList.remove('hidden');
}

function hideLoader() {
    const loader = document.getElementById('loader');
    if (loader) loader.classList.add('hidden');
}

function showNonPublicMessage(data) {
    const mapContainer = document.querySelector('.results-map-container');
    if (mapContainer) {
        mapContainer.style.display = 'block';
        showNoCoordinatesMessage();
    }

    const detailsContainer = document.querySelector('.results-details');
    if (!detailsContainer) return;

    detailsContainer.innerHTML = '';

    const messageCard = createNonPublicCard(data.classification);
    detailsContainer.appendChild(messageCard);

    const formatsContainer = document.getElementById('formatDetails');
    if (formatsContainer) displayFormats(data);
}

function createNonPublicCard(classification) {
    const card = document.createElement('div');
    card.className = 'data-card';
    card.style.cssText = 'text-align:center;padding:3rem 2rem';

    const svg = createLocationSVG();
    const heading = createHeading('No Public IP Information');
    const messageText = `Location, network, and security data are not available for ${classification} IP addresses.`;
    const message = createMessage(messageText);

    card.appendChild(svg);
    card.appendChild(heading);
    card.appendChild(message);

    return card;
}

function createLocationSVG() {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('width', '64');
    svg.setAttribute('height', '64');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '1.5');
    svg.style.cssText = 'margin:0 auto 1.5rem;color:var(--primary);opacity:0.8';

    const path1 = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path1.setAttribute('d', 'M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z');

    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', '12');
    circle.setAttribute('cy', '10');
    circle.setAttribute('r', '3');

    svg.appendChild(path1);
    svg.appendChild(circle);

    return svg;
}

function createHeading(text) {
    const h3 = document.createElement('h3');
    h3.style.cssText = 'margin-bottom:1rem;font-size:1.25rem;font-weight:600';
    h3.textContent = text;
    return h3;
}

function createMessage(text) {
    const p = document.createElement('p');
    p.style.cssText = 'color:var(--text-dim);line-height:1.6';
    p.textContent = text;
    return p;
}

function showNotification(message, type = 'info') {
    const notification = document.getElementById('notification');
    if (!notification) return;

    notification.textContent = message;
    notification.classList.remove('hidden');

    setTimeout(() => notification.classList.add('hidden'), 4000);
}
