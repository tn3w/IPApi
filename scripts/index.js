document.addEventListener('DOMContentLoaded', () => {
    const EXAMPLE_IPS = [
        '8.8.8.8',
        '8.8.4.4',
        '1.1.1.1',
        '9.9.9.9',
        '208.67.222.222',
        '4.2.2.1',
        '4.2.2.2',
        '2001:4860:4860::8888',
        '2606:4700:4700::1111',
        '2620:fe::fe',
        '2001:4860:4860::8844',
        '2620:119:35::35',
    ];

    const elements = {
        search: {
            form: document.getElementById('search-form'),
            input: document.getElementById('search-input'),
            button: document.getElementById('search-button'),
            myIpButton: document.getElementById('my-ip'),
            tryExampleButton: document.getElementById('try-example'),
            feelingLuckyButton: document.getElementById('feeling-lucky'),
        },
        results: {
            view: document.getElementById('results-view'),
            input: document.getElementById('results-search-input'),
            button: document.getElementById('results-search-button'),
            closeButton: document.getElementById('close-results'),
            loading: document.querySelector('.results-loading'),
            data: document.querySelector('.results-data'),
            locationSection: document.getElementById('location-section'),
            networkSection: document.getElementById('network-section'),
            locationGrid: document.getElementById('location-grid'),
            networkGrid: document.getElementById('network-grid'),
            error: document.getElementById('results-error'),
            errorMessage: document.getElementById('error-message'),
        },
        toggle: {
            button: document.getElementById('theme-toggle'),
            lightIcon: document.querySelector('.theme-icon-light'),
            darkIcon: document.querySelector('.theme-icon-dark'),
            text: document.querySelector('.theme-toggle-text'),
        },
        hero: document.querySelector('.hero'),
        notification: document.getElementById('notification-container'),
    };

    const apiBaseUrl = 'BASE_URL';

    let map = null;
    let marker = null;
    let currentQuery = null;
    let activeNotification = null;
    let notificationTimeout = null;
    let lastErrorMessage = '';
    let errorCounter = 1;

    let sectionItemCounts = {
        location: 0,
        network: 0,
    };

    const actionButtons = document.querySelectorAll('.action-buttons a');
    actionButtons.forEach((button) => {
        button.dataset.href = button.getAttribute('href');
        button.removeAttribute('href');
    });

    const toggleTheme = () => {
        const savedTheme = localStorage.getItem('theme');
        const prefersDarkMode = window.matchMedia('(prefers-color-scheme: dark)').matches;

        if (
            !savedTheme ||
            (savedTheme === 'dark' && prefersDarkMode) ||
            (savedTheme === 'light' && !prefersDarkMode)
        ) {
            localStorage.setItem('theme', prefersDarkMode ? 'light' : 'dark');
        } else {
            localStorage.setItem('theme', savedTheme === 'dark' ? 'light' : 'dark');
        }

        updateSiteTheme();
    };

    const updateSiteTheme = () => {
        const savedTheme = localStorage.getItem('theme');
        const prefersDarkMode = window.matchMedia('(prefers-color-scheme: dark)').matches;
        const useDarkMode = savedTheme === 'dark' || (savedTheme !== 'light' && prefersDarkMode);

        const htmlElement = document.documentElement;
        htmlElement.classList.remove('light-theme', 'dark-theme');

        if (savedTheme) {
            htmlElement.classList.add(useDarkMode ? 'dark-theme' : 'light-theme');
        }

        if (elements.toggle) {
            elements.toggle.lightIcon.style.display = useDarkMode ? 'block' : 'none';
            elements.toggle.darkIcon.style.display = useDarkMode ? 'none' : 'block';
            elements.toggle.text.textContent = useDarkMode ? 'Switch to Light' : 'Switch to Dark';
        }

        if (map && typeof L !== 'undefined') {
            map.eachLayer((layer) => {
                if (layer instanceof L.TileLayer) {
                    map.removeLayer(layer);
                }
            });

            const tileUrl = useDarkMode
                ? 'https://cartodb-basemaps-{s}.global.ssl.fastly.net/dark_all/{z}/{x}/{y}.png'
                : 'https://cartodb-basemaps-{s}.global.ssl.fastly.net/light_all/{z}/{x}/{y}.png';

            L.tileLayer(tileUrl, {
                attribution:
                    '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors' +
                    ' | &copy; <a href="https://carto.com/attributions">CARTO</a>',
                maxZoom: 19,
            }).addTo(map);

            if (marker) {
                marker.openPopup();
            }
        }
    };

    if (elements.toggle.button) {
        elements.toggle.button.addEventListener('click', toggleTheme);
    }

    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', updateSiteTheme);

    const updateSearchButtonVisibility = () => {
        const isEmpty = elements.search.input.value.trim() === '';
        elements.search.button.classList.toggle('visible', !isEmpty);
        elements.search.button.classList.toggle('hidden', isEmpty);
    };

    const setupSearchEvents = () => {
        updateSearchButtonVisibility();

        ['input', 'change', 'autocomplete'].forEach((event) => {
            elements.search.input.addEventListener(event, updateSearchButtonVisibility);
        });

        elements.search.input.addEventListener('animationstart', (e) => {
            if (e.animationName.indexOf('autofill') !== -1) updateSearchButtonVisibility();
        });

        elements.search.form.addEventListener('submit', (e) => {
            e.preventDefault();
        });

        elements.search.button.addEventListener('click', () => {
            const query = elements.search.input.value.trim();
            if (query) fetchIPData(query);
        });

        elements.search.input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && e.target.value.trim()) {
                fetchIPData(e.target.value.trim());
            }
        });

        elements.results.button.addEventListener('click', () => {
            const query = elements.results.input.value.trim();
            if (query) {
                elements.search.input.value = query;
                showLoading();
                fetchIPData(query);
                window.history.pushState(
                    { view: 'results', query: query },
                    '',
                    `?ip=${encodeURIComponent(query)}`
                );
            }
        });

        elements.results.input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && e.target.value.trim()) {
                const query = e.target.value.trim();
                elements.search.input.value = query;
                showLoading();
                fetchIPData(query);
                window.history.pushState(
                    { view: 'results', query: query },
                    '',
                    `?ip=${encodeURIComponent(query)}`
                );
            }
        });
    };

    const setupHelperButtons = () => {
        elements.search.myIpButton.addEventListener('click', async (e) => {
            e.preventDefault();

            const originalText = elements.search.myIpButton.textContent;
            elements.search.myIpButton.innerHTML = '<span class="spinner"></span> Loading...';
            elements.search.myIpButton.disabled = true;

            try {
                let isLocalhost =
                    window.location.hostname === 'localhost' ||
                    window.location.hostname === '127.0.0.1' ||
                    window.location.hostname === '::1';

                let ipAddress = '';
                if (isLocalhost) {
                    let ipifyResponse = await fetch('https://api4.ipify.org');

                    if (!ipifyResponse.ok) {
                        ipifyResponse = await fetch('https://api6.ipify.org');

                        if (!ipifyResponse.ok) {
                            throw new Error('Failed to fetch IP address from ipify');
                        }

                        ipAddress = await ipifyResponse.text();
                    } else {
                        ipAddress = await ipifyResponse.text();
                    }
                } else {
                    let ipAddressResponse = await fetch(`${apiBaseUrl}self?fields=ip_address`);
                    if (!ipAddressResponse.ok) {
                        throw new Error('Failed to fetch IP address.');
                    }

                    let ipAddressData = await ipAddressResponse.json();
                    ipAddress = ipAddressData.ip_address;
                }

                if (ipAddress && ipAddress.trim() !== '') {
                    elements.search.input.value = ipAddress;
                    updateSearchButtonVisibility();
                } else {
                    throw new Error('Could not fetch your IP address from ipify');
                }
            } catch (error) {
                showNotification(
                    'Error',
                    'Error fetching your IP address: ' + error.message + '. Please try again.'
                );
                console.error('Error fetching IP:', error);
            } finally {
                elements.search.myIpButton.innerHTML = originalText;
                elements.search.myIpButton.disabled = false;
            }
        });

        elements.search.tryExampleButton.addEventListener('click', (e) => {
            e.preventDefault();
            elements.search.input.value =
                EXAMPLE_IPS[Math.floor(Math.random() * EXAMPLE_IPS.length)];
            updateSearchButtonVisibility();
        });

        elements.search.feelingLuckyButton.addEventListener('click', (e) => {
            e.preventDefault();
            elements.search.input.value = generateRandomIPv4();
            updateSearchButtonVisibility();
        });
    };

    const showLoading = () => {
        elements.results.loading.classList.add('active');
        elements.results.data.classList.remove('active');
    };

    const hideLoading = () => {
        elements.results.loading.classList.remove('active');
    };

    const showNotification = (title, message, duration = 5000) => {
        if (message === lastErrorMessage) {
            errorCounter++;

            if (activeNotification) {
                const counterElement = activeNotification.querySelector('.notification-counter');
                if (counterElement) {
                    counterElement.textContent = `x${errorCounter}`;
                } else {
                    const titleElement = activeNotification.querySelector('.notification-title');
                    const counter = document.createElement('span');
                    counter.className = 'notification-counter';
                    counter.textContent = `x${errorCounter}`;
                    titleElement.appendChild(counter);
                }

                const progressBar = activeNotification.querySelector('.notification-progress');
                if (progressBar) {
                    progressBar.style.transition = 'none';
                    progressBar.style.width = '100%';
                    setTimeout(() => {
                        progressBar.style.transition = `width ${duration}ms linear`;
                        progressBar.style.width = '0';
                    }, 50);
                }

                if (notificationTimeout) clearTimeout(notificationTimeout);
                notificationTimeout = setTimeout(hideNotification, duration);

                return;
            }
        } else {
            lastErrorMessage = message;
            errorCounter = 1;
        }

        if (activeNotification) hideNotification();

        const notification = document.createElement('div');
        notification.className = 'notification';

        notification.innerHTML = `
            <div class="notification-header">
                <div class="notification-title">
                    <span>${title}</span>
                    ${errorCounter > 1 ? `<span class="notification-counter">x${errorCounter}</span>` : ''}
                </div>
                <button class="notification-close" aria-label="Close notification">&times;</button>
            </div>
            <div class="notification-message">${message}</div>
            <div class="notification-progress"></div>
        `;

        elements.notification.appendChild(notification);
        notification.offsetHeight;
        notification.classList.add('show');

        const progressBar = notification.querySelector('.notification-progress');
        progressBar.style.width = '100%';
        setTimeout(() => {
            progressBar.style.transition = `width ${duration}ms linear`;
            progressBar.style.width = '0';
        }, 50);

        const closeButton = notification.querySelector('.notification-close');
        closeButton.addEventListener('click', hideNotification);

        notificationTimeout = setTimeout(hideNotification, duration);
        activeNotification = notification;
    };

    const hideNotification = () => {
        if (activeNotification) {
            activeNotification.classList.remove('show');

            setTimeout(() => {
                if (activeNotification && activeNotification.parentNode) {
                    activeNotification.parentNode.removeChild(activeNotification);
                }
                activeNotification = null;
            }, 300);

            if (notificationTimeout) {
                clearTimeout(notificationTimeout);
                notificationTimeout = null;
            }
        }
    };

    const transitionToResultsView = (ipData) => {
        elements.results.input.value = elements.search.input.value;

        if (ipData) {
            prePopulateResultsData(ipData);
            document.title = ipData.ip_address + ' | IPApi';
        }

        document.body.classList.add('results-active');
        elements.results.view.style.display = 'block';
        elements.results.view.style.opacity = '0';

        const featuresSection = document.querySelector('.features-section');
        const useCasesSection = document.querySelector('.use-cases-section');
        const apiDocsSection = document.querySelector('.api-docs-section');
        const ctaSection = document.querySelector('.cta-section');

        featuresSection.style.display = 'none';
        useCasesSection.style.display = 'none';
        apiDocsSection.style.display = 'none';
        ctaSection.style.display = 'none';

        elements.hero.classList.add('fade-out');

        setTimeout(() => {
            elements.hero.classList.add('hidden');
            elements.hero.style.display = 'none';

            elements.results.view.style.opacity = '';
            elements.results.view.classList.add('active');
            elements.results.view.classList.add('fade-in');

            if (ipData) displayIPData(ipData);

            window.history.pushState(
                { view: 'results', query: currentQuery },
                '',
                `?ip=${encodeURIComponent(currentQuery)}`
            );
        }, 400);
    };

    const transitionToHeroView = () => {
        document.title = 'IPApi - IP Address Information';

        document.body.classList.remove('results-active');
        elements.results.view.style.display = 'block';
        elements.results.view.classList.remove('fade-in');
        elements.results.view.classList.add('fade-out');
        elements.hero.style.display = 'none';
        elements.hero.classList.remove('fade-out');

        setTimeout(() => {
            elements.results.view.classList.remove('active');
            elements.results.view.classList.remove('fade-out');
            elements.results.view.style.display = 'none';

            const featuresSection = document.querySelector('.features-section');
            const useCasesSection = document.querySelector('.use-cases-section');
            const apiDocsSection = document.querySelector('.api-docs-section');
            const ctaSection = document.querySelector('.cta-section');

            featuresSection.style.display = 'block';
            useCasesSection.style.display = 'block';
            apiDocsSection.style.display = 'block';
            ctaSection.style.display = 'block';

            elements.hero.classList.remove('hidden');
            elements.hero.style.display = 'flex';
            void elements.hero.offsetWidth;
            elements.hero.classList.add('fade-in');

            window.history.pushState({ view: 'hero' }, '', window.location.pathname);

            setTimeout(() => {
                elements.hero.classList.remove('fade-in');
            }, 400);
        }, 400);
    };

    const fetchIPData = async (ip) => {
        currentQuery = ip;

        const isResultsView = elements.results.view.classList.contains('active');
        if (isResultsView) {
            showLoading();
        } else {
            const loadingSpinner = document.createElement('div');
            loadingSpinner.className = 'hero-loading-spinner';
            loadingSpinner.innerHTML = '<div class="spinner"></div><p>Loading IP data...</p>';

            elements.hero.style.position = 'relative';
            elements.hero.appendChild(loadingSpinner);
        }

        try {
            const response = await fetch(`${apiBaseUrl}${encodeURIComponent(ip)}?fields=all`);
            if (!response.ok) {
                throw new Error(
                    response.headers.get('X-Error') || 'HTTP error! status: ' + response.status
                );
            }
            const data = await response.json();
            if (ip !== currentQuery) return;

            window.ipDataCache = data;

            if (isResultsView) {
                displayIPData(data);
            } else {
                const loadingSpinner = elements.hero.querySelector('.hero-loading-spinner');
                if (loadingSpinner) elements.hero.removeChild(loadingSpinner);
                transitionToResultsView(data);
            }
        } catch (error) {
            if (ip !== currentQuery) return;

            if (isResultsView) {
                hideLoading();
                transitionToHeroView();
            } else {
                const loadingSpinner = elements.hero.querySelector('.hero-loading-spinner');
                if (loadingSpinner) elements.hero.removeChild(loadingSpinner);
            }

            showNotification('Error', error.message + '. Please try again.');
            console.error('Error fetching IP data:', error);
        }
    };

    const isValidValue = (value) => {
        return (
            value !== null &&
            value !== undefined &&
            (typeof value !== 'string' ||
                (value.toLowerCase() !== 'none' && value.toLowerCase() !== 'null' && value !== ''))
        );
    };

    const prePopulateResultsData = (ipData) => {
        const ipTypeEl = document.getElementById('result-ip-type');
        const ipEl = document.getElementById('result-ip');
        const hostnameEl = document.getElementById('result-hostname');

        if (ipTypeEl) ipTypeEl.textContent = ipData.version === 6 ? 'IPV6' : 'IPV4';

        if (ipEl) {
            ipEl.textContent = ipData.ip_address || '';
            ipEl.classList.toggle('long-ip', ipData.ip_address && ipData.ip_address.length > 20);
        }

        if (hostnameEl)
            hostnameEl.textContent = isValidValue(ipData.hostname)
                ? ipData.hostname
                : 'No hostname available';
    };

    const initializeMap = (lat, lon, ipAddress) => {
        if (
            !isValidValue(lat) ||
            !isValidValue(lon) ||
            isNaN(parseFloat(lat)) ||
            isNaN(parseFloat(lon))
        ) {
            if (map) {
                map.remove();
                map = null;
                marker = null;
            }

            document.getElementById('ip-map').innerHTML = `
                <div style="
                    height: 100%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 1rem;
                    text-align: center;
                ">
                    Location coordinates not available for this IP address.
                </div>
            `;
            return;
        }

        try {
            lat = parseFloat(lat);
            lon = parseFloat(lon);

            if (lat < -90 || lat > 90 || lon < -180 || lon > 180 || (lat === 0 && lon === 0)) {
                if (map) {
                    map.remove();
                    map = null;
                    marker = null;
                }

                document.getElementById('ip-map').innerHTML = `
                    <div style="
                        height: 100%;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        padding: 1rem;
                        text-align: center;
                    ">
                        Invalid location coordinates for this IP address.
                    </div>
                `;
                return;
            }

            if (map) {
                map.remove();
                map = null;
                marker = null;
            }

            const mapContainer = document.getElementById('ip-map');
            mapContainer.innerHTML = '';

            if (!window.L) {
                const linkElement = document.createElement('link');
                linkElement.rel = 'stylesheet';
                linkElement.href = 'https://cdn.jsdelivr.net/npm/leaflet@1.9.4/dist/leaflet.css';
                document.head.appendChild(linkElement);

                const scriptElement = document.createElement('script');
                scriptElement.src = 'https://cdn.jsdelivr.net/npm/leaflet@1.9.4/dist/leaflet.js';
                document.head.appendChild(scriptElement);

                scriptElement.onload = () => createMap(lat, lon, ipAddress);
            } else {
                createMap(lat, lon, ipAddress);
            }
        } catch (error) {
            console.error('Error initializing map:', error);
            document.getElementById('ip-map').innerHTML = document.getElementById(
                'ip-map'
            ).innerHTML = `
                <div style="
                    height: 100%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 1rem;
                    text-align: center;
                ">
                    Error initializing map.
                </div>
            `;
        }
    };

    const createCustomMarker = (color) => {
        const markerColor =
            color ||
            getComputedStyle(document.documentElement).getPropertyValue('--primary').trim();

        return L.divIcon({
            className: 'custom-map-marker',
            html: `<svg width="36" height="48" viewBox="0 0 36 48" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M18 0C8.064 0 0 8.064 0 18C0 31.5 18 48 18 48C18 48 36 31.5 36 18C36 8.064 27.936 0 18 0ZM18 24.3C14.5 24.3 11.7 21.5 11.7 18C11.7 14.5 14.5 11.7 18 11.7C21.5 11.7 24.3 14.5 24.3 18C24.3 21.5 21.5 24.3 18 24.3Z" fill="${markerColor}"/>
                  </svg>`,
            iconSize: [36, 48],
            iconAnchor: [18, 48],
            popupAnchor: [0, -48],
        });
    };

    const createMap = (lat, lon, ipAddress) => {
        const mapContainer = document.getElementById('ip-map');
        const prefersDarkMode = window.matchMedia('(prefers-color-scheme: dark)').matches;

        const savedTheme = localStorage.getItem('theme');
        const useDarkMode = savedTheme === 'dark' || (savedTheme !== 'light' && prefersDarkMode);

        const htmlElement = document.documentElement;
        const hasDarkClass = htmlElement.classList.contains('dark-theme');
        const finalUseDarkMode =
            (savedTheme && hasDarkClass) || (!savedTheme && prefersDarkMode) || useDarkMode;

        mapContainer.innerHTML = '';

        try {
            if (map) {
                map.remove();
                map = null;
                marker = null;
            }

            map = L.map(mapContainer).setView([lat, lon], 10);

            const tileUrl = finalUseDarkMode
                ? 'https://cartodb-basemaps-{s}.global.ssl.fastly.net/dark_all/{z}/{x}/{y}.png'
                : 'https://cartodb-basemaps-{s}.global.ssl.fastly.net/light_all/{z}/{x}/{y}.png';

            const tileLayer = L.tileLayer(tileUrl, {
                attribution:
                    '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors' +
                    ' | &copy; <a href="https://carto.com/attributions">CARTO</a>',
                maxZoom: 19,
            }).addTo(map);

            const customIcon = createCustomMarker();

            marker = L.marker([lat, lon], { icon: customIcon })
                .addTo(map)
                .bindPopup(
                    '<div style="text-align:center;"><strong>IP: ' +
                        ipAddress +
                        '</strong><br>Lat: ' +
                        lat +
                        '<br>Lon: ' +
                        lon +
                        '</div>'
                )
                .openPopup();

            setTimeout(() => {
                map.invalidateSize();
                map.setView([lat, lon], 10);
            }, 100);
        } catch (error) {
            console.error('Error creating map:', error);
            mapContainer.innerHTML = `
                <div style="
                    height: 100%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 1rem;
                    text-align: center;
                ">
                    Error creating map: ${error.message}
                </div>
            `;
        }
    };

    const displayIPData = (data) => {
        hideLoading();

        const resultsDataContainer = document.querySelector('.results-data');
        if (resultsDataContainer) resultsDataContainer.classList.add('active');

        document.title = data.ip_address + ' | IPApi';

        const ipTypeEl = document.getElementById('result-ip-type');
        const ipEl = document.getElementById('result-ip');
        const hostnameEl = document.getElementById('result-hostname');
        const classificationEl = document.getElementById('result-classification');
        const vpnBadgeEl = document.getElementById('vpn-badge');
        const proxyBadgeEl = document.getElementById('proxy-badge');
        const dataCenterBadgeEl = document.getElementById('data-center-badge');
        const forumSpammerBadgeEl = document.getElementById('forum-spammer-badge');
        const fireholLevel1BadgeEl = document.getElementById('firehol-level1-badge');
        const torBadgeEl = document.getElementById('tor-badge');
        const anycastBadgeEl = document.getElementById('anycast-badge');
        const mapContainer = document.querySelector('.results-map-container');

        if (ipTypeEl) ipTypeEl.textContent = data.version === 6 ? 'IPV6' : 'IPV4';

        if (ipEl) {
            ipEl.textContent = data.ip_address || '';
            ipEl.classList.toggle('long-ip', data.ip_address && data.ip_address.length > 20);

            const ipvxContainer = document.querySelector('.ipvx-mapping');
            const hasIpv4 =
                isValidValue(data.ipv4_address) && data.ipv4_address !== data.ip_address;
            const hasIpv6 =
                isValidValue(data.ipv6_address) && data.ipv6_address !== data.ip_address;

            if (hasIpv4 || hasIpv6) {
                if (!ipvxContainer) {
                    const container = document.createElement('div');
                    container.className = 'ipvx-mapping';
                    ipEl.parentNode.insertBefore(container, ipEl.nextSibling);
                }

                const container = ipvxContainer || document.querySelector('.ipvx-mapping');
                container.innerHTML = '';
                container.style.display = 'block';

                if (hasIpv4) {
                    const ipv4Text = document.createTextNode('IPv4: ' + data.ipv4_address);
                    container.appendChild(ipv4Text);
                }

                if (hasIpv4 && hasIpv6) {
                    container.appendChild(document.createElement('br'));
                }

                if (hasIpv6) {
                    const ipv6Text = document.createTextNode('IPv6: ' + data.ipv6_address);
                    container.appendChild(ipv6Text);
                }
            } else if (ipvxContainer) {
                ipvxContainer.style.display = 'none';
            }
        }

        const isPublic = ['public', 'ipv4_mapped'].includes(data.classification || 'unknown');
        if (classificationEl) {
            const classification = data.classification || 'unknown';
            classificationEl.textContent =
                classification === 'ipv4_mapped'
                    ? 'IPv4 Mapped'
                    : classification.charAt(0).toUpperCase() + classification.slice(1);
            classificationEl.classList.toggle('non-public', !isPublic);
        }

        if (mapContainer) {
            mapContainer.style.display = isPublic ? 'block' : 'none';
        }

        if (vpnBadgeEl) vpnBadgeEl.style.display = data.is_vpn === true ? 'inline-flex' : 'none';
        if (proxyBadgeEl)
            proxyBadgeEl.style.display = data.is_proxy === true ? 'inline-flex' : 'none';
        if (dataCenterBadgeEl)
            dataCenterBadgeEl.style.display = data.is_datacenter === true ? 'inline-flex' : 'none';
        if (forumSpammerBadgeEl)
            forumSpammerBadgeEl.style.display =
                data.is_forum_spammer === true ? 'inline-flex' : 'none';
        if (fireholLevel1BadgeEl)
            fireholLevel1BadgeEl.style.display = data.is_firehol === true ? 'inline-flex' : 'none';
        if (torBadgeEl)
            torBadgeEl.style.display = data.is_tor_exit_node === true ? 'inline-flex' : 'none';
        if (anycastBadgeEl)
            anycastBadgeEl.style.display = data.is_anycast === true ? 'inline-flex' : 'none';

        if (hostnameEl)
            hostnameEl.textContent = isValidValue(data.hostname)
                ? data.hostname
                : 'No hostname available';

        updateIPFormats(data);

        sectionItemCounts.location = 0;
        sectionItemCounts.network = 0;

        if (elements.results.locationSection)
            elements.results.locationSection.style.display = 'none';
        if (elements.results.networkSection) elements.results.networkSection.style.display = 'none';

        const hasLocationData =
            isPublic && (isValidValue(data.latitude) || isValidValue(data.country));
        const hasNetworkData = isPublic && (isValidValue(data.asn) || isValidValue(data.as_name));

        if (elements.results.error && elements.results.errorMessage) {
            if (!isPublic) {
                let message = '';
                switch (data.classification) {
                    case 'private':
                        message =
                            'This is a private IP address, used in local networks. No public ip info is available.';
                        break;
                    case 'loopback':
                        message =
                            'This is a loopback address that points to your local machine. No ip info is available.';
                        break;
                    case 'multicast':
                        message = 'This is a multicast address. No ip info is available.';
                        break;
                    case 'reserved':
                        message =
                            'This is a reserved IP address for special use. No ip info is available.';
                        break;
                    case 'link_local':
                        message =
                            'This is a link-local address for communication within the local network segment. No ip info is available.';
                        break;
                    default:
                        message = `This is a ${data.classification || 'special'} IP address. No ip info is available.`;
                }
                elements.results.errorMessage.textContent = message;
                elements.results.error.style.display = 'flex';

                if (elements.results.locationSection)
                    elements.results.locationSection.style.display = 'none';
                if (elements.results.networkSection)
                    elements.results.networkSection.style.display = 'none';

                const abuseSection = document.querySelector('.results-section:last-child');
                if (abuseSection) abuseSection.style.display = 'none';
            } else if (!hasLocationData && !hasNetworkData) {
                elements.results.errorMessage.textContent =
                    'No location or network data available for this IP address.';
                elements.results.error.style.display = 'flex';
            } else {
                elements.results.error.style.display = 'none';
            }
        }

        const locationGrid = document.getElementById('location-grid');
        if (locationGrid && isPublic) {
            locationGrid.innerHTML = '';

            const locationFields = [
                { key: 'continent', label: 'Continent' },
                { key: 'country', label: 'Country' },
                { key: 'region', label: 'Region' },
                { key: 'is_eu', label: 'Is EU' },
                { key: 'city', label: 'City' },
                { key: 'district', label: 'District' },
                { key: 'postal_code', label: 'Postal Code' },
                { key: 'timezone_name', label: 'Timezone' },
                { key: 'currency', label: 'Currency' },
                { key: 'latitude', label: 'Latitude' },
                { key: 'longitude', label: 'Longitude' },
            ];

            locationFields.forEach((field) => {
                if (isValidValue(data[field.key])) {
                    let displayValue = data[field.key];

                    if (field.key === 'continent' && isValidValue(data.continent_code)) {
                        displayValue = data.continent + ' (' + data.continent_code + ')';
                    } else if (field.key === 'country' && isValidValue(data.country_code)) {
                        displayValue = data.country + ' (' + data.country_code + ')';
                    } else if (field.key === 'region' && isValidValue(data.region_code)) {
                        displayValue = data.region + ' (' + data.region_code + ')';
                    } else if (field.key === 'is_eu') {
                        displayValue = data.is_eu ? 'Yes' : 'No';
                    }

                    addResultItem(locationGrid, field.label, displayValue);

                    if (field.key === 'timezone_name' && isValidValue(data.utc_offset_str)) {
                        if (isValidValue(data.timezone_abbreviation)) {
                            addResultItem(
                                locationGrid,
                                'Timezone Abbreviation',
                                data.timezone_abbreviation
                            );
                        }

                        addResultItem(locationGrid, 'UTC Offset', data.utc_offset);
                        addResultItem(locationGrid, 'UTC Mark', data.utc_offset_str);

                        if (isValidValue(data.dst_active)) {
                            addResultItem(
                                locationGrid,
                                'DST Active',
                                data.dst_active ? 'Yes' : 'No'
                            );
                        }
                    }
                }
            });
        }

        const networkGrid = document.getElementById('network-grid');
        if (networkGrid && isPublic) {
            networkGrid.innerHTML = '';

            const showOrgName = data.as_name !== data.org;
            const showNet = data.net !== data.org && !showOrgName;

            const networkFields = [
                { key: 'asn', label: 'ASN' },
                { key: 'as_name', label: 'AS Name' },
                ...(showOrgName ? [{ key: 'org', label: 'Organization' }] : []),
                ...(showNet ? [{ key: 'net', label: 'Network' }] : []),
                { key: 'isp', label: 'ISP' },
                ...(data.domain !== data.hostname ? [{ key: 'domain', label: 'Domain' }] : []),
                { key: 'prefix', label: 'Prefix' },
                { key: 'date_allocated', label: 'Date Allocated' },
                { key: 'rir', label: 'RIR' },
                { key: 'abuse_contact', label: 'Abuse Contact' },
                {
                    key: 'rpki_status',
                    label: 'RPKI',
                    format: (data) => {
                        if (!isValidValue(data.rpki_status)) return null;

                        switch (data.rpki_status) {
                            case 'valid':
                                return 'Valid (' + data.rpki_roa_count + ' ROA found)';
                            case 'unknown':
                                return 'Unknown';
                            case 'invalid_asn':
                                return 'Invalid ASN';
                            case 'invalid_length':
                                return 'Invalid length';
                            default:
                                return data.rpki;
                        }
                    },
                },
                {
                    key: 'is_anycast',
                    label: 'Anycast',
                    format: (data) => {
                        return data.is_anycast === true ? 'Yes' : 'No';
                    },
                },
            ];

            networkFields.forEach((field) => {
                if (field.format) {
                    const value = field.format(data);
                    if (value) {
                        addResultItem(networkGrid, field.label, value);
                    }
                } else if (isValidValue(data[field.key])) {
                    addResultItem(networkGrid, field.label, data[field.key]);
                }
            });
        }

        if (elements.results.locationSection) {
            elements.results.locationSection.style.display =
                sectionItemCounts.location > 0 ? 'block' : 'none';
        }

        if (elements.results.networkSection) {
            elements.results.networkSection.style.display =
                sectionItemCounts.network > 0 ? 'block' : 'none';
        }

        const abuseGrid = document.getElementById('abuse-grid');
        const abuseSection = abuseGrid ? abuseGrid.closest('.results-section') : null;

        const shouldShowAbuseSection =
            sectionItemCounts.location > 0 || sectionItemCounts.network > 0;

        if (abuseSection) {
            abuseSection.style.display = shouldShowAbuseSection ? 'block' : 'none';
        }

        if (abuseGrid && shouldShowAbuseSection) {
            abuseGrid.innerHTML = '';

            let vpnDisplay = 'No';
            if (data.is_vpn === true) {
                vpnDisplay = isValidValue(data.vpn_provider)
                    ? 'Yes (' + data.vpn_provider + ')'
                    : 'Yes';
            }
            addResultItem(abuseGrid, 'VPN', vpnDisplay);

            addResultItem(abuseGrid, 'Proxy', data.is_proxy === true ? 'Yes' : 'No');
            addResultItem(abuseGrid, 'Data Center', data.is_datacenter === true ? 'Yes' : 'No');
            addResultItem(
                abuseGrid,
                'Forum Spammer',
                data.is_forum_spammer === true ? 'Yes' : 'No'
            );
            addResultItem(abuseGrid, 'Firehol Level 1', data.is_firehol === true ? 'Yes' : 'No');
            addResultItem(
                abuseGrid,
                'Tor Exit Node',
                data.is_tor_exit_node === true ? 'Yes' : 'No'
            );

            const extraFields = [
                { key: 'fraud_score', label: 'Fraud Score' },
                { key: 'threat_type', label: 'Threat Type' },
            ];

            extraFields.forEach((field) => {
                if (isValidValue(data[field.key])) {
                    addResultItem(abuseGrid, field.label, data[field.key]);
                } else {
                    addResultItem(abuseGrid, field.label, 'N/A');
                }
            });
        }

        if (isPublic) {
            initializeMap(data.latitude, data.longitude, data.ip_address);
        }
    };

    const addResultItem = (container, label, value) => {
        const item = document.createElement('div');
        item.className = 'result-item';

        const labelEl = document.createElement('div');
        labelEl.className = 'result-label';
        labelEl.textContent = label;

        const valueEl = document.createElement('div');
        valueEl.className = 'result-value';
        valueEl.textContent = value;

        item.appendChild(labelEl);
        item.appendChild(valueEl);
        container.appendChild(item);

        if (container === elements.results.locationGrid) {
            sectionItemCounts.location++;
            if (elements.results.locationSection && sectionItemCounts.location === 1) {
                elements.results.locationSection.style.display = 'block';
            }
        } else if (container === elements.results.networkGrid) {
            sectionItemCounts.network++;
            if (elements.results.networkSection && sectionItemCounts.network === 1) {
                elements.results.networkSection.style.display = 'block';
            }
        }
    };

    const ipv4ToInt = (ip) => {
        return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
    };

    const ipv4ToHex = (ip) => {
        return ipv4ToInt(ip).toString(16).padStart(8, '0');
    };

    const ipv4ToBinary = (ip) => {
        return ipv4ToInt(ip).toString(2).padStart(32, '0');
    };

    const ipv4ToDottedBinary = (ip) => {
        return ip
            .split('.')
            .map((octet) => parseInt(octet, 10).toString(2).padStart(8, '0'))
            .join('.');
    };

    const ipv4ToDottedHex = (ip) => {
        return ip
            .split('.')
            .map((octet) => parseInt(octet, 10).toString(16).padStart(2, '0'))
            .join('.');
    };

    const ipv4ToDottedOctal = (ip) => {
        return ip
            .split('.')
            .map((octet) => parseInt(octet, 10).toString(8).padStart(3, '0'))
            .join('.');
    };

    const ipv4ToIPv6Mapped = (ip) => {
        const octets = ip.split('.');
        const hex = octets
            .map((octet) => parseInt(octet, 10).toString(16).padStart(2, '0'))
            .join('');
        return `::ffff:${hex.slice(0, 4)}:${hex.slice(4, 8)}`;
    };

    const expandIPv6 = (ip) => {
        const doubleColonCount = (ip.match(/::/g) || []).length;
        if (doubleColonCount > 1) {
            throw new Error("Invalid IPv6 address: multiple '::' found");
        }

        if (doubleColonCount === 1) {
            const parts = ip.split('::');
            const left = parts[0] ? parts[0].split(':') : [];
            const right = parts[1] ? parts[1].split(':') : [];
            const missing = 8 - left.length - right.length;

            if (missing < 0) {
                throw new Error('Invalid IPv6 address: too many segments');
            }

            const middle = Array(missing).fill('0000');
            const expanded = [...left, ...middle, ...right];
            return expanded.map((part) => part.padStart(4, '0')).join(':');
        } else {
            return ip
                .split(':')
                .map((part) => part.padStart(4, '0'))
                .join(':');
        }
    };

    const compressIPv6 = (ip) => {
        const expanded = expandIPv6(ip);
        const parts = expanded.split(':');

        let longestRun = { start: -1, length: 0 };
        let currentRun = { start: -1, length: 0 };

        for (let i = 0; i < parts.length; i++) {
            if (parts[i] === '0000') {
                if (currentRun.length === 0) {
                    currentRun.start = i;
                }
                currentRun.length++;
            } else if (currentRun.length > 0) {
                if (currentRun.length > longestRun.length) {
                    longestRun = { ...currentRun };
                }
                currentRun = { start: -1, length: 0 };
            }
        }

        if (currentRun.length > longestRun.length) {
            longestRun = { ...currentRun };
        }

        if (longestRun.length >= 2) {
            const before = parts.slice(0, longestRun.start);
            const after = parts.slice(longestRun.start + longestRun.length);

            let result;
            if (before.length === 0 && after.length === 0) {
                result = '::';
            } else if (before.length === 0) {
                result =
                    '::' +
                    after
                        .map((p) => (parseInt(p, 16) === 0 ? '0' : p.replace(/^0+/, '')))
                        .join(':');
            } else if (after.length === 0) {
                result =
                    before
                        .map((p) => (parseInt(p, 16) === 0 ? '0' : p.replace(/^0+/, '')))
                        .join(':') + '::';
            } else {
                result =
                    before
                        .map((p) => (parseInt(p, 16) === 0 ? '0' : p.replace(/^0+/, '')))
                        .join(':') +
                    '::' +
                    after
                        .map((p) => (parseInt(p, 16) === 0 ? '0' : p.replace(/^0+/, '')))
                        .join(':');
            }

            return result;
        }

        return parts.map((p) => (parseInt(p, 16) === 0 ? '0' : p.replace(/^0+/, ''))).join(':');
    };

    const ipv6ToHex = (ip) => {
        return expandIPv6(ip).replace(/:/g, '');
    };

    const ipv6ToBinary = (ip) => {
        const expanded = expandIPv6(ip);
        return expanded
            .split(':')
            .map((part) => {
                return parseInt(part, 16).toString(2).padStart(16, '0');
            })
            .join(':');
    };

    const createFormatItem = (label, value) => {
        const item = document.createElement('div');
        item.className = 'format-item';

        const labelEl = document.createElement('span');
        labelEl.className = 'format-label';
        labelEl.textContent = label + ': ';

        const valueEl = document.createElement('span');
        valueEl.className = 'format-value';
        valueEl.textContent = value;

        item.appendChild(labelEl);
        item.appendChild(valueEl);
        return item;
    };

    const updateIPFormats = (data) => {
        const container = document.getElementById('ip-formats-container');
        if (!container) return;

        container.innerHTML = '';

        const formatSection = document.createElement('div');
        formatSection.className = 'ip-format';

        if (data.version === 4) {
            try {
                const ip = data.ip_address;
                const decimal = ipv4ToInt(ip).toString();
                const hex = '0x' + ipv4ToHex(ip);
                const binary = ipv4ToBinary(ip);
                const dottedBinary = ipv4ToDottedBinary(ip);
                const dottedHex = ipv4ToDottedHex(ip);
                const dottedOctal = ipv4ToDottedOctal(ip);
                const ipv6Mapped = ipv4ToIPv6Mapped(ip);

                formatSection.appendChild(createFormatItem('Decimal', decimal));
                formatSection.appendChild(createFormatItem('Hexadecimal', hex));
                formatSection.appendChild(createFormatItem('Binary', binary));
                formatSection.appendChild(createFormatItem('Dotted Binary', dottedBinary));
                formatSection.appendChild(createFormatItem('Dotted Hex', dottedHex));
                formatSection.appendChild(createFormatItem('Dotted Octal', dottedOctal));
                formatSection.appendChild(createFormatItem('IPv6 Mapped', ipv6Mapped));
            } catch (err) {
                console.error('Error calculating IPv4 formats:', err);
            }
        } else if (data.version === 6) {
            try {
                const ip = data.ip_address;
                const expanded = expandIPv6(ip);
                const compressed = compressIPv6(ip);
                const hex = '0x' + ipv6ToHex(ip);
                const binary = ipv6ToBinary(ip);

                formatSection.appendChild(createFormatItem('Expanded', expanded));
                formatSection.appendChild(createFormatItem('Compressed', compressed));
                formatSection.appendChild(createFormatItem('Hexadecimal', hex));
                formatSection.appendChild(createFormatItem('Binary Parts', binary));
            } catch (err) {
                console.error('Error calculating IPv6 formats:', err);
            }
        }

        container.appendChild(formatSection);
    };

    const generateRandomIPv4 = () => {
        const octet1 = Math.floor(Math.random() * 223) + 1;
        const octet2 = Math.floor(Math.random() * 254) + 1;
        const octet3 = Math.floor(Math.random() * 254) + 1;
        const octet4 = Math.floor(Math.random() * 254) + 1;

        if (
            octet1 === 10 ||
            (octet1 === 172 && octet2 >= 16 && octet2 <= 31) ||
            (octet1 === 192 && octet2 === 168) ||
            octet1 === 127 ||
            (octet1 === 169 && octet2 === 254)
        ) {
            return generateRandomIPv4();
        }

        return `${octet1}.${octet2}.${octet3}.${octet4}`;
    };

    const updateHeaderStructure = () => {
        const resultsHeader = document.querySelector('.results-header');
        const resultsLogo = document.querySelector('.results-logo');
        const resultsActions = document.querySelector('.results-actions');
        const closeButton = document.getElementById('close-results');

        if (window.innerWidth <= 768) {
            if (!document.querySelector('.results-logo-nav')) {
                const logoNav = document.createElement('div');
                logoNav.className = 'results-logo-nav';

                if (resultsLogo && closeButton) {
                    resultsHeader.insertBefore(logoNav, resultsActions);
                    logoNav.appendChild(resultsLogo);
                    logoNav.appendChild(closeButton);
                }
            }
        } else {
            const logoNav = document.querySelector('.results-logo-nav');
            if (logoNav) {
                const resultsLogo = logoNav.querySelector('.results-logo');
                const closeButton = logoNav.querySelector('#close-results');

                if (resultsLogo && closeButton && resultsHeader && resultsActions) {
                    resultsHeader.insertBefore(resultsLogo, resultsActions);
                    resultsActions.appendChild(closeButton);
                    logoNav.remove();
                }
            }
        }
    };

    const checkUrlForIp = () => {
        const urlParams = new URLSearchParams(window.location.search);
        const ipParam = urlParams.get('ip');

        if (ipParam) {
            elements.hero.style.display = 'none';
            elements.hero.classList.add('hidden');

            const featuresSection = document.querySelector('.features-section');
            const useCasesSection = document.querySelector('.use-cases-section');
            const apiDocsSection = document.querySelector('.api-docs-section');
            const ctaSection = document.querySelector('.cta-section');

            if (featuresSection) featuresSection.style.display = 'none';
            if (useCasesSection) useCasesSection.style.display = 'none';
            if (apiDocsSection) apiDocsSection.style.display = 'none';
            if (ctaSection) ctaSection.style.display = 'none';

            elements.results.view.style.display = 'block';
            elements.results.view.classList.add('active');
            showLoading();

            elements.search.input.value = ipParam;
            elements.results.input.value = ipParam;
            updateSearchButtonVisibility();

            document.body.classList.add('results-active');

            window.history.replaceState(
                { view: 'results', query: ipParam },
                '',
                `?ip=${encodeURIComponent(ipParam)}`
            );

            fetchIPData(ipParam);
        }
    };

    elements.results.closeButton.addEventListener('click', (e) => {
        e.preventDefault();
        transitionToHeroView();
    });

    window.addEventListener('resize', updateHeaderStructure);

    window.addEventListener('popstate', (event) => {
        if (event.state && event.state.view === 'results') {
            const query = event.state.query;
            if (query) {
                elements.search.input.value = query;
                fetchIPData(query);
            }
        } else if (elements.results.view.classList.contains('active')) {
            transitionToHeroView();
        }
    });

    document.body.classList.add('loaded');
    setupSearchEvents();
    setupHelperButtons();
    updateSiteTheme();
    setTimeout(updateHeaderStructure, 100);
    setTimeout(checkUrlForIp, 0);
});
