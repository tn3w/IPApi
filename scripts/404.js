document.addEventListener('DOMContentLoaded', () => {
    function updateTheme() {
        const savedTheme = localStorage.getItem('theme');
        const prefersDarkMode = window.matchMedia('(prefers-color-scheme: dark)').matches;

        const htmlElement = document.documentElement;
        htmlElement.classList.remove('light-theme', 'dark-theme');

        if (savedTheme === 'dark' || (savedTheme !== 'light' && prefersDarkMode)) {
            htmlElement.classList.add('dark-theme');
        } else if (savedTheme === 'light' || (savedTheme !== 'dark' && !prefersDarkMode)) {
            htmlElement.classList.add('light-theme');
        }
    }

    updateTheme();

    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', updateTheme);

    const searchForm = document.getElementById('search-form');
    const searchInput = document.getElementById('search-input');
    const searchButton = document.getElementById('search-button');

    function updateSearchButtonVisibility() {
        const isEmpty = searchInput.value.trim() === '';
        searchButton.classList.toggle('visible', !isEmpty);
        searchButton.classList.toggle('hidden', isEmpty);
    }

    function handleSearch() {
        const query = searchInput.value.trim();
        if (query) {
            window.location.href = `/?ip=${encodeURIComponent(query)}`;
        }
    }

    ['input', 'change', 'autocomplete'].forEach((event) => {
        searchInput.addEventListener(event, updateSearchButtonVisibility);
    });

    searchForm.addEventListener('submit', (event) => {
        event.preventDefault();
    });

    searchInput.addEventListener('animationstart', (e) => {
        if (e.animationName.indexOf('autofill') !== -1) updateSearchButtonVisibility();
    });

    updateSearchButtonVisibility();

    searchButton.addEventListener('click', handleSearch);

    searchInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter' && searchInput.value.trim()) {
            handleSearch();
        }
    });
});
