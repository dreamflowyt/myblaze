// Theme toggler for Blazer Chat
document.addEventListener('DOMContentLoaded', function() {
    // Check for saved theme preference or default to 'light'
    const currentTheme = localStorage.getItem('theme') || 'light';
    
    // Apply the theme on page load
    document.documentElement.setAttribute('data-theme', currentTheme);
    updateThemeToggle(currentTheme);
    
    // Add click handler to theme toggle button
    const themeToggle = document.getElementById('theme-toggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', function() {
            // Get the current theme directly from the HTML attribute
            const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
            
            // If current theme is light, switch to dark, and vice versa
            const newTheme = (currentTheme === 'light') ? 'dark' : 'light';
            
            // Update HTML attribute
            document.documentElement.setAttribute('data-theme', newTheme);
            
            // Store the preference
            localStorage.setItem('theme', newTheme);
            
            // Update toggle button appearance
            updateThemeToggle(newTheme);
        });
    }
});

function updateThemeToggle(theme) {
    const themeToggle = document.getElementById('theme-toggle');
    if (!themeToggle) return;
    
    if (theme === 'dark') {
        themeToggle.innerHTML = '<i class="fas fa-sun me-2"></i>Light Mode';
        themeToggle.setAttribute('title', 'Switch to light mode');
    } else {
        themeToggle.innerHTML = '<i class="fas fa-moon me-2"></i>Dark Mode';
        themeToggle.setAttribute('title', 'Switch to dark mode');
    }
}