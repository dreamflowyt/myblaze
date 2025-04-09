document.addEventListener('DOMContentLoaded', function() {
    // Toggle confirmation dialogues
    const deleteButtons = document.querySelectorAll('.delete-confirm');
    const adminToggleButtons = document.querySelectorAll('.admin-toggle-confirm');
    
    deleteButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            if (!confirm('Are you sure you want to delete this item? This action cannot be undone.')) {
                e.preventDefault();
            }
        });
    });
    
    adminToggleButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            if (!confirm('Are you sure you want to change the admin status for this user?')) {
                e.preventDefault();
            }
        });
    });
    
    // Search functionality for tables
    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
        searchInput.addEventListener('keyup', function() {
            const searchTerm = this.value.toLowerCase();
            const tableRows = document.querySelectorAll('.searchable-table tbody tr');
            
            tableRows.forEach(row => {
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(searchTerm) ? '' : 'none';
            });
        });
    }
    
    // Statistics charts (if Chart.js is available)
    if (typeof Chart !== 'undefined' && document.getElementById('usersChart')) {
        // Users growth chart
        const usersCtx = document.getElementById('usersChart').getContext('2d');
        new Chart(usersCtx, {
            type: 'line',
            data: {
                labels: ['January', 'February', 'March', 'April', 'May', 'June'],
                datasets: [{
                    label: 'New Users',
                    data: [12, 19, 3, 5, 2, 3],
                    borderColor: '#00ff00',
                    backgroundColor: 'rgba(0, 255, 0, 0.1)',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'top',
                        labels: {
                            color: '#00ff00'
                        }
                    },
                    title: {
                        display: true,
                        text: 'User Growth',
                        color: '#00ff00'
                    }
                },
                scales: {
                    x: {
                        ticks: {
                            color: '#888888'
                        },
                        grid: {
                            color: 'rgba(0, 255, 0, 0.1)'
                        }
                    },
                    y: {
                        ticks: {
                            color: '#888888'
                        },
                        grid: {
                            color: 'rgba(0, 255, 0, 0.1)'
                        }
                    }
                }
            }
        });
    }
    
    if (typeof Chart !== 'undefined' && document.getElementById('messagesChart')) {
        // Messages chart
        const messagesCtx = document.getElementById('messagesChart').getContext('2d');
        new Chart(messagesCtx, {
            type: 'bar',
            data: {
                labels: ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'],
                datasets: [{
                    label: 'Messages',
                    data: [65, 59, 80, 81, 56, 55, 40],
                    backgroundColor: 'rgba(0, 255, 0, 0.5)',
                    borderColor: '#00ff00',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'top',
                        labels: {
                            color: '#00ff00'
                        }
                    },
                    title: {
                        display: true,
                        text: 'Messages by Day',
                        color: '#00ff00'
                    }
                },
                scales: {
                    x: {
                        ticks: {
                            color: '#888888'
                        },
                        grid: {
                            color: 'rgba(0, 255, 0, 0.1)'
                        }
                    },
                    y: {
                        ticks: {
                            color: '#888888'
                        },
                        grid: {
                            color: 'rgba(0, 255, 0, 0.1)'
                        }
                    }
                }
            }
        });
    }
});
