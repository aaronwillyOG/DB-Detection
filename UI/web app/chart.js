var ctx = document.getElementById('tracker-chart').getContext('2d');
    var chart = new Chart(ctx, {
    type: 'line', 
    data: {
        labels: ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'], 
        datasets: [{
            label: 'Trackers Blocked', 
            data: [12, 19, 3, 5, 2, 3, 7], 
            backgroundColor: 'rgba(75, 192, 192, 0.2)', 
            borderColor: 'rgba(75, 192, 192, 1)', 
            borderWidth: 2 
        }]
    },
    options: {
        scales: {
            y: {
                beginAtZero: true 
            }
        }
    }
});