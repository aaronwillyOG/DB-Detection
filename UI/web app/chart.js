// Initialize chart
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

// Socket.IO setup for real-time alerts
const socket = io.connect('http://localhost:5000');

// Listen for tracker alerts
socket.on('tracker_alert', function(data) {
    // Parse the received data
    let alertType = data.type;
    let alertInfo = alertType === "DNS" ? data.domain : data.ip;

    // Add real-time alert to alert container
    const alertContainer = document.getElementById("alert-container");
    const alertDiv = document.createElement('div');
    alertDiv.className = 'alert-item';
    alertDiv.textContent = `Tracker detected: ${alertInfo}`;
    alertContainer.appendChild(alertDiv);

    // Update chart with live data
    chart.data.labels.push("New");  // Placeholder, can be timestamp
    chart.data.datasets[0].data.push(data.count);
    chart.update();
});




const hamburger = document.getElementById("hamburger");
const sidebar = document.getElementById("sidebar");
const mainContent = document.getElementById("main-content");

hamburger.addEventListener("click", () => {
    sidebar.classList.toggle("open");
    mainContent.classList.toggle("shift");
});
