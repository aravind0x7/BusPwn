// Rotate hacker quotes
function updateQuote() {
    const quotes = [
        "The quieter you become, the more you are able to hear.",
        "Hack the planet!",
        "There is no patch for human stupidity.",
        "Data is the new oil.",
        "Privacy is not a luxury; it's a right."
    ];
    document.getElementById("hacker-quote").innerText = '"' + quotes[Math.floor(Math.random() * quotes.length)] + '"';
}
setInterval(updateQuote, 5000);

// Show result tabs
function showResultTab(tabName) {
    const tabs = document.getElementsByClassName("result-tab-content");
    const buttons = document.getElementsByClassName("result-tab");
    for (let i = 0; i < tabs.length; i++) {
        tabs[i].style.display = "none";
    }
    for (let i = 0; i < buttons.length; i++) {
        buttons[i].className = buttons[i].className.replace(" active", "");
    }
    document.getElementById(tabName).style.display = "block";
    event.currentTarget.className += " active";
}

// Show/hide slave ID range based on checkbox
window.addEventListener("DOMContentLoaded", function () {
    document.getElementById("discover_slave_ids").addEventListener("change", function () {
        document.getElementById("slave-id-range").style.display = this.checked ? "block" : "none";
    });
    document.getElementById("slave-id-range").style.display = "none";
});

function testModbus() {
    const ip = document.getElementById("test_ip").value;
    const port = document.getElementById("test_port").value || 502;
    const testResult = document.getElementById("test-result");

    if (!ip) {
        alert("Target IP is required!");
        return;
    }

    testResult.innerText = "Testing connection...";
    testResult.className = "result-mini testing";

    fetch('/modbus_test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, port })
    })
        .then(res => res.json())
        .then(data => {
            testResult.innerText = (data.modbus_available ? "✅ " : "❌ ") + data.message;
            testResult.className = "result-mini " + (data.modbus_available ? "success" : "error");
        })
        .catch(error => {
            testResult.innerText = "❌ Error: " + error;
            testResult.className = "result-mini error";
        });
}

function startScan() {
    const ip = document.getElementById("scan_ip").value;
    const port = document.getElementById("scan_port").value || 502;
    const slave_id = document.getElementById("scan_slave_id").value || 1;
    const start_address = document.getElementById("scan_start").value || 0;
    const end_address = document.getElementById("scan_end").value || 10;
    const discover_slave_ids = document.getElementById("discover_slave_ids").checked;
    const slave_id_start = document.getElementById("slave_id_start").value || 1;
    const slave_id_end = document.getElementById("slave_id_end").value || 255;

    const scan_registers = document.getElementById("scan_registers").checked;
    const scan_coils = document.getElementById("scan_coils").checked;
    const scan_discrete_inputs = document.getElementById("scan_discrete_inputs").checked;
    const scan_input_registers = document.getElementById("scan_input_registers").checked;

    if (!ip) {
        alert("Target IP is required!");
        return;
    }
    if (!discover_slave_ids && !scan_registers && !scan_coils && !scan_discrete_inputs && !scan_input_registers) {
        alert("Select at least one scan option or enable slave ID discovery!");
        return;
    }

    document.getElementById("scan-output").innerText = "Starting scan...";
    document.getElementById("progress-bar").style.width = "0%";
    document.getElementById("progress-text").innerText = "Starting...";

    fetch('/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            ip, port, slave_id, start_address, end_address,
            scan_registers, scan_coils, scan_discrete_inputs, scan_input_registers,
            discover_slave_ids, slave_id_start, slave_id_end
        })
    })
        .then(res => res.json())
        .then(data => {
            if (data.status === "started") {
                pollScanStatus();
            } else {
                document.getElementById("scan-output").innerText = "Error starting scan: " + data.message;
            }
        })
        .catch(err => {
            document.getElementById("scan-output").innerText = "Error: " + err;
        });
}

function pollScanStatus() {
    const interval = setInterval(() => {
        fetch('/scan_status')
            .then(res => res.json())
            .then(data => {
                document.getElementById("progress-bar").style.width = data.progress + "%";
                document.getElementById("progress-text").innerText = data.message;

                if (["completed", "error", "aborted", "failed"].includes(data.status)) {
                    clearInterval(interval);
                    getScanResults();
                }
            })
            .catch(() => {
                document.getElementById("progress-text").innerText = "Error polling status";
                clearInterval(interval);
            });
    }, 1000);
}

function getScanResults() {
    fetch('/scan_results')
        .then(res => res.json())
        .then(data => {
            document.getElementById("scan-output").innerText = JSON.stringify(data, null, 2);
        })
        .catch(err => {
            document.getElementById("scan-output").innerText = "Error fetching results: " + err;
        });
}

function stopScan() {
    fetch('/stop_scan', { method: 'POST' })
        .then(res => res.json())
        .then(data => {
            document.getElementById("progress-text").innerText = data.message;
        })
        .catch(err => {
            document.getElementById("progress-text").innerText = "Error stopping scan: " + err;
        });
}

