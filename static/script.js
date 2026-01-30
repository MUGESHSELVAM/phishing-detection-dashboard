function checkURL() {
    const url = document.getElementById("url").value;
    const result = document.getElementById("result");

    result.innerText = "🔍 Scanning...";
    result.className = "";

    fetch("/api/check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url })
    })
    .then(res => res.json())
    .then(data => {
        if (data.result.includes("Phishing")) {
            result.innerText = "⚠️ PHISHING THREAT DETECTED";
            result.className = "danger";
        } else {
            result.innerText = "✅ SAFE WEBSITE";
            result.className = "safe";
        }
    })
    .catch(() => {
        result.innerText = "❌ Server Error";
        result.className = "danger";
    });
}
