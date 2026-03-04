// popup script: fetches current tab URL and shows result

document.addEventListener('DOMContentLoaded', async () => {
  const statusEl = document.getElementById('status');
  statusEl.textContent = 'Checking...';
  try {
    let [tab] = await chrome.tabs.query({active: true, currentWindow: true});
    let url = tab.url || '';
    // replace TOKEN with a real JWT obtained from the /auth/login flow
    const TOKEN = localStorage.getItem('auth_token') || '';
    const response = await fetch('http://localhost:8000/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${TOKEN}` },
      body: JSON.stringify({ url })
    });
    const data = await response.json();
    if (data.prediction === 'phishing') {
      statusEl.className = 'phish';
      statusEl.textContent = '⚠️ Phishing Alert!';
    } else {
      statusEl.className = 'safe';
      statusEl.textContent = '✅ Site appears safe';
    }
  } catch (err) {
    statusEl.textContent = 'Error contacting API';
    console.error(err);
  }
});