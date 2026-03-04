import { useState } from "react";
import { login, scanURL } from "./api";

function App() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [url, setUrl] = useState("");
  const [token, setToken] = useState(null);
  const [result, setResult] = useState(null);

  const handleLogin = async () => {
    const data = await login(email, password);
    if (data.access_token) {
      setToken(data.access_token);
      alert("Login successful!");
    } else {
      alert("Login failed");
    }
  };

  const handleScan = async () => {
    const data = await scanURL(url, token);
    setResult(data);
  };

  return (
    <div style={{ padding: "40px" }}>
      <h2>Phishing Detection Dashboard</h2>

      {!token && (
        <div>
          <h3>Login</h3>
          <input placeholder="Email" onChange={e => setEmail(e.target.value)} />
          <br /><br />
          <input type="password" placeholder="Password" onChange={e => setPassword(e.target.value)} />
          <br /><br />
          <button onClick={handleLogin}>Login</button>
        </div>
      )}

      {token && (
        <div>
          <h3>Scan URL</h3>
          <input placeholder="Enter URL" onChange={e => setUrl(e.target.value)} />
          <br /><br />
          <button onClick={handleScan}>Scan</button>

          {result && (
            <div style={{ marginTop: "20px" }}>
              <h4>Result:</h4>
              <p>Status: {result.status}</p>
              <p>Risk Score: {result.risk_score}</p>
              <p>Confidence: {result.confidence}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default App;