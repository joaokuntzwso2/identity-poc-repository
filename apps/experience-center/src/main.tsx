import React from 'react';
import { createRoot } from 'react-dom/client';

// Zero-mock fallback: the former fixture-driven Experience Center is retired.
// A standalone Vite preview must not impersonate a WSO2-authenticated customer.
function PortalEntry() {
  return <main style={{fontFamily:'system-ui',maxWidth:720,margin:'5rem auto',padding:'2rem'}}>
    <h1>WSO2 Identity Server 7.3 · Customer Portals</h1>
    <p>The customer portals run through the WSO2-backed BFF, not the synthetic preview.</p>
    <p><a href="http://127.0.0.1:4400/portal/aurora">Open Aurora portal</a></p>
    <p><a href="http://127.0.0.1:4400/portal/brisa">Open Brisa portal</a></p>
    <p>Authentication, access tokens, and protected profile requests are processed by the BFF. Unsupported experiences are disabled.</p>
  </main>;
}
createRoot(document.getElementById('root')!).render(<React.StrictMode><PortalEntry/></React.StrictMode>);
