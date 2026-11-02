import React from 'react';
import './live-entry.css';

type Brand = 'aurora' | 'brisa';
type Surface = 'web' | 'mobile' | 'operations';

// Vite remains an informational fallback. Identity and business activity live in the BFF.
// VITE_LIVE_BFF_ORIGIN is optional for non-local deployments; never supply OIDC secrets here.
const configuredOrigin = import.meta.env.VITE_LIVE_BFF_ORIGIN;
const liveOrigin = (typeof configuredOrigin === 'string' && /^https?:\/\//.test(configuredOrigin)
  ? configuredOrigin : 'http://127.0.0.1:4400').replace(/\/$/, '');
const url = (path: string) => `${liveOrigin}${path}`;
const channels: { brand: Brand; surface: 'web' | 'mobile'; label: string; description: string }[] = [
  { brand: 'aurora', surface: 'web', label: 'Aurora · Web', description: 'Portal web com login WSO2' },
  { brand: 'aurora', surface: 'mobile', label: 'Aurora · Mobile', description: 'Experiência mobile no navegador' },
  { brand: 'brisa', surface: 'web', label: 'Brisa · Web', description: 'Portal web com login WSO2' },
  { brand: 'brisa', surface: 'mobile', label: 'Brisa · Mobile', description: 'Experiência mobile no navegador' },
];

export function LiveBffEntry({ brand, surface, area }: { brand?: Brand; surface: Surface; area?: string }) {
  const chosen = channels.filter(channel => !brand || (brand === channel.brand && channel.surface === surface));
  const name = brand === 'aurora' ? 'Aurora' : brand === 'brisa' ? 'Brisa' : 'Experience Center';
  const title = surface === 'operations' ? 'Operações e evidências verificáveis'
    : `${name} · ${surface === 'mobile' ? 'Mobile' : 'Web'}`;
  const sub = surface === 'operations'
    ? 'O laboratório anterior avaliava regras com identidades fictícias. A demonstração atual exige autenticação e decisões reais do BFF.'
    : 'A versão antiga desta tela usava seleção local de personas e ações simuladas. Use o canal autenticado WSO2 para uma demonstração verificável.';
  const areaMap: Record<string, string> = { b2b: 'b2b', onboarding: 'presenter', authorization: 'security', 'evidence-lab': 'evidence' };
  return <main className={`live-only-entry ${brand ? `live-only-${brand}` : ''}`} id="main-content">
    <div className="live-only-container">
      <header className="live-only-header">
        <span className="live-only-emblem" aria-hidden="true">{brand === 'brisa' ? 'b.' : brand === 'aurora' ? '✳' : '◈'}</span>
        <div><span className="live-only-kicker">IDENTITY EXPERIENCE CENTER · WSO2</span>
          <h1>{title}</h1></div>
      </header>
      <section className="live-only-intro" aria-labelledby="live-only-notice">
        <h2 id="live-only-notice">A experiência real está no BFF</h2>
        <p>{sub}</p>
        <p role="status">Nenhum usuário foi autenticado por esta página. Papéis, consentimento e MFA não são simulados aqui.</p>
      </section>
      <nav aria-label="Abrir canais WSO2 reais" className="live-only-grid">
        {chosen.map(channel => <a className="live-only-card" key={`${channel.brand}-${channel.surface}`}
          href={url(`/portal/${channel.brand}/${channel.surface}`)}>
          <strong>{channel.label}</strong>
          <span>{channel.description}</span>
          <span aria-hidden="true">Abrir portal ↗</span>
        </a>)}
      </nav>
      <nav className="live-only-actions" aria-label="Roteiro e provas">
        <a href={url(`/lab#${surface === 'operations' ? areaMap[area || ''] || 'presenter' : 'presenter'}`)}>Modo apresentador</a>
        <a href={url('/lab#evidence')}>Evidência técnica</a>
        <a href={url('/lab')}>Experience Center</a>
      </nav>
      <footer className="live-only-footnote">
        <p>O login é processado no BFF usando OIDC e WSO2. Mobile significa layout responsivo em navegador, não aplicativo nativo.</p>
        <p>Não execute operações de negócio em previews locais. Use os canais reais para ler sessões, permissões e solicitações.</p>
      </footer>
    </div>
  </main>;
}
