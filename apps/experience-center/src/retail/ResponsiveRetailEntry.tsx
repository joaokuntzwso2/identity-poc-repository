import React from 'react';
import './responsive-retail.css';

type Brand = 'aurora' | 'brisa';

const configuredOrigin = import.meta.env.VITE_LIVE_BFF_ORIGIN;
// Only allow explicit HTTP(S) origins. Do not copy authentication state or browser tokens.
const liveOrigin = typeof configuredOrigin === 'string' && /^https?:\/\/[^/]+\/?$/.test(configuredOrigin)
  ? configuredOrigin.replace(/\/$/, '')
  : 'http://127.0.0.1:4400';

const stories: Record<Brand, {
  name: string;
  monogram: string;
  descriptor: string;
  eyebrow: string;
  headline: string;
  subheadline: string;
  featureOne: string;
  featureTwo: string;
}> = {
  aurora: {
    name: 'Aurora', monogram: '✳', descriptor: 'Tecnologia & cotidiano',
    eyebrow: 'ESCOLHAS PARA O SEU DIA', headline: 'Tecnologia que acompanha você.',
    subheadline: 'Descubra o universo Aurora no portal real, com autenticação WSO2.',
    featureOne: 'Novidades em tecnologia', featureTwo: 'Experiência personalizada',
  },
  brisa: {
    name: 'Brisa', monogram: 'b.', descriptor: 'Casa & living',
    eyebrow: 'A CASA, DO SEU JEITO', headline: 'A beleza mora nos detalhes.',
    subheadline: 'Inspire o seu espaço no portal real, com autenticação WSO2.',
    featureOne: 'Peças para cada espaço', featureTwo: 'Seu espaço, suas escolhas',
  },
};

export function ResponsiveRetailEntry({ brand }: { brand: Brand }) {
  const story = stories[brand];
  const portal = `${liveOrigin}/portal/${brand}/web`;
  const other: Brand = brand === 'aurora' ? 'brisa' : 'aurora';
  const otherPage = `/${other}.html`;
  return (
    <main className={`retail-preview retail-preview--${brand}`} id="main-content">
      <a className="retail-preview__skip" href="#retail-device-content">Ir para a prévia da loja</a>
      <div className="retail-preview__layout">
        <header className="retail-preview__context" aria-label="Informações do canal">
          <div className="retail-preview__identity">
            <span className="retail-preview__context-icon" aria-hidden="true">◈</span>
            <div>
              <span className="retail-preview__context-kicker">IDENTITY EXPERIENCE CENTER</span>
              <h1>{story.name} · Web</h1>
            </div>
          </div>
          <p className="retail-preview__context-copy">Uma prévia visual do canal web. A experiência autenticada permanece no portal WSO2.</p>
          <div className="retail-preview__context-actions">
            <a className="retail-preview__primary" href={portal}>Abrir portal real <span aria-hidden="true">↗</span></a>
            <a className="retail-preview__secondary" href={otherPage}>Ver {stories[other].name} Web</a>
          </div>
          <div className="retail-preview__notice" role="note">
            Esta página não autentica nem simula usuários, carrinho ou permissões. As ações reais abrem o BFF.
          </div>
        </header>

        <section className="retail-preview__stage" aria-label={`Apresentação móvel do canal ${story.name} Web`}>
          <div className="retail-preview__device" data-testid="retail-device-frame">
            <div className="retail-preview__device-top" aria-hidden="true"><span className="retail-preview__speaker" /></div>
            <div className="retail-preview__screen" id="retail-device-content">
              <p className="retail-preview__disclosure">AMBIENTE DE DEMONSTRAÇÃO · CANAL WEB</p>
              <div className="retail-preview__store-head">
                <div className="retail-preview__store-brand">
                  <span className="retail-preview__wordmark">{brand === 'brisa' ? 'brisa.' : 'aurora'}</span>
                  <span className="retail-preview__store-descriptor">{story.descriptor}</span>
                </div>
                <a className="retail-preview__account" href={portal} aria-label={`Abrir conta no portal real ${story.name}`} title="Abrir portal WSO2">↗</a>
              </div>
              <div className="retail-preview__hero">
                <span className="retail-preview__eyebrow">{story.eyebrow}</span>
                <h2>{story.headline}</h2>
                <p>{story.subheadline}</p>
                <a href={portal} className="retail-preview__hero-cta">Explorar no portal <span aria-hidden="true">↗</span></a>
                <div className="retail-preview__art" aria-hidden="true">
                  <div className="retail-preview__art-disc" />
                  <div className="retail-preview__art-object" />
                  <div className="retail-preview__art-accent" />
                </div>
              </div>
              <section className="retail-preview__discover" aria-labelledby="retail-discover-heading">
                <span className="retail-preview__section-kicker">EXPLORE O UNIVERSO {story.name.toUpperCase()}</span>
                <h3 id="retail-discover-heading">Inspiração para começar</h3>
                <div className="retail-preview__feature-grid">
                  <a href={portal} className="retail-preview__feature" aria-label={`${story.featureOne} no portal real`}>
                    <span className="retail-preview__feature-art retail-preview__feature-art--one" aria-hidden="true" />
                    <strong>{story.featureOne}</strong><span className="retail-preview__feature-link">Abrir loja ↗</span>
                  </a>
                  <a href={portal} className="retail-preview__feature" aria-label={`${story.featureTwo} no portal real`}>
                    <span className="retail-preview__feature-art retail-preview__feature-art--two" aria-hidden="true" />
                    <strong>{story.featureTwo}</strong><span className="retail-preview__feature-link">Abrir loja ↗</span>
                  </a>
                </div>
              </section>
              <nav className="retail-preview__bottom-nav" aria-label={`Acesso ao canal ${story.name}`}>
                <a href={portal}><span aria-hidden="true">⌂</span><span>Loja real</span></a>
                <a href={`${liveOrigin}/lab#presenter`}><span aria-hidden="true">◇</span><span>Jornada</span></a>
                <a href={`${liveOrigin}/lab#evidence`}><span aria-hidden="true">◎</span><span>Evidências</span></a>
              </nav>
            </div>
            <div className="retail-preview__device-bottom" aria-hidden="true"><span /></div>
          </div>
        </section>
      </div>
    </main>
  );
}
