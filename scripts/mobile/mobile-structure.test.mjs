import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
const read = (p) => readFileSync(p, 'utf8');

test('two independently registered mobile previews have distinct entry points', () => {
    const aurora = read('apps/experience-center/aurora-mobile.html');
    const brisa = read('apps/experience-center/brisa-mobile.html');
    assert.match(aurora, /data-application-id="aurora-mobile"/);
    assert.match(brisa, /data-application-id="brisa-mobile"/);
    assert.match(aurora, /aurora-entry\.tsx/);
    assert.match(brisa, /brisa-entry\.tsx/);
    assert.notEqual(aurora, brisa);
});

test('mobile applications share preview API, never simulate native security as verified', () => {
    const mobile = read('apps/experience-center/src/mobile/MobileLaboratory.tsx');
    const domain = read('apps/experience-center/src/mobile/mobile-domain.ts');
    assert.match(mobile, /PREVIEW SEM WSO2/);
    assert.match(mobile, /data-testid="device-frame"/);
    assert.match(mobile, /Navegação do \$\{brandTitle\} Mobile/);
    assert.match(mobile, /Simular cadastro/);
    assert.match(domain, /identityVerified:false/);
    assert.match(domain, /X-Experience-Preview/);
    assert.match(domain, /identity-poc:\$\{appId\}:\$\{persona\}:cart:v1/);
    assert.doesNotMatch(mobile, /Bearer\s+[A-Za-z0-9]+/);
});

test('Vite multi-page config contains both mobile applications', () => {
    const config = read('apps/experience-center/mobile.vite.config.ts');
    assert.match(config, /auroraMobile:/);
    assert.match(config, /brisaMobile:/);
    assert.match(read('experience.sh'), /mobile\.vite\.config\.ts/);
});
