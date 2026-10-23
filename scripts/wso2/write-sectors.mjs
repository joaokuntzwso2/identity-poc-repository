import {config,deploymentPlan} from './domain.mjs';import {writeSectorDocuments} from './sector.mjs';
const docs=writeSectorDocuments(deploymentPlan(config()));console.log('SECTOR_DOCUMENTS_WRITTEN',Object.keys(docs).join(', '),'— build and serve on trusted HTTPS before bootstrap apply.');
