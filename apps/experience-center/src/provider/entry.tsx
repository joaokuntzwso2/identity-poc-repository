import React from 'react';
import {createRoot} from 'react-dom/client';
import {ProviderReadiness} from './ProviderReadiness';
import './provider.css';
const element=document.getElementById('root');
if(!element)throw new Error('PROVIDER_ROOT_MISSING');
createRoot(element).render(<React.StrictMode><ProviderReadiness/></React.StrictMode>);
