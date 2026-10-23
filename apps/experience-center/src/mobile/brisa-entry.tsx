import React from 'react';
import {createRoot} from 'react-dom/client';
import {MobileLaboratory} from './MobileLaboratory';
import './mobile.css';
const root=document.getElementById('root');
if(!root)throw Error('Brisa mobile root not found');
createRoot(root).render(<React.StrictMode><MobileLaboratory brand="brisa" appId="brisa-mobile"/></React.StrictMode>);
