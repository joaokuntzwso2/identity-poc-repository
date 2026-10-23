import React from 'react';
import {createRoot} from 'react-dom/client';
import {RetailApp} from './retail/RetailApp';
const el=document.getElementById('root');
if(!el)throw new Error('Missing root element');
const brand=el.dataset.brand;
if(brand!=='aurora'&&brand!=='brisa')throw new Error('Invalid fictional brand');
createRoot(el).render(<React.StrictMode><RetailApp brand={brand}/></React.StrictMode>);
