import React from 'react';
import { createRoot } from 'react-dom/client';
import { OperationsLab } from './OperationsLab';
import './operations.css';
const page = document.body.dataset.operationsPage || 'b2b';
createRoot(document.getElementById('root')!).render(<React.StrictMode><OperationsLab initialPage={page} /></React.StrictMode>);
