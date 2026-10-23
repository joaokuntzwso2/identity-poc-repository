import React from 'react';import{createRoot}from'react-dom/client';import{OperatorLab}from'./OperatorLab';import './operator.css';
const root=document.getElementById('root');if(root)createRoot(root).render(<React.StrictMode><OperatorLab/></React.StrictMode>);
