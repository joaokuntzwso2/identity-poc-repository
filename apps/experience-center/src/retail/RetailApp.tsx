import React from 'react';
import { ResponsiveRetailEntry } from './ResponsiveRetailEntry';

// These Vite entry points are responsive access previews, not authenticated portals.
// All live authentication and business interactions remain on the WSO2-backed BFF.
export function RetailApp({ brand }: { brand: 'aurora' | 'brisa' }) {
  return <ResponsiveRetailEntry brand={brand} />;
}
