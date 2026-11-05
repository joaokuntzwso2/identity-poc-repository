import React from 'react';
import { LiveBffEntry } from '../retired/LiveBffEntry';

// Standalone Vite preview intentionally does not create or select identities.
// The live retail UI and persistence remain implemented in the existing BFF.
export function RetailApp({ brand }: { brand: 'aurora' | 'brisa' }) {
  return <LiveBffEntry brand={brand} surface="web" />;
}
