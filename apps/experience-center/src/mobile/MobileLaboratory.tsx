import React from 'react';
import { LiveBffEntry } from '../retired/LiveBffEntry';

// This is a browser experience, not a native app or a separate identity simulator.
export function MobileLaboratory({ brand }: { brand: 'aurora' | 'brisa'; appId: 'aurora-mobile' | 'brisa-mobile' }) {
  return <LiveBffEntry brand={brand} surface="mobile" />;
}
