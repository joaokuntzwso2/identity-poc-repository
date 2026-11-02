import React from 'react';
import { LiveBffEntry } from '../retired/LiveBffEntry';

// No local role assignment, tenant mutations or synthetic authorization outcomes.
export function OperationsLab({ initialPage }: { initialPage: string }) {
  return <LiveBffEntry surface="operations" area={initialPage} />;
}
