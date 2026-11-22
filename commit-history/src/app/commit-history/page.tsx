import type { Metadata } from 'next';
import { CommitHistoryClient } from './CommitHistoryClient';

export const metadata: Metadata = {
  title: 'Commit History — CodeWhy',
  description: 'Explore commit authors, timestamps, file diffs, and graph-linked possible project effects.',
};

export default function CommitHistoryPage() {
  return <CommitHistoryClient />;
}
