import { NextRequest } from 'next/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { KnowledgeGraph } from '@/types/graph';

const { getRepositoryGraph } = vi.hoisted(() => ({ getRepositoryGraph: vi.fn() }));

vi.mock('@/lib/graph/graph-store', () => ({ getRepositoryGraph }));

import { GET } from '@/app/api/commit-history/route';

function makeGraph(overrides: Partial<KnowledgeGraph> = {}): KnowledgeGraph {
  return {
    repoId: 'repo-demo-test',
    repoName: 'example/public-repo',
    nodes: [],
    edges: [],
    updatedAt: '2026-11-22T00:00:00.000Z',
    branch: 'trunk',
    commitSha: 'c'.repeat(40),
    isDemo: false,
    githubIsPrivate: false,
    ...overrides,
  };
}

function request(url: string) {
  return new NextRequest(`http://localhost/api/commit-history?repoId=repo-demo-test${url}`);
}

describe('GET /api/commit-history', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubEnv('GITHUB_TOKEN', 'must-not-be-used-for-commit-history');
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
  });

  it('refuses private repositories before making a GitHub request', async () => {
    getRepositoryGraph.mockReturnValue(makeGraph({ githubIsPrivate: true }));
    const fetchSpy = vi.spyOn(globalThis, 'fetch');

    const response = await GET(request(''));

    expect(response.status).toBe(403);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('requires old or unverified graphs to be re-indexed before history is available', async () => {
    const { githubIsPrivate: _ignored, ...legacyGraph } = makeGraph();
    getRepositoryGraph.mockReturnValue(legacyGraph);
    const fetchSpy = vi.spyOn(globalThis, 'fetch');

    const response = await GET(request(''));

    expect(response.status).toBe(403);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('uses unauthenticated public commit requests and respects GitHub pagination links', async () => {
    getRepositoryGraph.mockReturnValue(makeGraph());
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify([
      {
        sha: 'a'.repeat(40),
        html_url: 'https://github.com/example/public-repo/commit/aaaaaaaa',
        commit: {
          message: 'Add a feature',
          author: { name: 'Author', email: 'author@example.com', date: '2026-11-21T12:00:00Z' },
          committer: { name: 'Committer', date: '2026-11-21T12:01:00Z' },
        },
        author: { login: 'author-login' },
        committer: { login: 'committer-login' },
        parents: [{ sha: 'b'.repeat(40) }],
      },
    ]), {
      status: 200,
      headers: { link: '<https://api.github.com/next-page>; rel="next"' },
    }));

    const response = await GET(request('&page=1'));
    const payload = await response.json();
    const options = fetchSpy.mock.calls[0][1] as RequestInit & { next?: { revalidate?: number } };
    const headers = options.headers as Record<string, string>;

    expect(response.status).toBe(200);
    expect(payload.hasMore).toBe(true);
    expect(payload.commits[0].author).toBe('author-login');
    expect(payload.commits[0].committer).toBe('committer-login');
    expect(headers.Authorization).toBeUndefined();
    expect(options.next?.revalidate).toBe(60);
    expect(String(fetchSpy.mock.calls[0][0])).toContain('sha=trunk');
  });

  it('counts changed files uniquely and discloses current-graph effect scope', async () => {
    getRepositoryGraph.mockReturnValue(makeGraph({
      nodes: [
        { id: 'file-a', label: 'a.ts', type: 'file', filePath: 'src/a.ts' },
        { id: 'function-a', label: 'run', type: 'function', filePath: 'src/a.ts' },
        { id: 'function-b', label: 'consume', type: 'function', filePath: 'src/b.ts' },
        { id: 'file-b', label: 'b.ts', type: 'file', filePath: 'src/b.ts' },
      ],
      edges: [
        { id: 'edge-import', source: 'function-a', target: 'function-b', type: 'imports' },
      ],
    }));
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      sha: 'a'.repeat(40),
      html_url: 'https://github.com/example/public-repo/commit/aaaaaaaa',
      commit: {
        message: 'Change run',
        author: { name: 'Author', date: '2026-11-21T12:00:00Z' },
        committer: { name: 'Committer', date: '2026-11-21T12:01:00Z' },
        verification: { verified: false, reason: 'unsigned' },
      },
      author: null,
      committer: null,
      parents: [{ sha: 'b'.repeat(40) }],
      stats: { additions: 2, deletions: 1, total: 3 },
      files: [{ filename: 'src/a.ts', status: 'modified', additions: 2, deletions: 1, changes: 3, patch: '@@ -1 +1 @@' }],
    }), { status: 200 }));

    const response = await GET(request(`&sha=${'a'.repeat(40)}`));
    const payload = await response.json();

    expect(response.status).toBe(200);
    expect(payload.commit.analysisCoverage.indexedFilesMatched).toBe(1);
    expect(payload.commit.analysisCoverage.indexedFiles).toBe(2);
    expect(payload.commit.analysisCoverage.scope).toContain('currently indexed snapshot');
    expect(payload.commit.possibleEffects).toEqual([expect.objectContaining({
      label: 'consume',
      relationships: ['imports'],
    })]);
  });
});
