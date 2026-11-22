import { NextRequest, NextResponse } from 'next/server';
import { getRepositoryGraph } from '@/lib/graph/graph-store';
import type { GraphEdge, GraphNode, KnowledgeGraph } from '@/types/graph';

const GITHUB_API = 'https://api.github.com';
const MAX_PAGE = 1_000;
const MAX_PATCH_PER_FILE = 16_000;
const MAX_PATCH_RESPONSE = 512_000;
const GITHUB_CACHE_SECONDS = 60;

type JsonObject = Record<string, unknown>;

interface GitHubUser {
  login?: string;
  avatar_url?: string;
  html_url?: string;
}

interface GitIdentity {
  name?: string;
  email?: string;
  date?: string;
}

interface GitHubCommitListItem {
  sha: string;
  html_url: string;
  commit: {
    message: string;
    author?: GitIdentity | null;
    committer?: GitIdentity | null;
  };
  author?: GitHubUser | null;
  committer?: GitHubUser | null;
  parents?: Array<{ sha: string }>;
}

function isObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isCommitListItem(value: unknown): value is GitHubCommitListItem {
  if (!isObject(value) || !isObject(value.commit)) return false;
  return typeof value.sha === 'string'
    && /^[a-f0-9]{40}$/i.test(value.sha)
    && typeof value.html_url === 'string'
    && typeof value.commit.message === 'string';
}

function nonEmptyString(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value : null;
}

function repositoryCoordinates(repoName: string): { owner: string; name: string } | null {
  const match = /^([A-Za-z0-9-]+)\/([A-Za-z0-9._-]+)$/.exec(repoName.trim());
  if (!match) return null;
  const name = match[2].replace(/\.git$/i, '');
  return name ? { owner: match[1], name } : null;
}

function githubHeaders(): HeadersInit {
  // This endpoint intentionally supports public repositories only. A global
  // server token here could expose any private repo registered in the graph.
  return {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'CodeWhy-Intelligence-Platform',
  };
}

function normalizeRepoPath(filePath: string): string {
  return filePath.replace(/\\/g, '/').replace(/^(\.\/|\/)+/, '');
}

function isFileNode(node: GraphNode): boolean {
  return node.type === 'file' || node.type === 'test' || node.type === 'config';
}

function buildPossibleEffects(graph: KnowledgeGraph, changedPaths: Set<string>) {
  const normalizedPaths = new Set([...changedPaths].map(normalizeRepoPath));
  const touchedNodes = graph.nodes.filter((node) => normalizedPaths.has(normalizeRepoPath(node.filePath)));
  const touchedIds = new Set(touchedNodes.map((node) => node.id));
  const edgesByNeighbor = new Map<string, GraphEdge[]>();

  for (const edge of graph.edges) {
    const sourceChanged = touchedIds.has(edge.source);
    const targetChanged = touchedIds.has(edge.target);
    if (sourceChanged === targetChanged) continue;
    const neighborId = sourceChanged ? edge.target : edge.source;
    if (!edgesByNeighbor.has(neighborId)) edgesByNeighbor.set(neighborId, []);
    edgesByNeighbor.get(neighborId)!.push(edge);
  }

  const nodesById = new Map(graph.nodes.map((node) => [node.id, node]));
  const effectCandidates: Array<{
    id: string;
    label: string;
    filePath: string;
    relationships: string[];
    evidenceBasis: string;
  }> = [];
  for (const [id, edges] of edgesByNeighbor) {
    const node = nodesById.get(id);
    if (node && node.type !== 'commit') {
      effectCandidates.push({
        id: node.id,
        label: node.label,
        filePath: node.filePath,
        relationships: [...new Set(edges.map((edge) => edge.type))],
        evidenceBasis: edges.some((edge) => edge.type === 'co_changed')
          ? 'Includes historical co-change association'
          : 'Indexed graph relationship',
      });
    }
  }
  const effects = effectCandidates.slice(0, 30);

  const indexedPaths = new Set(graph.nodes.filter(isFileNode).map((node) => normalizeRepoPath(node.filePath)));
  const matchedChangedPaths = [...normalizedPaths].filter((path) => indexedPaths.has(path));

  return {
    touchedNodes,
    effects,
    possibleEffectsTruncated: effectCandidates.length > effects.length,
    indexedFilesMatched: matchedChangedPaths.length,
    indexedFileCount: indexedPaths.size,
  };
}

function mapCommitListItem(item: GitHubCommitListItem) {
  return {
    sha: item.sha,
    shortSha: item.sha.slice(0, 7),
    message: item.commit.message || 'Commit',
    author: item.author?.login || item.commit.author?.name || 'Unknown author',
    authorEmail: item.commit.author?.email || null,
    committer: item.committer?.login || item.commit.committer?.name || 'Unknown committer',
    committedAt: item.commit.committer?.date || null,
    avatarUrl: item.author?.avatar_url || null,
    authoredAt: item.commit.author?.date || null,
    url: item.html_url,
    parents: Array.isArray(item.parents) ? item.parents.length : 0,
  };
}

export async function GET(request: NextRequest) {
  const params = request.nextUrl.searchParams;
  const repoId = params.get('repoId')?.trim() || request.cookies.get('codewhy_active_repo_id')?.value;
  const graph = repoId ? getRepositoryGraph(repoId) : undefined;
  if (!graph) return NextResponse.json({ error: 'Select an analyzed repository first.' }, { status: 404 });
  if (graph.isDemo) return NextResponse.json({ error: 'Demo data has no real GitHub history. Connect a GitHub repository first.' }, { status: 422 });
  if (graph.githubIsPrivate !== false) {
    return NextResponse.json({ error: graph.githubIsPrivate ? 'Private repository history is disabled until account-scoped GitHub authentication is implemented.' : 'Re-index this repository from its public GitHub URL to enable verified commit history.' }, { status: 403 });
  }

  const coordinates = repositoryCoordinates(graph.repoName);
  if (!coordinates) return NextResponse.json({ error: 'This repository is not linked to a GitHub owner/name. Re-index it from its GitHub URL.' }, { status: 422 });

  const base = `${GITHUB_API}/repos/${encodeURIComponent(coordinates.owner)}/${encodeURIComponent(coordinates.name)}`;
  const sha = params.get('sha');
  try {
    if (sha) {
      if (!/^[a-f0-9]{7,40}$/i.test(sha)) return NextResponse.json({ error: 'Invalid commit hash.' }, { status: 400 });
      const response = await fetch(`${base}/commits/${encodeURIComponent(sha)}`, {
        headers: githubHeaders(),
        cache: 'force-cache',
        next: { revalidate: GITHUB_CACHE_SECONDS },
        signal: AbortSignal.timeout(12_000),
      });
      if (!response.ok) return githubError(response.status);

      const payload: unknown = await response.json();
      if (!isObject(payload) || !isObject(payload.commit) || typeof payload.sha !== 'string' || !isObject(payload.commit.author) && payload.commit.author !== null && payload.commit.author !== undefined) {
        return NextResponse.json({ error: 'GitHub returned an invalid commit response.' }, { status: 502 });
      }

      let patchBudget = MAX_PATCH_RESPONSE;
      const rawFiles = Array.isArray(payload.files) ? payload.files : [];
      const files = rawFiles.filter((file): file is JsonObject => isObject(file) && typeof file.filename === 'string').map((file) => {
        const rawPatch = nonEmptyString(file.patch);
        const allowedLength = rawPatch ? Math.min(rawPatch.length, MAX_PATCH_PER_FILE, patchBudget) : 0;
        const patch = rawPatch && allowedLength > 0 ? rawPatch.slice(0, allowedLength) : null;
        patchBudget -= allowedLength;
        return {
          path: file.filename as string,
          previousPath: nonEmptyString(file.previous_filename),
          status: nonEmptyString(file.status) || 'modified',
          additions: typeof file.additions === 'number' ? file.additions : 0,
          deletions: typeof file.deletions === 'number' ? file.deletions : 0,
          changes: typeof file.changes === 'number' ? file.changes : 0,
          patch,
          truncated: Boolean(rawPatch && patch && rawPatch.length > patch.length),
          patchUnavailableReason: rawPatch && !patch ? 'response_limit' as const : !rawPatch ? 'not_provided' as const : null,
          blobUrl: nonEmptyString(file.blob_url),
        };
      });

      const changedPaths = new Set<string>();
      for (const file of files) {
        changedPaths.add(file.path);
        if (file.previousPath) changedPaths.add(file.previousPath);
      }
      const analysis = buildPossibleEffects(graph, changedPaths);
      const githubAuthor = isObject(payload.author) ? payload.author as GitHubUser : null;
      const githubCommitter = isObject(payload.committer) ? payload.committer as GitHubUser : null;
      const gitAuthor = isObject(payload.commit.author) ? payload.commit.author as GitIdentity : null;
      const gitCommitter = isObject(payload.commit.committer) ? payload.commit.committer as GitIdentity : null;
      const stats = isObject(payload.stats) ? payload.stats : {};
      const verification = isObject(payload.commit.verification) ? payload.commit.verification : {};
      const parents = Array.isArray(payload.parents)
        ? payload.parents.filter((parent): parent is JsonObject => isObject(parent) && typeof parent.sha === 'string').map((parent) => parent.sha as string)
        : [];

      return NextResponse.json({
        commit: {
          sha: payload.sha,
          message: typeof payload.commit.message === 'string' ? payload.commit.message : '',
          author: githubAuthor?.login || gitAuthor?.name || 'Unknown author',
          authorEmail: gitAuthor?.email || null,
          authorUrl: githubAuthor?.html_url || null,
          committer: githubCommitter?.login || gitCommitter?.name || 'Unknown committer',
          committerEmail: gitCommitter?.email || null,
          committerUrl: githubCommitter?.html_url || null,
          avatarUrl: githubAuthor?.avatar_url || null,
          authoredAt: gitAuthor?.date || null,
          committedAt: gitCommitter?.date || null,
          url: nonEmptyString(payload.html_url),
          repositoryUrl: `https://github.com/${coordinates.owner}/${coordinates.name}`,
          parents,
          verified: verification.verified === true,
          verificationReason: nonEmptyString(verification.reason),
          stats: {
            additions: typeof stats.additions === 'number' ? stats.additions : 0,
            deletions: typeof stats.deletions === 'number' ? stats.deletions : 0,
            total: typeof stats.total === 'number' ? stats.total : 0,
          },
          files,
          possibleEffects: analysis.effects,
          analysisCoverage: {
            indexedFilesMatched: analysis.indexedFilesMatched,
            changedFiles: files.length,
            indexedFiles: analysis.indexedFileCount,
            possibleEffectsTruncated: analysis.possibleEffectsTruncated,
            graphUpdatedAt: graph.updatedAt,
            graphCommitSha: graph.commitSha || null,
            scope: 'Effects are graph links from the currently indexed snapshot; they do not prove historical or runtime causation.',
          },
        },
      });
    }

    const rawPage = Number(params.get('page'));
    const page = Number.isInteger(rawPage) && rawPage > 0 ? Math.min(MAX_PAGE, rawPage) : 1;
    const response = await fetch(
      `${base}/commits?per_page=20&page=${page}${graph.branch ? `&sha=${encodeURIComponent(graph.branch)}` : ''}`,
      {
        headers: githubHeaders(),
        cache: 'force-cache',
        next: { revalidate: GITHUB_CACHE_SECONDS },
        signal: AbortSignal.timeout(12_000),
      },
    );
    if (!response.ok) return githubError(response.status);

    const payload: unknown = await response.json();
    if (!Array.isArray(payload) || !payload.every(isCommitListItem)) {
      return NextResponse.json({ error: 'GitHub returned an invalid commit list.' }, { status: 502 });
    }

    const hasMore = /rel="next"/.test(response.headers.get('link') || '');
    return NextResponse.json({
      repoId: graph.repoId,
      repoName: graph.repoName,
      branch: graph.branch || null,
      commits: payload.map(mapCommitListItem),
      page,
      hasMore,
    });
  } catch (error) {
    if (error instanceof Error && error.name === 'TimeoutError') {
      return NextResponse.json({ error: 'GitHub took too long to respond. Try again.' }, { status: 504 });
    }
    return NextResponse.json({ error: 'GitHub could not be reached. Check the connection and try again.' }, { status: 502 });
  }
}

function githubError(status: number) {
  if (status === 404) return NextResponse.json({ error: 'Repository or commit was not found. Private repositories are not enabled in this unauthenticated feature.' }, { status: 404 });
  if (status === 403 || status === 429) return NextResponse.json({ error: 'GitHub rate limit or public access restriction reached. Try again later.' }, { status: 429 });
  return NextResponse.json({ error: `GitHub returned an error (${status}).` }, { status: 502 });
}
