'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import {
  AlertCircle,
  ArrowDown,
  ArrowUp,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  FileCode2,
  GitCommitHorizontal,
  GitFork,
  LoaderCircle,
  RefreshCw,
  ShieldCheck,
  UserRound,
} from 'lucide-react';
import { useActiveRepo } from '@/lib/repositories/active-repo-client';

interface CommitRow {
  sha: string;
  shortSha: string;
  message: string;
  author: string;
  authorEmail: string | null;
  committer: string;
  committedAt: string | null;
  avatarUrl: string | null;
  authoredAt: string | null;
  url: string;
  parents: number;
}

interface ChangedFile {
  path: string;
  previousPath: string | null;
  status: string;
  additions: number;
  deletions: number;
  changes: number;
  patch: string | null;
  truncated: boolean;
  patchUnavailableReason: 'response_limit' | 'not_provided' | null;
  blobUrl: string | null;
}

interface PossibleEffect {
  id: string;
  label: string;
  filePath: string;
  relationships: string[];
  evidenceBasis: string;
}

interface CommitDetail {
  sha: string;
  message: string;
  author: string;
  authorEmail: string | null;
  authorUrl: string | null;
  committer: string;
  committerEmail: string | null;
  committerUrl: string | null;
  avatarUrl: string | null;
  authoredAt: string | null;
  committedAt: string | null;
  url: string | null;
  repositoryUrl: string;
  parents: string[];
  verified: boolean;
  verificationReason: string | null;
  stats: { additions: number; deletions: number; total: number };
  files: ChangedFile[];
  possibleEffects: PossibleEffect[];
  analysisCoverage: {
    indexedFilesMatched: number;
    changedFiles: number;
    indexedFiles: number;
    possibleEffectsTruncated: boolean;
    graphUpdatedAt: string;
    graphCommitSha: string | null;
    scope: string;
  };
}

interface CommitListResponse {
  commits: CommitRow[];
  hasMore: boolean;
}

function dateLabel(value: string | null) {
  if (!value) return 'Date unavailable';
  const date = new Date(value);
  return Number.isNaN(date.valueOf())
    ? 'Date unavailable'
    : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isStringOrNull(value: unknown): value is string | null {
  return typeof value === 'string' || value === null;
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value);
}

function isCommitRow(value: unknown): value is CommitRow {
  if (!isRecord(value)) return false;
  return typeof value.sha === 'string'
    && typeof value.shortSha === 'string'
    && typeof value.message === 'string'
    && typeof value.author === 'string'
    && isStringOrNull(value.authorEmail)
    && typeof value.committer === 'string'
    && isStringOrNull(value.committedAt)
    && isStringOrNull(value.avatarUrl)
    && isStringOrNull(value.authoredAt)
    && typeof value.url === 'string'
    && isFiniteNumber(value.parents);
}

function isChangedFile(value: unknown): value is ChangedFile {
  if (!isRecord(value)) return false;
  return typeof value.path === 'string'
    && isStringOrNull(value.previousPath)
    && typeof value.status === 'string'
    && isFiniteNumber(value.additions)
    && isFiniteNumber(value.deletions)
    && isFiniteNumber(value.changes)
    && isStringOrNull(value.patch)
    && typeof value.truncated === 'boolean'
    && (value.patchUnavailableReason === 'response_limit' || value.patchUnavailableReason === 'not_provided' || value.patchUnavailableReason === null)
    && isStringOrNull(value.blobUrl);
}

function isPossibleEffect(value: unknown): value is PossibleEffect {
  if (!isRecord(value)) return false;
  return typeof value.id === 'string'
    && typeof value.label === 'string'
    && typeof value.filePath === 'string'
    && Array.isArray(value.relationships)
    && value.relationships.every((relationship) => typeof relationship === 'string')
    && typeof value.evidenceBasis === 'string';
}

function isCommitListResponse(value: unknown): value is CommitListResponse {
  return isRecord(value)
    && Array.isArray(value.commits)
    && typeof value.hasMore === 'boolean'
    && value.commits.every(isCommitRow);
}

function isCommitDetailResponse(value: unknown): value is { commit: CommitDetail } {
  if (!isRecord(value) || !isRecord(value.commit)) return false;
  const detail = value.commit;
  if (!isRecord(detail.stats) || !isRecord(detail.analysisCoverage)) return false;
  const coverage = detail.analysisCoverage;

  return typeof detail.sha === 'string'
    && typeof detail.message === 'string'
    && typeof detail.author === 'string'
    && isStringOrNull(detail.authorEmail)
    && isStringOrNull(detail.authorUrl)
    && typeof detail.committer === 'string'
    && isStringOrNull(detail.committerEmail)
    && isStringOrNull(detail.committerUrl)
    && isStringOrNull(detail.avatarUrl)
    && isStringOrNull(detail.authoredAt)
    && isStringOrNull(detail.committedAt)
    && isStringOrNull(detail.url)
    && typeof detail.repositoryUrl === 'string'
    && Array.isArray(detail.parents)
    && detail.parents.every((parent) => typeof parent === 'string')
    && typeof detail.verified === 'boolean'
    && isStringOrNull(detail.verificationReason)
    && isFiniteNumber(detail.stats.additions)
    && isFiniteNumber(detail.stats.deletions)
    && isFiniteNumber(detail.stats.total)
    && Array.isArray(detail.files)
    && detail.files.every(isChangedFile)
    && Array.isArray(detail.possibleEffects)
    && detail.possibleEffects.every(isPossibleEffect)
    && isFiniteNumber(coverage.indexedFilesMatched)
    && isFiniteNumber(coverage.changedFiles)
    && isFiniteNumber(coverage.indexedFiles)
    && typeof coverage.possibleEffectsTruncated === 'boolean'
    && typeof coverage.graphUpdatedAt === 'string'
    && isStringOrNull(coverage.graphCommitSha)
    && typeof coverage.scope === 'string';
}

export function CommitHistoryClient() {
  const { activeRepo, isLoading: isActiveRepoLoading } = useActiveRepo();
  const [commits, setCommits] = useState<CommitRow[]>([]);
  const [detail, setDetail] = useState<CommitDetail | null>(null);
  const [selectedSha, setSelectedSha] = useState<string | null>(null);
  const [expandedFile, setExpandedFile] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [hasMore, setHasMore] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const listRequest = useRef<AbortController | null>(null);
  const detailRequest = useRef<AbortController | null>(null);

  const loadDetail = useCallback(async (sha: string) => {
    detailRequest.current?.abort();
    const controller = new AbortController();
    detailRequest.current = controller;
    setSelectedSha(sha);
    setDetail(null);
    setLoadingDetail(true);
    setError(null);

    try {
      const response = await fetch(
        `/api/commit-history?repoId=${encodeURIComponent(activeRepo.repoId)}&sha=${encodeURIComponent(sha)}`,
        { cache: 'no-store', signal: controller.signal },
      );
      const payload: unknown = await response.json();
      if (!response.ok) {
        const message = typeof payload === 'object' && payload !== null
          ? (payload as Record<string, unknown>).error
          : null;
        throw new Error(typeof message === 'string' ? message : 'Commit details could not be loaded.');
      }
      if (!isCommitDetailResponse(payload)) throw new Error('The server returned invalid commit details.');
      if (!controller.signal.aborted && detailRequest.current === controller) {
        setDetail(payload.commit);
        setExpandedFile(payload.commit.files[0]?.path ?? null);
      }
    } catch (cause) {
      if (controller.signal.aborted) return;
      setError(cause instanceof Error ? cause.message : 'Commit details could not be loaded.');
    } finally {
      if (detailRequest.current === controller) setLoadingDetail(false);
    }
  }, [activeRepo.repoId]);

  const loadPage = useCallback(async (nextPage = 1, append = false) => {
    listRequest.current?.abort();
    const controller = new AbortController();
    listRequest.current = controller;
    setLoading(true);
    setError(null);

    if (!append) {
      detailRequest.current?.abort();
      setDetail(null);
      setSelectedSha(null);
      setLoadingDetail(false);
    }

    try {
      const response = await fetch(
        `/api/commit-history?repoId=${encodeURIComponent(activeRepo.repoId)}&page=${nextPage}`,
        { cache: 'no-store', signal: controller.signal },
      );
      const payload: unknown = await response.json();
      if (!response.ok) {
        const message = typeof payload === 'object' && payload !== null
          ? (payload as Record<string, unknown>).error
          : null;
        throw new Error(typeof message === 'string' ? message : 'Commit history could not be loaded.');
      }
      if (!isCommitListResponse(payload)) throw new Error('The server returned an invalid commit list.');
      if (controller.signal.aborted || listRequest.current !== controller) return;

      setCommits((current) => append ? [...current, ...payload.commits] : payload.commits);
      setHasMore(payload.hasMore);
      setPage(nextPage);
      if (!append && payload.commits[0]) void loadDetail(payload.commits[0].sha);
    } catch (cause) {
      if (controller.signal.aborted) return;
      setError(cause instanceof Error ? cause.message : 'Commit history could not be loaded.');
      if (!append) {
        setCommits([]);
        setDetail(null);
      }
    } finally {
      if (listRequest.current === controller) setLoading(false);
    }
  }, [activeRepo.repoId, loadDetail]);

  useEffect(() => {
    if (isActiveRepoLoading) return;
    setCommits([]);
    setDetail(null);
    setSelectedSha(null);
    setPage(1);
    setHasMore(false);
    void loadPage(1);
    return () => {
      listRequest.current?.abort();
      detailRequest.current?.abort();
    };
  }, [activeRepo.repoId, isActiveRepoLoading, loadPage]);

  const normalizedQuery = query.trim().toLowerCase();
  const visible = commits.filter((commit) =>
    `${commit.message} ${commit.author} ${commit.committer} ${commit.sha}`.toLowerCase().includes(normalizedQuery),
  );

  return (
    <main className="mx-auto max-w-7xl space-y-6 pb-12">
      <header className="overflow-hidden rounded-3xl bg-gradient-to-r from-indigo-700 via-blue-700 to-cyan-700 px-7 py-7 text-white shadow-lg">
        <div className="flex flex-col justify-between gap-5 md:flex-row md:items-center">
          <div className="flex items-center gap-4">
            <div className="grid h-14 w-14 place-items-center rounded-2xl border border-white/20 bg-white/15">
              <GitCommitHorizontal className="h-7 w-7" />
            </div>
            <div>
              <h1 className="text-2xl font-extrabold">Commit History</h1>
              <p className="mt-1 max-w-3xl text-sm text-blue-100">
                Inspect commit messages, authors, dates, file patches, and graph-linked review hints.
              </p>
            </div>
          </div>
          <div className="rounded-xl border border-white/20 bg-white/10 px-4 py-2 text-sm font-semibold">
            {activeRepo.repoName}
          </div>
        </div>
      </header>

      {error && (
        <div role="alert" className="flex items-start gap-3 rounded-xl border border-rose-200 bg-rose-50 p-4 text-sm text-rose-800">
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <div className="grid gap-5 xl:grid-cols-[0.85fr_1.6fr]">
        <section className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
          <div className="border-b border-slate-100 p-4">
            <div className="flex items-center justify-between">
              <h2 className="font-bold text-slate-900">Recent commits</h2>
              <button type="button" onClick={() => void loadPage(1)} aria-label="Refresh commits" className="rounded-lg p-2 text-slate-500 hover:bg-slate-100">
                <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
              </button>
            </div>
            <label className="sr-only" htmlFor="commit-history-search">Search loaded commits</label>
            <input
              id="commit-history-search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search loaded commits"
              className="mt-3 w-full rounded-xl border border-slate-200 px-3 py-2 text-sm text-slate-800 outline-none focus:border-blue-500"
            />
            <p className="mt-1 text-[11px] text-slate-500">GitHub results cache for up to about a minute. Search covers commits loaded so far; load older commits to expand it.</p>
          </div>
          <div className="max-h-[68vh] overflow-y-auto">
            {loading && commits.length === 0 ? (
              <div className="flex items-center gap-2 p-6 text-sm text-slate-500">
                <LoaderCircle className="h-4 w-4 animate-spin" />Loading GitHub history…
              </div>
            ) : visible.map((commit) => (
              <button
                key={commit.sha}
                type="button"
                aria-current={selectedSha === commit.sha ? 'true' : undefined}
                onClick={() => void loadDetail(commit.sha)}
                className={`block w-full border-b border-slate-100 p-4 text-left transition hover:bg-blue-50 ${selectedSha === commit.sha ? 'bg-blue-50 ring-inset ring-2 ring-blue-200' : ''}`}
              >
                <span className="line-clamp-2 text-sm font-semibold leading-5 text-slate-900">{commit.message.split('\n')[0]}</span>
                <span className="mt-2 flex items-center gap-2 text-xs text-slate-500">
                  <UserRound className="h-3.5 w-3.5" />{commit.author}
                  <span className="ml-auto font-mono text-blue-700">{commit.shortSha}</span>
                </span>
                <span className="mt-1 block text-[11px] text-slate-400">{dateLabel(commit.authoredAt)}</span>
              </button>
            ))}
            {!loading && visible.length === 0 && (
              <p className="p-6 text-sm text-slate-500">{commits.length ? 'No loaded commits match this search.' : 'No commits found.'}</p>
            )}
          </div>
          <div className="border-t border-slate-100 p-3">
            {hasMore && (
              <button type="button" disabled={loading} onClick={() => void loadPage(page + 1, true)} className="w-full rounded-lg bg-slate-50 px-3 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-100 disabled:opacity-50">
                Load older commits
              </button>
            )}
          </div>
        </section>

        <section className="min-w-0 space-y-4">
          {loadingDetail && (
            <div role="status" className="flex items-center justify-center gap-2 rounded-2xl border border-slate-200 bg-white p-12 text-slate-500">
              <LoaderCircle className="h-5 w-5 animate-spin" />Loading selected commit…
            </div>
          )}
          {!detail && !loadingDetail && commits.length > 0 && !error && (
            <div className="rounded-2xl border border-slate-200 bg-white p-8 text-sm text-slate-500">Select a commit to inspect its details.</div>
          )}

          {detail && (
            <>
              <article className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div className="min-w-0">
                    <p className="text-xs font-bold uppercase tracking-wide text-blue-700">Commit details</p>
                    <h2 className="mt-2 break-words text-lg font-bold text-slate-900">{detail.message.split('\n')[0]}</h2>
                    {detail.message.split('\n').slice(1).join('\n').trim() && (
                      <p className="mt-2 whitespace-pre-wrap text-sm text-slate-600">{detail.message.split('\n').slice(1).join('\n').trim()}</p>
                    )}
                  </div>
                  {detail.url && (
                    <a href={detail.url} target="_blank" rel="noopener noreferrer" className="inline-flex shrink-0 items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-2 text-xs font-semibold text-blue-700 hover:bg-blue-50">
                      Open on GitHub <ExternalLink className="h-3.5 w-3.5" />
                    </a>
                  )}
                </div>

                <div className="mt-5 grid gap-3 md:grid-cols-3">
                  <div className="flex items-center gap-3 rounded-xl bg-slate-50 p-3">
                    {detail.avatarUrl ? <img src={detail.avatarUrl} alt="" className="h-9 w-9 rounded-full" /> : <UserRound className="h-8 w-8 rounded-full bg-white p-1.5 text-slate-500" />}
                    <div className="min-w-0">
                      <p className="text-xs text-slate-500">Author</p>
                      {detail.authorUrl ? <a href={detail.authorUrl} target="_blank" rel="noopener noreferrer" className="block truncate text-sm font-semibold text-blue-700 hover:underline">{detail.author}</a> : <p className="truncate text-sm font-semibold text-slate-900">{detail.author}</p>}
                      {detail.authorEmail && <p className="truncate text-xs text-slate-500">{detail.authorEmail}</p>}
                      <p className="mt-1 text-[11px] text-slate-500">Authored {dateLabel(detail.authoredAt)}</p>
                    </div>
                  </div>
                  <div className="rounded-xl bg-slate-50 p-3">
                    <p className="text-xs text-slate-500">Committer</p>
                    {detail.committerUrl ? <a href={detail.committerUrl} target="_blank" rel="noopener noreferrer" className="block truncate text-sm font-semibold text-blue-700 hover:underline">{detail.committer}</a> : <p className="truncate text-sm font-semibold text-slate-900">{detail.committer}</p>}
                    {detail.committerEmail && <p className="truncate text-xs text-slate-500">{detail.committerEmail}</p>}
                    <p className="mt-1 text-[11px] text-slate-500">Committed {dateLabel(detail.committedAt)}</p>
                  </div>
                  <div className="rounded-xl bg-slate-50 p-3">
                    <p className="text-xs text-slate-500">Commit identity</p>
                    <p className="mt-1 break-all font-mono text-xs text-slate-800">{detail.sha}</p>
                    <p className="mt-2 flex items-center gap-1 text-[11px] text-slate-600">
                      {detail.verified && <ShieldCheck className="h-3.5 w-3.5 text-emerald-700" />}
                      {detail.verified ? 'GitHub signature verified' : `Signature not verified${detail.verificationReason ? ` · ${detail.verificationReason}` : ''}`}
                    </p>
                  </div>
                </div>

                <div className="mt-4 flex flex-wrap items-center gap-2 text-xs">
                  <span className="flex items-center gap-1 rounded-lg bg-emerald-50 px-2.5 py-1.5 text-emerald-800"><ArrowUp className="h-3.5 w-3.5" />{detail.stats.additions} added</span>
                  <span className="flex items-center gap-1 rounded-lg bg-rose-50 px-2.5 py-1.5 text-rose-800"><ArrowDown className="h-3.5 w-3.5" />{detail.stats.deletions} removed</span>
                  <span className="rounded-lg bg-slate-100 px-2.5 py-1.5 text-slate-700">{detail.files.length} files in GitHub response</span>
                  <span className="flex items-center gap-1 text-slate-500"><GitFork className="h-3.5 w-3.5" />{detail.parents.length} parent{detail.parents.length === 1 ? '' : 's'}</span>
                </div>
                {detail.parents.length > 0 && (
                  <p className="mt-3 text-xs text-slate-500">
                    Parent commits: {detail.parents.map((parent, index) => (
                      <span key={parent}>
                        <a href={`${detail.repositoryUrl}/commit/${encodeURIComponent(parent)}`} target="_blank" rel="noopener noreferrer" className="font-mono text-blue-700 hover:underline">{parent.slice(0, 12)}</a>
                        {index < detail.parents.length - 1 ? ', ' : ''}
                      </span>
                    ))}
                  </p>
                )}
              </article>

              <article className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
                <div className="flex items-center gap-2"><FileCode2 className="h-4 w-4 text-blue-700" /><h3 className="font-bold text-slate-900">Changed files and patches</h3></div>
                <p className="mt-1 text-xs text-slate-500">GitHub may omit patch text for binary files or changes that exceed its response limits.</p>
                <div className="mt-4 space-y-2">
                  {detail.files.map((file) => (
                    <div key={`${file.previousPath || ''}:${file.path}`} className="overflow-hidden rounded-xl border border-slate-200">
                      <button type="button" aria-expanded={expandedFile === file.path} onClick={() => setExpandedFile(expandedFile === file.path ? null : file.path)} className="flex w-full flex-wrap items-center gap-2 bg-slate-50 px-3 py-3 text-left">
                        <span className="font-mono text-xs font-semibold text-slate-800">{file.previousPath ? `${file.previousPath} → ` : ''}{file.path}</span>
                        <span className="rounded bg-white px-2 py-0.5 text-[10px] uppercase text-slate-500">{file.status}</span>
                        <span className="ml-auto text-xs text-emerald-700">+{file.additions}</span>
                        <span className="text-xs text-rose-700">−{file.deletions}</span>
                        {expandedFile === file.path ? <ChevronUp className="h-4 w-4 text-slate-400" /> : <ChevronDown className="h-4 w-4 text-slate-400" />}
                      </button>
                      {expandedFile === file.path && (
                        <div className="p-3">
                          {file.patch ? (
                            <pre className="max-h-96 overflow-auto rounded-lg bg-slate-950 p-3 font-mono text-[11px] leading-5 text-slate-100"><code>{file.patch}</code></pre>
                          ) : (
                            <p className="text-xs text-slate-500">{file.patchUnavailableReason === 'response_limit' ? 'Patch omitted to keep the response size bounded.' : 'GitHub did not provide a text patch for this file.'}</p>
                          )}
                          {file.truncated && <p className="mt-2 text-xs text-amber-700">Patch shortened to keep the response size bounded. Open the commit on GitHub for the complete diff.</p>}
                          {file.blobUrl && <a href={file.blobUrl} target="_blank" rel="noopener noreferrer" className="mt-2 inline-flex items-center gap-1 text-xs font-semibold text-blue-700 hover:underline">Open file on GitHub <ExternalLink className="h-3.5 w-3.5" /></a>}
                        </div>
                      )}
                    </div>
                  ))}
                  {detail.files.length === 0 && <p className="rounded-lg bg-slate-50 p-3 text-sm text-slate-600">GitHub returned no file list for this commit.</p>}
                </div>
              </article>

              <article className="rounded-2xl border border-amber-200 bg-amber-50 p-5">
                <h3 className="font-bold text-amber-950">Graph-linked review hints</h3>
                <p className="mt-1 text-xs leading-5 text-amber-900">These are relationships from the current indexed snapshot. They do not prove what the project did at the historical commit or establish runtime causation.</p>
                {detail.possibleEffects.length ? (
                  <ul className="mt-3 space-y-2">
                    {detail.possibleEffects.map((item) => (
                      <li key={item.id} className="rounded-lg border border-amber-200 bg-white/70 px-3 py-2 text-sm">
                        <span className="font-semibold text-slate-900">{item.label}</span>
                        <span className="mt-1 block font-mono text-xs text-slate-500">{item.filePath}</span>
                        <span className="mt-2 flex flex-wrap gap-1.5">
                          {item.relationships.map((relationship) => <span key={relationship} className="rounded bg-amber-100 px-1.5 py-0.5 text-[10px] text-amber-950">{relationship}</span>)}
                          <span className="rounded bg-slate-100 px-1.5 py-0.5 text-[10px] text-slate-700">{item.evidenceBasis}</span>
                        </span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="mt-3 rounded-lg bg-white/70 p-3 text-sm text-slate-700">No indexed graph relationship was found for the changed files.</p>
                )}
                {detail.analysisCoverage.possibleEffectsTruncated && <p className="mt-2 text-xs font-semibold text-amber-950">Showing the first 30 graph-linked review hints.</p>}
                <p className="mt-3 text-[11px] text-amber-950">
                  Changed-file coverage: {detail.analysisCoverage.indexedFilesMatched}/{detail.analysisCoverage.changedFiles} matched; {detail.analysisCoverage.indexedFiles} files are indexed. Graph indexed {dateLabel(detail.analysisCoverage.graphUpdatedAt)}{detail.analysisCoverage.graphCommitSha ? ` at ${detail.analysisCoverage.graphCommitSha.slice(0, 7)}` : ''}.
                </p>
              </article>
            </>
          )}
        </section>
      </div>
    </main>
  );
}
