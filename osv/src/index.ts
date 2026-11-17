import {
  VULNERABILITY_CONTRACT_VERSION,
  type FeedAdapter,
  type FeedRecord,
  type VulnerabilityAdvisory,
} from "@absolutejs/vulnerabilities";

export const OSV_API_URL = "https://api.osv.dev/v1";

export type OsvPackageQuery = {
  ecosystem?: string;
  name?: string;
  purl?: string;
};

export type OsvQuery = {
  commit?: string;
  package?: OsvPackageQuery;
  version?: string;
};

export type OsvNormalizeOptions = {
  fetchedAt: string;
  sourceName?: string;
  sourceUrl?: (id: string) => string;
};

export type OsvFetch = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;

type JsonObject = Record<string, unknown>;

const object = (value: unknown, label: string): JsonObject => {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new Error(`${label} must be an object`);
  return value as JsonObject;
};

const text = (value: unknown, label: string) => {
  if (typeof value !== "string" || value.trim().length === 0)
    throw new Error(`${label} must be a non-empty string`);
  return value.trim();
};

const optionalText = (value: unknown) =>
  typeof value === "string" && value.trim().length > 0 ? value.trim() : null;

const timestamp = (value: unknown, label: string) => {
  const result = text(value, label);
  if (!Number.isFinite(Date.parse(result)))
    throw new Error(`${label} must be a valid timestamp`);
  return result;
};

const stringArray = (value: unknown) =>
  Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];

const unique = (values: readonly string[]) => [
  ...new Set(values.map((value) => value.trim()).filter(Boolean)),
];

const severitySystem = (
  value: string,
): VulnerabilityAdvisory["severity"][number]["system"] => {
  if (value === "CVSS_V2") return "cvss-v2";
  if (value === "CVSS_V3") return "cvss-v3";
  if (value === "CVSS_V4") return "cvss-v4";
  return value.length > 0 ? "vendor" : "unknown";
};

const severityValue = (
  value: string,
): VulnerabilityAdvisory["severity"][number]["value"] => {
  const normalized = value.toLowerCase();
  if (
    normalized === "critical" ||
    normalized === "high" ||
    normalized === "medium" ||
    normalized === "low" ||
    normalized === "negligible"
  )
    return normalized;
  return "unknown";
};

const normalizeSeverity = (
  value: unknown,
): VulnerabilityAdvisory["severity"] => {
  if (!Array.isArray(value)) return [];
  return value.flatMap((entry) => {
    const severity = object(entry, "OSV severity");
    const type = optionalText(severity.type);
    const score = optionalText(severity.score);
    if (type === null || score === null) return [];
    return [
      {
        score: null,
        system: severitySystem(type.toUpperCase()),
        value: severityValue(score),
        vector: score,
      },
    ];
  });
};

const databaseSeverity = (advisory: JsonObject) => {
  if (
    typeof advisory.database_specific !== "object" ||
    advisory.database_specific === null ||
    Array.isArray(advisory.database_specific)
  )
    return [];
  const severity = optionalText(
    (advisory.database_specific as JsonObject).severity,
  );
  if (severity === null) return [];

  return [
    {
      score: null,
      system: "vendor" as const,
      value: severityValue(severity),
      vector: severity,
    },
  ];
};

const normalizeAffected = (
  value: unknown,
): NonNullable<VulnerabilityAdvisory["affected"]> => {
  if (!Array.isArray(value)) return [];
  return value.map((entry) => {
    const affected = object(entry, "OSV affected entry");
    const packageValue = object(affected.package, "OSV affected package");
    const ecosystem = text(
      packageValue.ecosystem,
      "OSV affected package ecosystem",
    );
    const name = text(packageValue.name, "OSV affected package name");
    const ranges = Array.isArray(affected.ranges)
      ? affected.ranges.flatMap((entry) => {
          const range = object(entry, "OSV affected range");
          const rawType = optionalText(range.type)?.toLowerCase();
          if (
            rawType !== "ecosystem" &&
            rawType !== "git" &&
            rawType !== "semver"
          )
            return [];
          const events = Array.isArray(range.events)
            ? range.events.flatMap((entry) => {
                const event = object(entry, "OSV range event");
                const normalized = {
                  ...(optionalText(event.fixed)
                    ? { fixed: optionalText(event.fixed) ?? undefined }
                    : {}),
                  ...(optionalText(event.introduced)
                    ? {
                        introduced: optionalText(event.introduced) ?? undefined,
                      }
                    : {}),
                  ...(optionalText(event.last_affected)
                    ? {
                        lastAffected:
                          optionalText(event.last_affected) ?? undefined,
                      }
                    : {}),
                  ...(optionalText(event.limit)
                    ? { limit: optionalText(event.limit) ?? undefined }
                    : {}),
                };
                return Object.keys(normalized).length > 0 ? [normalized] : [];
              })
            : [];
          const type: "ecosystem" | "git" | "semver" = rawType;
          return [
            {
              events,
              repository: optionalText(range.repo),
              type,
            },
          ];
        })
      : [];
    return {
      package: {
        ecosystem,
        name,
        purl: optionalText(packageValue.purl),
      },
      ranges,
      versions: unique(stringArray(affected.versions)),
    };
  });
};

export const normalizeOsvAdvisory = (
  input: unknown,
  options: OsvNormalizeOptions,
): VulnerabilityAdvisory => {
  const advisory = object(input, "OSV advisory");
  const id = text(advisory.id, "OSV advisory id");
  const modifiedAt = timestamp(advisory.modified, "OSV advisory modified");
  const sourceUrl =
    options.sourceUrl?.(id) ?? `${OSV_API_URL}/vulns/${encodeURIComponent(id)}`;
  return {
    affected: normalizeAffected(advisory.affected),
    aliases: unique([
      id,
      ...stringArray(advisory.aliases),
      ...stringArray(advisory.upstream),
    ]),
    contract: VULNERABILITY_CONTRACT_VERSION,
    details: optionalText(advisory.details),
    id,
    modifiedAt,
    publishedAt: advisory.published
      ? timestamp(advisory.published, "OSV advisory published")
      : null,
    severity: [
      ...normalizeSeverity(advisory.severity),
      ...databaseSeverity(advisory),
    ],
    source: {
      fetchedAt: timestamp(options.fetchedAt, "OSV fetchedAt"),
      name: options.sourceName ?? "osv",
      revision: optionalText(advisory.schema_version),
      url: sourceUrl,
    },
    summary: optionalText(advisory.summary) ?? id,
    withdrawnAt: advisory.withdrawn
      ? timestamp(advisory.withdrawn, "OSV advisory withdrawn")
      : null,
  };
};

const queryKey = (query: OsvQuery) => JSON.stringify(query);

/* Answers that mean "try again shortly": rate limiting and the gateway or
 * server failing for a moment. A refresh fetches hundreds of advisories
 * one by one, so without retrying, one 504 among them failed the whole
 * refresh. */
const TRANSIENT_STATUSES = new Set([429, 500, 502, 503, 504]);
const DEFAULT_ATTEMPTS = 4;
const DEFAULT_BACKOFF_MS = 1000;
const MAX_RETRY_AFTER_MS = 30_000;

const waitFor = (ms: number, signal: AbortSignal | undefined) =>
  new Promise<void>((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason);
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(signal?.reason);
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });

/* How long OSV asked us to wait, when it said (seconds form only). */
const retryAfterMs = (response: Response) => {
  const header = response.headers.get("retry-after");
  const seconds = header === null ? Number.NaN : Number(header);
  return Number.isFinite(seconds) && seconds >= 0
    ? Math.min(seconds * 1000, MAX_RETRY_AFTER_MS)
    : null;
};

/**
 * One OSV request, tried again on a transient answer or a dropped
 * connection with doubling waits. A definite answer (200, 400, 404) is
 * returned at once, and an abort is never retried.
 */
const fetchWithRetry = async (
  fetcher: OsvFetch,
  input: string,
  init: RequestInit,
  retry: { attempts: number; backoffMs: number },
) => {
  for (let attempt = 1; ; attempt += 1) {
    const last = attempt >= retry.attempts;
    const backoff = retry.backoffMs * 2 ** (attempt - 1);
    let response: Response;
    try {
      response = await fetcher(input, init);
    } catch (error) {
      if (init.signal?.aborted || last) throw error;
      await waitFor(backoff, init.signal ?? undefined);
      continue;
    }
    if (!TRANSIENT_STATUSES.has(response.status) || last) return response;
    await response.body?.cancel();
    await waitFor(retryAfterMs(response) ?? backoff, init.signal ?? undefined);
  }
};

export const createOsvAdapter = (options: {
  apiUrl?: string;
  fetch?: OsvFetch;
  queries: readonly OsvQuery[];
  /* Tries per request (default 4) and the first wait between them, which
   * doubles each time (default 1 s). */
  retry?: { attempts?: number; backoffMs?: number };
}): FeedAdapter<VulnerabilityAdvisory> => {
  if (options.queries.length === 0)
    throw new Error("At least one OSV query is required");
  const apiUrl = (options.apiUrl ?? OSV_API_URL).replace(/\/$/, "");
  const rawFetcher = options.fetch ?? globalThis.fetch;
  const retry = {
    attempts: Math.max(1, options.retry?.attempts ?? DEFAULT_ATTEMPTS),
    backoffMs: Math.max(0, options.retry?.backoffMs ?? DEFAULT_BACKOFF_MS),
  };
  const fetcher = (input: string, init: RequestInit) =>
    fetchWithRetry(rawFetcher, input, init, retry);
  return {
    descriptor: {
      id: "osv",
      name: "Open Source Vulnerabilities",
      url: apiUrl,
    },
    fetch: async ({ signal }) => {
      const fetchedAt = new Date().toISOString();
      const ids = new Set<string>();
      const pending: Array<{ pageToken?: string; query: OsvQuery }> =
        options.queries.map((query) => ({ query }));
      const seenPages = new Set<string>();
      while (pending.length > 0) {
        const batch = pending.splice(0, 1000);
        const response = await fetcher(`${apiUrl}/querybatch`, {
          body: JSON.stringify({
            queries: batch.map(({ pageToken, query }) => ({
              ...query,
              ...(pageToken ? { page_token: pageToken } : {}),
            })),
          }),
          headers: { "content-type": "application/json" },
          method: "POST",
          signal,
        });
        if (!response.ok)
          throw new Error(`OSV querybatch failed with HTTP ${response.status}`);
        const payload = object(
          await response.json(),
          "OSV querybatch response",
        );
        if (
          !Array.isArray(payload.results) ||
          payload.results.length !== batch.length
        )
          throw new Error("OSV querybatch returned misaligned results");
        payload.results.forEach((entry, index) => {
          const result = object(entry, "OSV query result");
          if (Array.isArray(result.vulns))
            for (const item of result.vulns) {
              const vulnerability = object(item, "OSV query vulnerability");
              ids.add(text(vulnerability.id, "OSV vulnerability id"));
            }
          const pageToken = optionalText(result.next_page_token);
          const source = batch[index];
          if (pageToken && source) {
            const pageKey = `${queryKey(source.query)}:${pageToken}`;
            if (seenPages.has(pageKey))
              throw new Error("OSV querybatch repeated a pagination token");
            seenPages.add(pageKey);
            pending.push({ pageToken, query: source.query });
          }
        });
      }

      const records: FeedRecord<VulnerabilityAdvisory>[] = [];
      for (const id of [...ids].sort()) {
        const response = await fetcher(
          `${apiUrl}/vulns/${encodeURIComponent(id)}`,
          { signal },
        );
        if (!response.ok)
          throw new Error(
            `OSV advisory ${id} failed with HTTP ${response.status}`,
          );
        const value = normalizeOsvAdvisory(await response.json(), {
          fetchedAt,
        });
        records.push({ id: value.id, modifiedAt: value.modifiedAt, value });
      }
      const revision = records.reduce<string | null>(
        (latest, record) =>
          latest === null || Date.parse(record.modifiedAt) > Date.parse(latest)
            ? record.modifiedAt
            : latest,
        null,
      );
      return {
        cursor: { etag: null, lastModified: null, token: null },
        fetchedAt,
        records,
        replaceAll: true,
        revision,
        status: "updated",
      };
    },
  };
};
