import { lookup } from 'node:dns/promises';
import { request as httpsRequest } from 'node:https';
import { isIP } from 'node:net';

const nestedUrlDepthLimit = 4;
const nestedValueLengthLimit = 16 * 1024;
const embeddedNestedUrlLimit = 50;
const sensitiveNameCore = '(?:access(?:[^a-z0-9]*)token|address|api(?:[^a-z0-9]*)key|auth(?:orization)?|code|credential(?:s)?|csrf(?:[^a-z0-9]*token)?|e(?:[^a-z0-9]*)?mail|(?:first|full|last)(?:[^a-z0-9]*)name|jwt|password|phone(?:[^a-z0-9]*number)?|saml(?:[^a-z0-9]*)response|secret|session(?:[^a-z0-9]*id)?|sig(?:nature)?|token)';
const sensitiveName = new RegExp(`(?:^|[^a-z0-9])${sensitiveNameCore}(?=$|[^a-z0-9])`, 'i');
const sensitiveCarrier = new RegExp(`(?:^|[^a-z0-9])${sensitiveNameCore}(?=$|[^a-z0-9]*[:=])`, 'i');
const obviousEmail = /\b[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\b/i;
const obviousInternationalPhone = /(?<![a-z0-9])\+\d{10,15}(?![a-z0-9])/i;
const obviousFormattedPhone = /(?<![a-z0-9])(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?|\d{2,4}[\s.-])\d{3,4}[\s.-]\d{3,4}(?![a-z0-9])/i;
const ordinaryUuidPathSegment = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const jwtPathSegment = /^[a-z0-9_-]{8,}\.[a-z0-9_-]{8,}\.[a-z0-9_-]{6,}$/i;
const apiKeyPathSegment = /^(?:sk-[a-z0-9_-]{16,}|(?:sk|pk)_(?:live|test)_[a-z0-9_-]{12,}|gh[pousr]_[a-z0-9]{16,}|github_pat_[a-z0-9_]{20,}|xox[baprs]-[a-z0-9-]{16,}|aiza[a-z0-9_-]{20,}|akia[a-z0-9]{12,})$/i;
const credentialPathMarker = /^(?:activate(?:-account)?|email-verification|invite(?:-token)?|invitation|magic(?:-link)?|password-reset|reset(?:-password|-token)?|verify(?:-email)?)$/i;
const inlineCredentialPathToken = /^(?:activate(?:-account)?|email-verification|invite|invitation|magic(?:-link)?|password-reset|reset(?:-password)?|verify(?:-email)?)(?:[-_=.:]+(?:token[-_=.:]*)?)(.{8,})$/i;

function plainIpv4Parts(address) {
  return isIP(address) === 4 ? address.split('.').map(Number) : null;
}

function ipv6Words(address) {
  let normalized = String(address || '').toLowerCase();
  const zone = normalized.indexOf('%');
  if (zone >= 0) normalized = normalized.slice(0, zone);
  if (isIP(normalized) !== 6) return null;

  const dotted = normalized.match(/(?:^|:)(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (dotted) {
    const ipv4 = plainIpv4Parts(dotted[1]);
    if (!ipv4) return null;
    const high = ((ipv4[0] << 8) | ipv4[1]).toString(16);
    const low = ((ipv4[2] << 8) | ipv4[3]).toString(16);
    normalized = `${normalized.slice(0, dotted.index + (dotted[0].startsWith(':') ? 1 : 0))}${high}:${low}`;
  }

  const halves = normalized.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  if (halves.length === 1 && left.length !== 8) return null;
  const missing = halves.length === 2 ? 8 - left.length - right.length : 0;
  if (missing < 1 && halves.length === 2) return null;
  const words = [...left, ...Array(missing).fill('0'), ...right];
  if (words.length !== 8 || words.some((word) => !/^[0-9a-f]{1,4}$/i.test(word))) return null;
  return words.map((word) => Number.parseInt(word, 16));
}

function embeddedIpv4Parts(address) {
  const words = ipv6Words(address);
  if (!words) return null;
  const compatible = words.slice(0, 6).every((word) => word === 0);
  const mapped = words.slice(0, 5).every((word) => word === 0) && words[5] === 0xffff;
  if (!compatible && !mapped) return null;
  if (compatible && words[6] === 0 && (words[7] === 0 || words[7] === 1)) return null;
  return [words[6] >> 8, words[6] & 255, words[7] >> 8, words[7] & 255];
}

function ipv4Parts(address) {
  return plainIpv4Parts(address) || embeddedIpv4Parts(address);
}

function isBenchmarkFakeIpv4(address) {
  const parts = plainIpv4Parts(address);
  return Boolean(parts && parts[0] === 198 && (parts[1] === 18 || parts[1] === 19));
}

function isNonPublicHostname(hostname) {
  const normalized = String(hostname || '').replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
  if (!normalized || (!isIP(normalized) && !normalized.includes('.'))) return true;
  return normalized === 'localhost'
    || normalized.endsWith('.localhost')
    || normalized.endsWith('.local')
    || normalized.endsWith('.internal')
    || normalized.endsWith('.corp')
    || normalized.endsWith('.lan')
    || normalized.endsWith('.home')
    || normalized === 'home.arpa'
    || normalized.endsWith('.home.arpa')
    || normalized.endsWith('.onion');
}

function isPrivateAddress(address) {
  const ipv4 = ipv4Parts(address);
  if (ipv4) {
    const [a, b, c] = ipv4;
    return a === 0
      || a === 10
      || a === 127
      || (a === 100 && b >= 64 && b <= 127)
      || (a === 169 && b === 254)
      || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && b === 0 && c === 0)
      || (a === 192 && b === 0 && c === 2)
      || (a === 192 && b === 88 && c === 99)
      || (a === 192 && b === 168)
      || (a === 198 && (b === 18 || b === 19))
      || (a === 198 && b === 51 && c === 100)
      || (a === 203 && b === 0 && c === 113)
      || a >= 224;
  }
  const words = ipv6Words(address);
  if (!words) return false;
  return words.every((word) => word === 0)
    || (words.slice(0, 7).every((word) => word === 0) && words[7] === 1)
    || (words[0] & 0xfe00) === 0xfc00
    || (words[0] & 0xffc0) === 0xfe80
    || (words[0] & 0xffc0) === 0xfec0
    || (words[0] & 0xff00) === 0xff00
    || (words[0] === 0x0064 && words[1] === 0xff9b)
    || (words[0] === 0x0100 && words.slice(1, 4).every((word) => word === 0))
    || (words[0] === 0x2001 && words[1] < 0x0200)
    || (words[0] === 0x2001 && words[1] === 0x0db8)
    || words[0] === 0x2002;
}

export { isPrivateAddress as isPrivateOrReservedAddress };

function normalizedResolverEntries(result) {
  return (Array.isArray(result) ? result : [result])
    .map((entry) => {
      const address = String(entry?.address || entry || '');
      return { address, family: Number(entry?.family || isIP(address)) };
    })
    .filter(({ address, family }) => address && [4, 6].includes(family));
}

function assertDnsHostname(hostname) {
  const normalized = String(hostname || '').replace(/\.$/, '').toLowerCase();
  if (normalized.length < 1 || normalized.length > 253) throw new Error('Invalid DNS hostname.');
  const labels = normalized.split('.');
  if (labels.some((label) => (
    label.length < 1
    || label.length > 63
    || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)
  ))) throw new Error('Invalid DNS hostname.');
  return normalized;
}

async function pinnedDohQuery(hostname, type, {
  request = httpsRequest,
  timeoutMs = 2500,
  maximumBytes = 64 * 1024,
  resolverAddress = '1.1.1.1'
} = {}) {
  const normalized = assertDnsHostname(hostname);
  return new Promise((resolveQuery, rejectQuery) => {
    let settled = false;
    const finishReject = (error) => {
      if (settled) return;
      settled = true;
      rejectQuery(error);
    };
    const clientRequest = request({
      hostname: resolverAddress,
      family: 4,
      port: 443,
      method: 'GET',
      path: `/dns-query?name=${encodeURIComponent(normalized)}&type=${type}`,
      headers: {
        accept: 'application/dns-json',
        host: 'cloudflare-dns.com'
      },
      servername: 'cloudflare-dns.com',
      agent: false
    }, (response) => {
      if (response.statusCode !== 200) {
        response.resume();
        finishReject(new Error('Pinned DNS-over-HTTPS request failed.'));
        return;
      }
      const declaredLength = Number(response.headers['content-length'] || 0);
      if (declaredLength > maximumBytes) {
        response.destroy();
        finishReject(new Error('Pinned DNS-over-HTTPS response exceeded the byte limit.'));
        return;
      }
      const chunks = [];
      let bytes = 0;
      response.on('data', (chunk) => {
        bytes += chunk.length;
        if (bytes > maximumBytes) {
          response.destroy();
          finishReject(new Error('Pinned DNS-over-HTTPS response exceeded the byte limit.'));
          return;
        }
        chunks.push(chunk);
      });
      response.once('aborted', () => finishReject(new Error('Pinned DNS-over-HTTPS response aborted.')));
      response.once('error', finishReject);
      response.once('end', () => {
        if (settled) return;
        try {
          const payload = JSON.parse(Buffer.concat(chunks, bytes).toString('utf8'));
          if (payload?.Status !== 0 || !Array.isArray(payload?.Answer)) {
            throw new Error('Pinned DNS-over-HTTPS response was not a successful DNS answer.');
          }
          const expectedFamily = type === 'AAAA' ? 6 : 4;
          const expectedType = type === 'AAAA' ? 28 : 1;
          const entries = payload.Answer
            .filter((answer) => Number(answer?.type) === expectedType)
            .map((answer) => String(answer?.data || '').replace(/\.$/, ''))
            .filter((address) => isIP(address) === expectedFamily)
            .map((address) => ({ address, family: expectedFamily }));
          settled = true;
          resolveQuery(entries);
        } catch (error) {
          finishReject(error);
        }
      });
    });
    clientRequest.setTimeout(timeoutMs, () => clientRequest.destroy(new Error('Pinned DNS-over-HTTPS request timed out.')));
    clientRequest.once('error', finishReject);
    clientRequest.end();
  });
}

export async function resolvePinnedPublicDns(hostname, options = {}) {
  let ipv4 = [];
  try { ipv4 = await pinnedDohQuery(hostname, 'A', options); } catch {}
  if (ipv4.length) return ipv4;
  const ipv6 = await pinnedDohQuery(hostname, 'AAAA', options);
  if (!ipv6.length) throw new Error('Pinned DNS-over-HTTPS returned no usable addresses.');
  return ipv6;
}

export function createPublicHostResolver({
  systemResolver = lookup,
  dohResolver = resolvePinnedPublicDns
} = {}) {
  return async (hostname, options = {}) => {
    if (isNonPublicHostname(hostname)) throw new Error('Non-public hostnames may not use external DNS resolution.');
    const result = await systemResolver(hostname, options);
    const entries = normalizedResolverEntries(result);
    // Some managed environments deliberately synthesize 198.18.0.0/15 answers.
    // Fall back only when every system answer is in that benchmark-only range.
    // Mixed/private answers remain visible to the caller and therefore fail closed.
    if (entries.length && entries.every(({ address }) => isBenchmarkFakeIpv4(address))) {
      return normalizedResolverEntries(await dohResolver(hostname, options));
    }
    return entries;
  };
}

export const resolvePublicHostAddresses = createPublicHostResolver();

function normalizeCamelCase(value) {
  return String(value ?? '')
    .replace(/([a-z\d])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2');
}

function decodedCandidates(value) {
  const candidates = [];
  let current = String(value ?? '');
  let unresolvedPercentEncoding = false;
  let overlong = false;
  for (let depth = 0; depth <= nestedUrlDepthLimit; depth += 1) {
    if (!candidates.includes(current)) candidates.push(current);
    if (current.length > nestedValueLengthLimit) {
      overlong = true;
      unresolvedPercentEncoding = /%[0-9a-f]{2}/i.test(current);
      break;
    }
    try {
      const decoded = decodeURIComponent(current);
      if (decoded === current) break;
      if (depth === nestedUrlDepthLimit) {
        unresolvedPercentEncoding = true;
        break;
      }
      current = decoded;
    } catch {
      unresolvedPercentEncoding = /%[0-9a-f]{2}/i.test(current);
      break;
    }
  }
  return { candidates, overlong, unresolvedPercentEncoding };
}

function sensitiveParameterName(name) {
  const decoded = decodedCandidates(name);
  return decoded.unresolvedPercentEncoding || decoded.candidates.some((candidate) => (
    candidate.length > nestedValueLengthLimit
      ? /%[0-9a-f]{2}/i.test(candidate)
      : sensitiveName.test(normalizeCamelCase(candidate))
  ));
}

function obviousPiiIssue(value) {
  const decoded = decodedCandidates(value);
  if (decoded.unresolvedPercentEncoding) return 'contains encoding beyond the inspection limit';
  if (decoded.overlong) return 'contains an overlong value beyond the inspection limit';
  for (const candidate of decoded.candidates) {
    if (obviousEmail.test(candidate)) return 'contains an email address';
    if (obviousInternationalPhone.test(candidate) || obviousFormattedPhone.test(candidate)) {
      return 'contains a phone number';
    }
  }
  return null;
}

function sensitiveHash(parsed) {
  return credentialCarrierIssue(parsed.hash) !== null || obviousPiiIssue(parsed.hash) !== null;
}

function sensitivePathAnalysis(parsed) {
  const rawSegments = String(parsed.pathname || '').split('/');
  const decodedSegments = rawSegments.map((segment) => {
    const decoded = decodedCandidates(segment);
    return {
      decoded,
      value: decoded.candidates.at(-1) || segment
    };
  });
  const redactedIndexes = new Set();
  let issue = null;
  for (let index = 0; index < decodedSegments.length; index += 1) {
    const { decoded, value } = decodedSegments[index];
    if (decoded.unresolvedPercentEncoding || decoded.overlong) {
      redactedIndexes.add(index);
      issue ||= 'contains an encoded or overlong path segment beyond the inspection limit';
      continue;
    }
    if (obviousPiiIssue(value)) {
      redactedIndexes.add(index);
      issue ||= 'contains personal data in a path segment';
      continue;
    }
    if (jwtPathSegment.test(value) || apiKeyPathSegment.test(value)) {
      redactedIndexes.add(index);
      issue ||= 'contains a credential-like path token';
      continue;
    }
    const inline = value.match(inlineCredentialPathToken);
    if (inline && !ordinaryUuidPathSegment.test(inline[1])) {
      redactedIndexes.add(index);
      issue ||= 'contains a credential-named path token';
      continue;
    }
    if (!credentialPathMarker.test(value)) continue;
    const next = decodedSegments[index + 1]?.value || '';
    if (next && next.length >= 8 && !ordinaryUuidPathSegment.test(next)) {
      redactedIndexes.add(index + 1);
      issue ||= 'contains a token after a credential-named path segment';
    }
  }
  return { issue, rawSegments, redactedIndexes };
}

function parsedHttpUrl(value) {
  try {
    const parsed = new URL(String(value).trim());
    return ['http:', 'https:'].includes(parsed.protocol) ? parsed : null;
  } catch {
    return null;
  }
}

function parsedReportUrl(value) {
  try {
    const parsed = new URL(String(value).trim());
    return ['http:', 'https:', 'ws:', 'wss:'].includes(parsed.protocol) ? parsed : null;
  } catch {
    return null;
  }
}

function parsedNestedHttpUrl(value) {
  const trimmed = String(value ?? '').trim();
  if (trimmed.startsWith('//')) {
    try {
      return { parsed: new URL(trimmed, 'https://nested.invalid/'), schemeRelative: true };
    } catch {
      return null;
    }
  }
  const parsed = parsedHttpUrl(trimmed);
  return parsed ? { parsed, schemeRelative: false } : null;
}

function embeddedNestedUrls(value) {
  const text = String(value ?? '');
  const entries = [];
  const pattern = /(^|[\s("'=])((?:https?:)?\/\/[^\s"'<>}\]]+)/gi;
  for (const match of text.matchAll(pattern)) {
    let candidate = match[2];
    while (/[),.;]$/.test(candidate)) candidate = candidate.slice(0, -1);
    if (!candidate) continue;
    const nested = parsedNestedHttpUrl(candidate);
    if (!nested) continue;
    if (entries.length >= embeddedNestedUrlLimit) return { entries, overLimit: true };
    const start = Number(match.index || 0) + match[1].length;
    entries.push({ ...nested, start, end: start + candidate.length });
  }
  return { entries, overLimit: false };
}

function parsedJsonHasSensitiveKey(value, depth = 0) {
  if (depth > nestedUrlDepthLimit) return true;
  if (Array.isArray(value)) return value.some((entry) => parsedJsonHasSensitiveKey(entry, depth + 1));
  if (!value || typeof value !== 'object') {
    if (typeof value !== 'string' || value.length > nestedValueLengthLimit) return false;
    const decoded = decodedCandidates(value);
    if (decoded.unresolvedPercentEncoding) return true;
    for (const candidate of decoded.candidates) {
      const trimmed = candidate.trim();
      if (!/^[{[]/.test(trimmed)) continue;
      try {
        if (parsedJsonHasSensitiveKey(JSON.parse(trimmed), depth + 1)) return true;
      } catch {
        // Non-JSON string values are inspected by their owning carrier.
      }
    }
    return false;
  }
  return Object.entries(value).some(([key, entry]) => (
    sensitiveParameterName(key) || parsedJsonHasSensitiveKey(entry, depth + 1)
  ));
}

function credentialCarrierIssue(value) {
  const decoded = decodedCandidates(value);
  if (decoded.unresolvedPercentEncoding) return 'contains encoding beyond the inspection limit';
  if (decoded.overlong) return 'contains an overlong value beyond the inspection limit';
  for (const candidate of decoded.candidates) {
    if (candidate.length > nestedValueLengthLimit) continue;
    const normalized = normalizeCamelCase(candidate);
    if (sensitiveCarrier.test(normalized)) return 'contains credential-like key/value data';
    const jsonCandidate = candidate.trim().replace(/^#/, '');
    if (/^[{[]/.test(jsonCandidate)) {
      try {
        if (parsedJsonHasSensitiveKey(JSON.parse(jsonCandidate))) {
          return 'contains credential-like JSON data';
        }
      } catch {
        // A malformed JSON-looking value still receives the text-carrier check above.
      }
    }
  }
  return null;
}

function nestedCredentialIssue(value, depth) {
  const carrierIssue = credentialCarrierIssue(value);
  if (carrierIssue) return carrierIssue;
  const piiIssue = obviousPiiIssue(value);
  if (piiIssue) return piiIssue;
  const decoded = decodedCandidates(value);
  for (const candidate of decoded.candidates) {
    if (candidate.length > nestedValueLengthLimit) {
      if (/https?%?[:/]|%[0-9a-f]{2}/i.test(candidate)) return 'contains an overlong encoded or nested URL value';
      continue;
    }
    const nested = parsedNestedHttpUrl(candidate);
    if (nested) {
      if (depth >= nestedUrlDepthLimit) return 'contains a URL nested beyond the inspection limit';
      const issue = credentialLikeParsedUrl(nested.parsed, depth + 1);
      if (issue) return `contains a nested URL that ${issue}`;
    }
    const embedded = embeddedNestedUrls(candidate);
    if (embedded.overLimit) return 'contains too many embedded URLs to inspect safely';
    for (const entry of embedded.entries) {
      if (depth >= nestedUrlDepthLimit) return 'contains an embedded URL nested beyond the inspection limit';
      const issue = credentialLikeParsedUrl(entry.parsed, depth + 1);
      if (issue) return `contains an embedded URL that ${issue}`;
    }
  }
  return null;
}

function credentialLikeParsedUrl(parsed, depth = 0) {
  if (!['http:', 'https:'].includes(parsed.protocol)) return 'must use HTTP(S)';
  if (parsed.username || parsed.password) return 'must not contain URL credentials';
  const pathIssue = sensitivePathAnalysis(parsed).issue;
  if (pathIssue) return pathIssue;
  for (const [name, value] of parsed.searchParams) {
    if (sensitiveParameterName(name)) return `contains sensitive query parameter "${name}"`;
    const nestedIssue = nestedCredentialIssue(value, depth);
    if (nestedIssue) return `${nestedIssue} in query parameter "${name}"`;
  }
  if (parsed.hash && sensitiveHash(parsed)) return 'contains a credential-like fragment';
  return null;
}

export function credentialLikeUrlIssue(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return 'is not a valid absolute URL';
  }
  return credentialLikeParsedUrl(parsed);
}

export function assertSafeHttpUrl(rawUrl, label = 'URL') {
  const issue = credentialLikeUrlIssue(rawUrl);
  if (issue) throw new Error(`${label} ${issue}.`);
  return new URL(rawUrl);
}

function redactNestedValue(value, depth) {
  if (credentialCarrierIssue(value) || obviousPiiIssue(value)) return '[REDACTED]';
  const decoded = decodedCandidates(value);
  for (const candidate of decoded.candidates) {
    if (candidate.length > nestedValueLengthLimit) {
      if (/https?%?[:/]|%[0-9a-f]{2}/i.test(candidate)) return '[REDACTED]';
      continue;
    }
    const nested = parsedNestedHttpUrl(candidate);
    if (nested) {
      if (depth >= nestedUrlDepthLimit) return '[REDACTED]';
      const issue = credentialLikeParsedUrl(nested.parsed, depth + 1);
      if (issue) {
        if (nested.schemeRelative) return '[REDACTED]';
        return redactParsedSensitiveUrl(nested.parsed, depth + 1);
      }
    }
    const embedded = embeddedNestedUrls(candidate);
    if (embedded.overLimit) return '[REDACTED]';
    let redactedCandidate = candidate;
    let changed = false;
    for (const entry of [...embedded.entries].reverse()) {
      if (depth >= nestedUrlDepthLimit || credentialLikeParsedUrl(entry.parsed, depth + 1)) {
        const replacement = entry.schemeRelative
          ? '[REDACTED]'
          : redactParsedSensitiveUrl(entry.parsed, depth + 1);
        redactedCandidate = `${redactedCandidate.slice(0, entry.start)}${replacement}${redactedCandidate.slice(entry.end)}`;
        changed = true;
      }
    }
    if (changed) return candidate === String(value) ? redactedCandidate : '[REDACTED]';
  }
  return value;
}

function redactParsedSensitiveUrl(parsed, depth = 0) {
  parsed.username = '';
  parsed.password = '';
  const pathAnalysis = sensitivePathAnalysis(parsed);
  if (pathAnalysis.redactedIndexes.size) {
    parsed.pathname = pathAnalysis.rawSegments
      .map((segment, index) => pathAnalysis.redactedIndexes.has(index) ? '[REDACTED]' : segment)
      .join('/');
  }
  for (const [name, value] of [...parsed.searchParams]) {
    if (sensitiveParameterName(name)) {
      parsed.searchParams.set(name, '[REDACTED]');
    } else {
      const redactedValue = redactNestedValue(value, depth);
      if (redactedValue !== value) parsed.searchParams.set(name, redactedValue);
    }
  }
  if (parsed.hash && sensitiveHash(parsed)) parsed.hash = '#[REDACTED]';
  return parsed.href;
}

export function redactSensitiveUrl(rawUrl) {
  const parsed = parsedReportUrl(rawUrl);
  return parsed ? redactParsedSensitiveUrl(parsed) : rawUrl;
}

function redactUrlsInText(value) {
  try {
    const parsed = new URL(value);
    if (['http:', 'https:', 'ws:', 'wss:'].includes(parsed.protocol)) return redactSensitiveUrl(value);
  } catch {
    // Fall through to redact absolute URLs embedded in diagnostic text.
  }
  return String(value).replace(/(?:https?|wss?):\/\/[^\s"'<>]+/gi, (match) => {
    let suffix = '';
    let candidate = match;
    while (/[),.;\]}]$/.test(candidate)) {
      suffix = `${candidate.at(-1)}${suffix}`;
      candidate = candidate.slice(0, -1);
    }
    return `${redactSensitiveUrl(candidate)}${suffix}`;
  });
}

function sensitiveReportKey(name) {
  if (['cookieNames'].includes(String(name))) return false;
  if (sensitiveParameterName(name)) return true;
  const parts = String(name || '')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
  const compact = parts.join('');
  if (['count', 'enabled', 'length', 'present', 'status'].includes(parts.at(-1))) return false;
  if (parts.some((part) => ['authorization', 'credential', 'credentials', 'csrf', 'jwt', 'password', 'secret', 'signature', 'token'].includes(part))) return true;
  return [
    'accesstoken', 'apikey', 'authorizationheader', 'authtoken', 'bearertoken',
    'clientsecret', 'cookie', 'cookieheader', 'refreshtoken', 'requestcookie',
    'responsecookie', 'samlresponse', 'sessionid', 'sessiontoken', 'setcookie', 'signedtoken'
  ].some((key) => compact.includes(key));
}

function redactCredentialText(value) {
  let output = redactUrlsInText(value);
  output = output.replace(new RegExp(obviousEmail.source, 'gi'), '[REDACTED_EMAIL]');
  output = output.replace(new RegExp(obviousInternationalPhone.source, 'gi'), '[REDACTED_PHONE]');
  output = output.replace(
    new RegExp(obviousFormattedPhone.source, 'gi'),
    '[REDACTED_PHONE]'
  );
  output = output.replace(
    /\b((?:proxy-)?authorization)(?:\s*:\s*|\s+)(?:(?:bearer|basic)\s+)?[^\r\n,;|}\]]+/gi,
    '$1: [REDACTED]'
  );
  output = output.replace(/\b(set-cookie|cookie)\s*:\s*[^\r\n]*/gi, '$1: [REDACTED]');
  output = output.replace(/\bbearer\s+[a-z0-9._~+/-]{4,}=*/gi, 'Bearer [REDACTED]');
  output = output.replace(
    /((?:["']?)(?:access[_-]?token|accessToken|address|api[_-]?key|apiKey|auth[_-]?token|authToken|authorization|client[_-]?secret|clientSecret|credential|csrf|e[_-]?mail|email|first[_-]?name|firstName|full[_-]?name|fullName|jwt|last[_-]?name|lastName|password|phone(?:[_-]?number)?|refresh[_-]?token|refreshToken|samlResponse|secret|session[_-]?(?:id|token)|sessionId|sessionToken|sig|signature|token)(?:["']?)\s*[:=]\s*)(?:"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|[^\r\n,;&#|}\]]+)/gi,
    '$1[REDACTED]'
  );
  return output;
}

export function redactReportData(value) {
  if (typeof value === 'string') return redactCredentialText(value);
  if (Array.isArray(value)) return value.map(redactReportData);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).map(([key, entry]) => [
    key,
    sensitiveReportKey(key)
      && !(typeof entry === 'boolean' && ['emailConfirmation', 'emailEnabled'].includes(key))
      && !(typeof entry === 'number' && /(?:Count|Length|Bytes)$/i.test(key))
      && entry !== null
      && entry !== undefined
      && !(key === 'code' && (
        typeof entry === 'string' && /^[A-Z][A-Z0-9_]{2,63}$/.test(entry)
        || Number.isInteger(entry) && entry >= 0 && entry <= 255
      ))
      ? '[REDACTED]'
      : redactReportData(entry)
  ]));
}

export function isLoopbackHostname(hostname) {
  const normalized = String(hostname || '').replace(/^\[|\]$/g, '').toLowerCase();
  if (normalized === 'localhost' || normalized.endsWith('.localhost')) return true;
  const ipv4 = ipv4Parts(normalized);
  if (ipv4) return ipv4[0] === 127;
  const words = ipv6Words(normalized);
  return Boolean(words && words.slice(0, 7).every((word) => word === 0) && words[7] === 1);
}

export function createPrivateHostChecker({ resolver = resolvePublicHostAddresses, timeoutMs = 3000 } = {}) {
  return async (hostname) => {
    const normalized = String(hostname || '').replace(/^\[|\]$/g, '').toLowerCase();
    if (isNonPublicHostname(normalized)) return true;
    if (isIP(normalized)) return isPrivateAddress(normalized);
    let timer;
    try {
      const addresses = await Promise.race([
        resolver(normalized, { all: true, verbatim: true }),
        new Promise((resolveLookup) => {
          timer = setTimeout(() => resolveLookup([]), timeoutMs);
        })
      ]);
      const entries = Array.isArray(addresses) ? addresses : [addresses];
      const normalizedEntries = entries.map((entry) => String(entry?.address || entry || ''));
      return !normalizedEntries.length
        || normalizedEntries.some((address) => !isIP(address) || isPrivateAddress(address));
    } catch {
      return true;
    } finally {
      clearTimeout(timer);
    }
  };
}

export async function blocksPrivateDestination(rawUrl, allowedOrigin, hostIsPrivate) {
  let parsed;
  try { parsed = new URL(rawUrl); } catch { return true; }
  if (!['http:', 'https:'].includes(parsed.protocol)) return true;
  if (parsed.username || parsed.password) return true;
  let allowed = null;
  try { allowed = new URL(allowedOrigin); } catch {}
  if (allowed
    && parsed.origin === allowed.origin
    && isLoopbackHostname(allowed.hostname)
    && parsed.hostname.toLowerCase() === allowed.hostname.toLowerCase()
    && parsed.port === allowed.port) return false;
  return hostIsPrivate(parsed.hostname);
}

// Browser capture routes use this synchronous preflight only when every HTTP(S)
// socket is forced through createValidatingBrowserProxy. DNS must be checked by
// that proxy, because it pins the vetted answer to the actual connection.
export function blocksUnsafeDestinationBeforeProxy(rawUrl, allowedOrigin) {
  let parsed;
  try { parsed = new URL(rawUrl); } catch { return true; }
  if (!['http:', 'https:'].includes(parsed.protocol)) return true;
  if (parsed.username || parsed.password) return true;
  let allowed = null;
  try { allowed = new URL(allowedOrigin); } catch {}
  if (allowed
    && parsed.origin === allowed.origin
    && isLoopbackHostname(allowed.hostname)
    && parsed.hostname.toLowerCase() === allowed.hostname.toLowerCase()
    && parsed.port === allowed.port) return false;
  const normalized = parsed.hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
  if (isIP(normalized)) return isPrivateAddress(normalized);
  return isNonPublicHostname(normalized);
}
