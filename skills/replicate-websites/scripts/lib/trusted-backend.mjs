import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { isAbsolute, join, relative, resolve } from 'node:path';

const implementation = 'replicate-websites-starter-v1';
const maximumPackageBytes = 1024 * 1024;
const maximumServerBytes = 2 * 1024 * 1024;

function escapeRegularExpression(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function templateExpression(template) {
  const captures = new Set();
  let expression = '^';
  let cursor = 0;
  for (const match of template.matchAll(/\{\{([A-Z_]+)\}\}/g)) {
    expression += escapeRegularExpression(template.slice(cursor, match.index));
    const name = match[1];
    if (captures.has(name)) {
      expression += `\\k<${name}>`;
    } else if (name === 'PROJECT_NAME') {
      expression += `(?<${name}>[a-z0-9][a-z0-9._-]{0,127})`;
      captures.add(name);
    } else if (name === 'REPLICA_MODE') {
      expression += `(?<${name}>authorized-local|owned|public-simulation)`;
      captures.add(name);
    } else {
      throw new Error(`Unsupported trusted-backend template token: ${name}`);
    }
    cursor = match.index + match[0].length;
  }
  expression += `${escapeRegularExpression(template.slice(cursor))}$`;
  return new RegExp(expression, 'u');
}

function isWithin(parent, child) {
  const pathFromParent = relative(parent, child);
  return pathFromParent === '' || (!pathFromParent.startsWith('..') && !isAbsolute(pathFromParent));
}

async function canonicalDirectory(pathname, label) {
  const requested = resolve(pathname);
  const stat = await fs.lstat(requested);
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error(`${label} must be a real, non-symlink directory.`);
  }
  return fs.realpath(requested);
}

async function regularFile(pathname, label, containingRoot, maximumBytes) {
  const stat = await fs.lstat(pathname);
  if (stat.isSymbolicLink() || !stat.isFile()) throw new Error(`${label} must be a regular, non-symlink file.`);
  if (stat.size > maximumBytes) throw new Error(`${label} exceeds its ${maximumBytes}-byte safety limit.`);
  const canonical = await fs.realpath(pathname);
  if (containingRoot && !isWithin(containingRoot, canonical)) {
    throw new Error(`${label} must remain inside its canonical root.`);
  }
  return canonical;
}

async function readBoundedFile(pathname, label, maximumBytes) {
  const contents = await fs.readFile(pathname);
  if (contents.byteLength > maximumBytes) throw new Error(`${label} exceeds its ${maximumBytes}-byte safety limit.`);
  return contents;
}

export async function verifyTrustedBackend({ candidateRoot, skillRoot, manifest }) {
  if (manifest.mode !== 'authorized-local') {
    throw new Error('Mutation verification requires manifest.mode to be authorized-local. Owned and public-simulation candidates are read-only evaluation targets.');
  }
  if (manifest.backend?.implementation !== implementation) {
    throw new Error(`manifest.backend.implementation must be ${implementation}.`);
  }
  if (manifest.backend?.auditPath !== '/api/replica-audit') {
    throw new Error('manifest.backend.auditPath must be /api/replica-audit.');
  }
  if (manifest.backend?.submitPath !== '/api/applications') {
    throw new Error('manifest.backend.submitPath must be /api/applications.');
  }
  if (manifest.backend?.emailEnabledByDefault !== false || manifest.backend?.retainsApplicantValues !== false) {
    throw new Error('The trusted backend requires explicit email-off and non-retention declarations.');
  }

  const root = await canonicalDirectory(candidateRoot, 'Candidate root');
  const packagePath = await regularFile(
    join(root, 'package.json'), 'Candidate package.json', root, maximumPackageBytes
  );
  const serverPath = await regularFile(
    join(root, 'server.mjs'), 'Candidate server.mjs', root, maximumServerBytes
  );
  const canonicalSkillRoot = await canonicalDirectory(skillRoot, 'Skill root');
  const templatePath = await regularFile(
    join(canonicalSkillRoot, 'assets', 'replica-starter', 'server.mjs'),
    'Trusted server template',
    canonicalSkillRoot,
    maximumServerBytes
  );
  const packageJson = JSON.parse((await readBoundedFile(
    packagePath, 'Candidate package.json', maximumPackageBytes
  )).toString('utf8'));
  if (packageJson.scripts?.start !== 'node server.mjs') {
    throw new Error('Candidate package.json must start the audited backend with exactly "node server.mjs".');
  }
  const template = (await readBoundedFile(
    templatePath, 'Trusted server template', maximumServerBytes
  )).toString('utf8');
  const candidateBytes = await readBoundedFile(serverPath, 'Candidate server.mjs', maximumServerBytes);
  const candidate = candidateBytes.toString('utf8');
  const match = candidate.match(templateExpression(template));
  if (!match) {
    throw new Error('Candidate server.mjs does not exactly match the immutable audited starter backend.');
  }
  if (match.groups?.REPLICA_MODE !== manifest.mode) {
    throw new Error('Candidate server mode does not match manifest.mode.');
  }
  if (match.groups?.PROJECT_NAME !== packageJson.name) {
    throw new Error('Candidate server project name does not match package.json.');
  }
  const result = {
    implementation,
    projectName: match.groups?.PROJECT_NAME || null,
    mode: match.groups?.REPLICA_MODE || null,
    serverPath,
    serverSha256: createHash('sha256').update(candidateBytes).digest('hex')
  };
  Object.defineProperty(result, 'verifiedServerBytes', {
    configurable: false,
    enumerable: false,
    writable: false,
    value: Buffer.from(candidateBytes)
  });
  return result;
}

export const trustedBackendImplementation = implementation;
