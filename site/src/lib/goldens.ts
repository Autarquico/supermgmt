import { readFileSync } from 'node:fs';
import path from 'node:path';
import { REPO_BLOB_URL } from '../../scripts/sync-docs.mjs';

const GOLDEN_DIR = 'internal/tui/testdata';

const repoRoot = () => path.resolve(process.cwd(), '..');

export function goldenUrl(file: string): string {
  return `${REPO_BLOB_URL}${GOLDEN_DIR}/${file}`;
}

export function readGolden(file: string): string {
  const full = path.join(repoRoot(), GOLDEN_DIR, file);
  try {
    return readFileSync(full, 'utf8').replace(/\s+$/, '');
  } catch {
    throw new Error(`golden frame ${GOLDEN_DIR}/${file} not found (the site builds from the site/ folder of the repository)`);
  }
}

// The plan hash shown in "how it works" is the one in the approvals frame, never a made-up value.
export function approvalsPlanHash(approvalsGolden: string): string {
  const match = approvalsGolden.match(/PLAN #([0-9a-f]{8,})/);
  if (!match) throw new Error('no "PLAN #<hash>" line in the approvals golden frame');
  return match[1];
}
