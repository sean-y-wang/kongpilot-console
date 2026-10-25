import { readFileSync } from 'node:fs';
import { M6Harness } from './lib/m6-harness.mjs';
import { runM6 } from './live-m6.mjs';

if (process.env.M6_DEPLOYMENT_READY !== 'true' || process.env.M6_PUBLICATION_CONTINUATION_READY !== 'true') throw new Error('M6 patched-runtime and explicit continuation handoff required');
const proof = JSON.parse(readFileSync('artifacts/M6/publication-initial-ledger-proof.json','utf8'));
const h = new M6Harness({ requireReference: true }); let failure;
try { await runM6(h, { publicationContinuation: true, proof }); } catch (error) { failure = error; }
process.exitCode = await h.finish(failure);
