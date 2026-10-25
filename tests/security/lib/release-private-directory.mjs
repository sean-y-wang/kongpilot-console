import { lstatSync, mkdirSync, realpathSync } from 'node:fs';
import { dirname, isAbsolute, normalize, resolve, sep } from 'node:path';

const DEFAULT_PRIVATE_DIRECTORY = '/dev/shm/kongpilot-release-lab';
const sameNode = (left, right) => left.dev === right.dev && left.ino === right.ino;
const canonical = value => typeof value === 'string' && value.length > 1 && !value.includes('\0')
  && !value.includes('\\') && normalize(value) === value && !value.endsWith(sep);
const privateFolder = stat => stat.isDirectory() && !stat.isSymbolicLink()
  && stat.uid === process.getuid() && (stat.mode & 0o777) === 0o700;

function privateDirectoryStat(directory) {
  try {
    const parent = dirname(directory), parentStat = lstatSync(parent), stat = lstatSync(directory);
    // realpath on the parent rejects symlinks anywhere in the ancestor chain.
    // The leaf itself is checked with lstat, without following it.
    if (!parentStat.isDirectory() || parentStat.isSymbolicLink() || realpathSync(parent) !== parent
      || !privateFolder(stat)) throw Error();
    return stat;
  } catch { throw Error('RELEASE_LEDGER_PRIVATE_DIRECTORY_INVALID'); }
}

/** Select an existing operator-owned directory. Never create or import a ledger. */
export function selectReleasePrivateDirectory() {
  const selector = process.env.RELEASE_LAB_PRIVATE_DIR;
  const directory = selector === undefined ? DEFAULT_PRIVATE_DIRECTORY : selector;
  if (!canonical(directory) || !isAbsolute(directory)) throw Error('RELEASE_LEDGER_PRIVATE_DIRECTORY_INVALID');
  const stat = privateDirectoryStat(directory);
  return Object.freeze({ directory, selector, custom: selector !== undefined,
    binding: Object.freeze({ directory, device: stat.dev, inode: stat.ino }) });
}

export function assertReleasePrivateDirectory(selection) {
  if (process.env.RELEASE_LAB_PRIVATE_DIR !== selection.selector)
    throw Error('RELEASE_LEDGER_SAVE_PATH_INVALID');
  const stat = privateDirectoryStat(selection.directory);
  if (!sameNode(stat, { dev: selection.binding.device, ino: selection.binding.inode }))
    throw Error('RELEASE_LEDGER_PRIVATE_DIRECTORY_INVALID');
}

export function releaseStorageBindingMatches(state, selection) {
  const binding = state?.privateStorageBinding;
  // Historical default RAM ledgers keep their version 1 representation. A new
  // custom directory cannot adopt those ledgers or a copied run's credentials.
  if (binding === undefined) return !selection.custom;
  return binding && Object.keys(binding).sort().join(',') === 'device,directory,inode'
    && binding.directory === selection.binding.directory && binding.device === selection.binding.device
    && binding.inode === selection.binding.inode;
}

function verifyReportDirectories(selection, create) {
  try {
    if (realpathSync(selection.cwd) !== selection.cwd) throw Error();
    let current = selection.cwd;
    for (const part of selection.directory.slice(selection.cwd.length + 1).split(sep)) {
      current = resolve(current, part);
      let stat;
      try { stat = lstatSync(current); } catch (error) {
        if (error?.code !== 'ENOENT') throw error;
        if (!create) return;
        mkdirSync(current, { mode: 0o755 });
        stat = lstatSync(current);
      }
      if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid()
        || (stat.mode & 0o022) !== 0 || realpathSync(current) !== current) throw Error();
    }
  } catch { throw Error('RELEASE_REPORT_DIRECTORY_INVALID'); }
}

/** Custom reports are confined to a distinct run underneath this milestone. */
export function selectReleaseReportDirectory(milestone) {
  const selector = process.env.RELEASE_LAB_REPORT_DIRECTORY, cwd = process.cwd();
  if (selector === undefined) return Object.freeze({ directory: resolve(`artifacts/${milestone}`),
    selector, custom: false, cwd });
  if (!canonical(selector)) throw Error('RELEASE_REPORT_DIRECTORY_INVALID');
  const directory = resolve(selector), root = resolve(`artifacts/${milestone}/runs`);
  if (!directory.startsWith(`${root}${sep}`)) throw Error('RELEASE_REPORT_DIRECTORY_INVALID');
  const selection = Object.freeze({ directory, selector, custom: true, cwd });
  verifyReportDirectories(selection, false);
  return selection;
}

export function assertReleaseReportDirectory(selection, { create = false } = {}) {
  if (process.env.RELEASE_LAB_REPORT_DIRECTORY !== selection.selector)
    throw Error('RELEASE_REPORT_SAVE_PATH_INVALID');
  if (selection.custom) verifyReportDirectories(selection, create);
}
