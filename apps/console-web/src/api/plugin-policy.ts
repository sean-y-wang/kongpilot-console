export function requiresPlatformPlugin(name: string, known?: boolean, hasBinding = true) {
  return !hasBinding || ['pre-function', 'post-function', 'file-log'].includes(name) || known === false;
}
