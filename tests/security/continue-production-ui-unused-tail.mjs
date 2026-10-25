// Independent known-prefix entry. Only Security maintains the original SID.
// Root's exclusive handoff is required before the imported runner reads files.
if(process.env.PRODUCTION_UI_UNUSED_TAIL_READY!=='true'||process.env.PRODUCTION_UI_EXCLUSIVE_READY==='true')throw Error('PRODUCTION_EXCLUSIVE_UNUSED_TAIL_HANDOFF_REQUIRED');
await import('./production-ui-lifecycle.mjs');
