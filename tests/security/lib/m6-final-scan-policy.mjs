/** The final check covers newly issued material and the last cleanup traffic. */
export function assertFinalM6Evidence(reference, {http,browser,manual,cleanup,material}) {
  if (http?.failed!==0 || !Number.isSafeInteger(http.passed) || http.passed<1 || browser?.failed!==0 || browser.passed!==1
    || manual?.allPassed!==true || cleanup?.allPassed!==true
    || reference?.phase!=='cleanup-complete'
    || material?.allPassed!==true || material.keyValuePublished!==false
    || material.keyRetainedPrivately!==true || material.audited!==true
    || material.scannerRevealPosts!==1 || material.nativeWrites!==0
    || reference.browserKeyScan?.phase!=='scanner-material-verified'
    || typeof reference.browserKeyScan?.credentialId!=='string') {
    throw new Error('FINAL_M6_EVIDENCE_INCOMPLETE');
  }
}

export function finalM6SecretForms(values) {
  return [...new Set(values.filter(value=>typeof value==='string'&&value.length>0)
    .flatMap(value=>[value,JSON.stringify(value).slice(1,-1),encodeURIComponent(value),Buffer.from(value).toString('base64')]))];
}

export function finalM6RuntimeLogsPassed(logs) {
  const expected=['kong','kong-secondary','kong-portal','console-api','console-web','portal-web','telemetry-collector'];
  return logs?.allPassed===true && logs.rawLogsPublished===false
    && Array.isArray(logs.services) && logs.services.length===expected.length
    && expected.every(service=>logs.services.filter(row=>row.service===service&&row.knownSecretDetected===false).length===1);
}

export function finalM6RuntimeLogAdapter(reference,secrets,checks) {
  return {
    referenceData:reference,secrets,
    requireLive(){if(reference.phase!=='cleanup-complete')throw new Error('FINAL_M6_CLEANUP_REQUIRED');},
    check(group,kind,name) {
      checks.push({group:kind,name,passed:group===true});
      if(group!==true)throw new Error('FINAL_M6_RUNTIME_LOG_FAILED');
    },
  };
}
