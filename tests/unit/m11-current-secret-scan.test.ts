import { describe, expect, it } from 'vitest';
import { currentSecretScannerSelfTest } from '../security/m11-current-secret-scan.mjs';

describe('M11 current-material scanner synthetic boundary and disclosure checks', () => {
  it('keeps real private/runtime/git closed while testing byte matches and fail-closed file/provenance gates', async () => {
    const result = await currentSecretScannerSelfTest();
    expect(result).toEqual({ passed: true, checks: 40, actualPrivateMaterialRead: false, actualRepositoryGitInvoked: false, runtimeRequests: 0 });
  });
});
