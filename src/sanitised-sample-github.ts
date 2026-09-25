export const GOLDENS_ONLY_REPO = 'wvdlinde-cribl/cribl-pack-goldens';

export function sanitisedSampleRepoError(
  repo: string,
  branch: string,
  configuredGoldenRepo = '',
): string | null {
  const target = String(repo || '').trim().toLowerCase();
  const golden = String(configuredGoldenRepo || '').trim().toLowerCase();
  if (!/^[\w.-]+\/[\w.-]+$/.test(target)) return 'Sample repository must be owner/repo.';
  if (target === GOLDENS_ONLY_REPO || (golden && target === golden)) {
    return 'The goldens-only repository cannot store samples.';
  }
  if (String(branch || '').trim().toLowerCase().includes('shared-goldens')) {
    return 'The shared-goldens branch is goldens-only.';
  }
  return null;
}

export function assertSuitableSanitisedSampleRepo(
  repo: string,
  branch: string,
  configuredGoldenRepo = '',
): void {
  const error = sanitisedSampleRepoError(repo, branch, configuredGoldenRepo);
  if (error) throw new Error(error);
}
