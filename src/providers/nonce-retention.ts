/**
 * Retain admission state through the entire final accepted second. The extra
 * second covers inclusive, second-granularity verifiers; rounding up also
 * covers subsecond cache clocks. A longer configured retention always wins.
 */
export function nonceRetentionSeconds(
  configuredTtlSeconds: number,
  validUntilSeconds: number,
  nowMs: number,
): number {
  if (!Number.isFinite(configuredTtlSeconds) || configuredTtlSeconds <= 0 ||
      !Number.isFinite(validUntilSeconds) || !Number.isFinite(nowMs)) {
    throw new RangeError('Nonce retention requires a positive TTL and a bounded acceptance window');
  }
  return Math.max(configuredTtlSeconds, Math.ceil(validUntilSeconds + 1 - nowMs / 1000));
}
