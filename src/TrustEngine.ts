import type {
  TrustPolicyConfig,
  TrustDecision,
  TrustEvaluationResult,
  CertificateInfo,
  PinEntry,
} from './types/TrustPolicy';

const DEFAULT_GRACE_WINDOW_DAYS = 15;

/**
 * Time-bounded TLS trust engine.
 *
 * Operates in two modes:
 * 1. **Strong mode** — SPKI hash matches a configured pin → accept.
 * 2. **Recovery mode** — SPKI mismatch, but the pin policy is within the
 *    grace window near expiry AND the certificate issuer is in the allowlist
 *    → accept temporarily.
 *
 * Outside the grace window, all SPKI mismatches result in hard failure.
 */
export class TrustEngine {
  private readonly config: TrustPolicyConfig;
  private readonly graceWindowDays: number;

  constructor(config: TrustPolicyConfig) {
    this.config = config;
    this.graceWindowDays = config.graceWindowDays ?? DEFAULT_GRACE_WINDOW_DAYS;
  }

  /**
   * Evaluate trust for a given domain and its presented certificate.
   *
   * @param domain - The target domain (e.g., "psync.club")
   * @param certificate - Certificate info extracted from the TLS handshake
   * @param now - Optional current date for testing; defaults to `new Date()`
   */
  evaluate(
    domain: string,
    certificate: CertificateInfo,
    now: Date = new Date()
  ): TrustEvaluationResult {
    const pins = this.config.pins[domain];

    // No pin configuration for this domain — reject
    if (!pins || pins.length === 0) {
      return {
        decision: 'reject',
        mode: 'hard_fail',
        reason: `No pin configuration found for domain: ${domain}`,
      };
    }

    // Step 1: Try exact SPKI match against any configured pin
    if (this.matchesAnyPin(certificate.spkiHash, pins)) {
      return {
        decision: 'accept',
        mode: 'strong',
        reason: 'SPKI hash matches a configured pin',
      };
    }

    // Step 2: SPKI mismatch — check if we're within the grace window
    const lastExpiry = this.getLastAcceptablePinExpiry(pins);
    if (lastExpiry === null) {
      return {
        decision: 'reject',
        mode: 'hard_fail',
        reason: 'No valid pin expiry dates configured',
      };
    }

    const graceWindowActive = this.isWithinGraceWindow(lastExpiry, now);
    if (!graceWindowActive) {
      // Determine if we're before expiry or after grace
      if (now < lastExpiry) {
        return {
          decision: 'reject',
          mode: 'hard_fail',
          reason:
            'SPKI mismatch and pins have not yet expired (not in recovery window)',
        };
      }
      return {
        decision: 'reject',
        mode: 'hard_fail',
        reason: 'SPKI mismatch and recovery window has expired',
      };
    }

    // Step 3: Within grace window — validate issuer against allowlist
    const allowedIssuers = this.config.issuerAllowlist[domain];
    if (!allowedIssuers || allowedIssuers.length === 0) {
      return {
        decision: 'reject',
        mode: 'hard_fail',
        reason:
          'SPKI mismatch during recovery window but no issuer allowlist configured',
      };
    }

    if (this.isIssuerAllowed(certificate.issuer, allowedIssuers)) {
      return {
        decision: 'accept_temporary',
        mode: 'recovery',
        reason: `SPKI mismatch accepted temporarily: issuer "${certificate.issuer}" is in allowlist (recovery mode)`,
      };
    }

    return {
      decision: 'reject',
      mode: 'hard_fail',
      reason: `SPKI mismatch and issuer "${certificate.issuer}" is not in the allowlist`,
    };
  }

  /**
   * Convenience method returning just the decision.
   */
  evaluateDecision(
    domain: string,
    certificate: CertificateInfo,
    now?: Date
  ): TrustDecision {
    return this.evaluate(domain, certificate, now).decision;
  }

  /**
   * Check if the given SPKI hash matches any pin in the set.
   */
  private matchesAnyPin(spkiHash: string, pins: PinEntry[]): boolean {
    return pins.some((pin) => pin.hash === spkiHash);
  }

  /**
   * Get the latest expiry date among all configured pins for a domain.
   * This represents the "last acceptable pin expiry" that triggers the recovery window.
   */
  private getLastAcceptablePinExpiry(pins: PinEntry[]): Date | null {
    let latest: Date | null = null;
    for (const pin of pins) {
      const expiry = parseDate(pin.validUntil);
      if (expiry === null) {
        continue;
      }
      if (latest === null || expiry > latest) {
        latest = expiry;
      }
    }
    return latest;
  }

  /**
   * Determine if the current time is within the grace window.
   *
   * The grace window starts on (or after) the pin expiry date and extends
   * for `graceWindowDays` days after expiry.
   *
   * Timeline:
   *   [before expiry]  →  [expiry ... expiry + graceWindowDays]  →  [after grace]
   *       reject             recovery mode active                       reject
   */
  private isWithinGraceWindow(pinExpiry: Date, now: Date): boolean {
    // Must be on or after the expiry date
    if (now < pinExpiry) {
      return false;
    }

    // Must be within graceWindowDays after expiry
    const graceEnd = new Date(pinExpiry.getTime());
    graceEnd.setDate(graceEnd.getDate() + this.graceWindowDays);

    return now <= graceEnd;
  }

  /**
   * Check if the certificate issuer is in the domain's allowlist.
   * Uses case-insensitive substring matching to handle issuer variations.
   */
  private isIssuerAllowed(issuer: string, allowedIssuers: string[]): boolean {
    const normalizedIssuer = issuer.toLowerCase();
    return allowedIssuers.some((allowed) =>
      normalizedIssuer.includes(allowed.toLowerCase())
    );
  }

  /**
   * Get the current policy status for a domain.
   */
  getDomainStatus(
    domain: string,
    now: Date = new Date()
  ): {
    hasPins: boolean;
    pinCount: number;
    lastExpiry: Date | null;
    graceWindowActive: boolean;
    graceWindowEnd: Date | null;
    hasIssuerAllowlist: boolean;
  } {
    const pins = this.config.pins[domain];
    if (!pins || pins.length === 0) {
      return {
        hasPins: false,
        pinCount: 0,
        lastExpiry: null,
        graceWindowActive: false,
        graceWindowEnd: null,
        hasIssuerAllowlist: false,
      };
    }

    const lastExpiry = this.getLastAcceptablePinExpiry(pins);
    let graceWindowActive = false;
    let graceWindowEnd: Date | null = null;

    if (lastExpiry !== null) {
      graceWindowActive = this.isWithinGraceWindow(lastExpiry, now);
      graceWindowEnd = new Date(lastExpiry.getTime());
      graceWindowEnd.setDate(graceWindowEnd.getDate() + this.graceWindowDays);
    }

    const allowedIssuers = this.config.issuerAllowlist[domain];

    return {
      hasPins: true,
      pinCount: pins.length,
      lastExpiry,
      graceWindowActive,
      graceWindowEnd,
      hasIssuerAllowlist: !!allowedIssuers && allowedIssuers.length > 0,
    };
  }
}

/**
 * Parse an ISO 8601 date string (YYYY-MM-DD or full ISO) into a Date.
 * Returns null if parsing fails.
 */
function parseDate(dateStr: string): Date | null {
  const d = new Date(dateStr);
  if (isNaN(d.getTime())) {
    return null;
  }
  return d;
}

export type {
  TrustPolicyConfig,
  TrustDecision,
  TrustEvaluationResult,
  CertificateInfo,
  PinEntry,
} from './types/TrustPolicy';
