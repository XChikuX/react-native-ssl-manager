/**
 * A single SPKI pin entry with an expiration date.
 */
export interface PinEntry {
  /** SHA-256 SPKI hash, prefixed with `sha256/` */
  hash: string;
  /** ISO 8601 date string (YYYY-MM-DD) after which this pin is considered expired */
  validUntil: string;
}

/**
 * Trust policy configuration for the time-bounded TLS trust engine.
 *
 * Combines SPKI pinning (exact public-key trust), CAA-derived issuer policy
 * (issuer-level trust), and a bounded grace window (time limit on fallback).
 */
export interface TrustPolicyConfig {
  /**
   * Per-domain pin sets. Each domain maps to one or more SPKI pin entries
   * with individual expiration dates.
   */
  pins: Record<string, PinEntry[]>;

  /**
   * Per-domain issuer allowlists derived from DNS CAA records.
   * Used only during the recovery window when SPKI validation fails.
   */
  issuerAllowlist: Record<string, string[]>;

  /**
   * Number of days after the last acceptable pin's expiry during which
   * issuer-based fallback is permitted. Defaults to 15 if not specified.
   */
  graceWindowDays?: number;
}

/**
 * The result of a trust evaluation.
 */
export type TrustDecision = 'accept' | 'accept_temporary' | 'reject';

/**
 * Detailed result from the trust engine evaluation.
 */
export interface TrustEvaluationResult {
  /** The trust decision */
  decision: TrustDecision;

  /** The mode the engine operated in */
  mode: 'strong' | 'recovery' | 'hard_fail';

  /** Human-readable reason for the decision */
  reason: string;
}

/**
 * Information about the server certificate presented during TLS handshake,
 * extracted by the native layer.
 */
export interface CertificateInfo {
  /** SHA-256 SPKI hash of the leaf certificate, prefixed with `sha256/` */
  spkiHash: string;

  /** The certificate issuer identifier (e.g., "pki.goog", "letsencrypt.org") */
  issuer: string;

  /** ISO 8601 date string for certificate NotBefore */
  notBefore?: string;

  /** ISO 8601 date string for certificate NotAfter */
  notAfter?: string;
}
