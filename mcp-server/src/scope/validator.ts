import IPCIDR from "ip-cidr";
import { getScopeConfig, ScopeConfig } from "./scope-config";

interface ValidationResult {
  valid: boolean;
  reason?: string;
  matched_rule?: string;
}

export async function validateScope(target: string): Promise<ValidationResult> {
  const config = await getScopeConfig();

  // Normalize: extract hostname from URLs (https://app.groovysec.com/path → app.groovysec.com)
  let normalizedTarget = target;
  try {
    if (target.includes("://")) {
      normalizedTarget = new URL(target).hostname;
    } else if (target.includes("/")) {
      // Handle cases like "app.groovysec.com/path" without protocol
      normalizedTarget = target.split("/")[0];
    }
  } catch {
    // Not a valid URL, use target as-is
  }
  // Strip any trailing port from non-URL targets (e.g. "app.groovysec.com:8443")
  normalizedTarget = normalizedTarget.replace(/:\d+$/, "");

  // Check exclusions first (check both original and normalized)
  for (const exclusion of config.exclusions) {
    if (matchesPattern(normalizedTarget, exclusion) || matchesPattern(target, exclusion)) {
      return {
        valid: false,
        reason: `Target matches exclusion pattern: ${exclusion}`,
      };
    }
  }

  // Check if target is an IP address
  const isIP = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(normalizedTarget);

  if (isIP) {
    // Validate against CIDR ranges
    for (const network of config.networks) {
      const cidr = new IPCIDR(network.cidr);
      if (cidr.contains(normalizedTarget)) {
        return {
          valid: true,
          matched_rule: `Network: ${network.cidr} (${network.environment})`,
        };
      }
    }
  } else {
    // Validate against domain patterns
    for (const domain of config.domains) {
      if (matchesDomainPattern(normalizedTarget, domain.pattern)) {
        return {
          valid: true,
          matched_rule: `Domain: ${domain.pattern} (${domain.environment})`,
        };
      }
    }
  }

  return {
    valid: false,
    reason: "Target does not match any allowed scope",
  };
}

function matchesPattern(target: string, pattern: string): boolean {
  if (pattern.includes("*")) {
    const regex = new RegExp("^" + pattern.replace(/\*/g, ".*") + "$");
    return regex.test(target);
  }
  return target === pattern;
}

function matchesDomainPattern(target: string, pattern: string): boolean {
  // Handle wildcard domains like *.staging.company.com
  if (pattern.startsWith("*.")) {
    const suffix = pattern.slice(2);
    return target.endsWith(suffix) || target === suffix.slice(1);
  }
  return target === pattern || target.endsWith("." + pattern);
}
