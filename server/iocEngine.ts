import { SecurityEvent, IOCRecord } from './types';
import { db } from './db';

export interface IOCMatchResult {
  matched: boolean;
  ioc_record?: IOCRecord;
  threat_level?: 'low' | 'medium' | 'high' | 'critical';
  confidence?: number;
  extracted_value?: string;
  source?: string;
  reputation_summary?: string;
}

export class IOCEngine {
  public correlate(event: SecurityEvent): IOCMatchResult {
    // 1. Check Source IP
    if (event.source_ip) {
      const match = db.iocs.find(i => i.type === 'IP' && i.ioc === event.source_ip);
      if (match) {
        return {
          matched: true,
          ioc_record: match,
          threat_level: match.threat_level,
          confidence: match.confidence,
          extracted_value: event.source_ip,
          source: match.source,
          reputation_summary: `Identified malicious IP in ${match.source} (${match.threat_level.toUpperCase()} severity, ${match.confidence}% confidence)`
        };
      }
    }

    // 2. Check File Hash
    if (event.file_hash) {
      const match = db.iocs.find(i => i.type === 'HASH' && i.ioc.toLowerCase() === event.file_hash?.toLowerCase());
      if (match) {
        return {
          matched: true,
          ioc_record: match,
          threat_level: match.threat_level,
          confidence: match.confidence,
          extracted_value: event.file_hash,
          source: match.source,
          reputation_summary: `Known malware hash signature detected: ${match.description}`
        };
      }
    }

    // 3. Check Domain
    if (event.domain) {
      const match = db.iocs.find(i => i.type === 'DOMAIN' && i.ioc.toLowerCase() === event.domain?.toLowerCase());
      if (match) {
        return {
          matched: true,
          ioc_record: match,
          threat_level: match.threat_level,
          confidence: match.confidence,
          extracted_value: event.domain,
          source: match.source,
          reputation_summary: `Host domain flagged as malicious command-and-control infrastructure`
        };
      }
    }

    // 4. Check URL
    if (event.url) {
      const match = db.iocs.find(i => i.type === 'URL' && (event.url?.includes(i.ioc) || i.ioc.includes(event.url || '')));
      if (match) {
        return {
          matched: true,
          ioc_record: match,
          threat_level: match.threat_level,
          confidence: match.confidence,
          extracted_value: event.url,
          source: match.source,
          reputation_summary: `Exploit staging URL confirmed in threat repository`
        };
      }
    }

    // 5. Check Payload for embedded IPs/domains
    if (event.payload) {
      for (const ioc of db.iocs) {
        if (event.payload.includes(ioc.ioc)) {
          return {
            matched: true,
            ioc_record: ioc,
            threat_level: ioc.threat_level,
            confidence: ioc.confidence,
            extracted_value: ioc.ioc,
            source: ioc.source,
            reputation_summary: `Embedded IOC indicator [${ioc.type}: ${ioc.ioc}] discovered within event payload`
          };
        }
      }
    }

    return { matched: false };
  }
}

export const iocEngine = new IOCEngine();
