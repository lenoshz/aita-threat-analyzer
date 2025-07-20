// Type definitions for AITA frontend
export interface User {
  id: number;
  username: string;
  email: string;
  full_name?: string;
  role: string;
  is_active: boolean;
  is_superuser: boolean;
  created_at: string;
  last_login?: string;
}

export interface ThreatIntelligence {
  id: number;
  source: string;
  external_id?: string;
  title: string;
  description?: string;
  threat_type?: string;
  severity?: 'critical' | 'high' | 'medium' | 'low';
  cvss_score?: number;
  cvss_vector?: string;
  ip_addresses: string[];
  domains: string[];
  urls: string[];
  file_hashes: Record<string, string>;
  risk_score?: number;
  confidence_score?: number;
  predicted_category?: string;
  summary?: string;
  tags: string[];
  references: string[];
  published_date?: string;
  discovered_date: string;
  created_at: string;
  updated_at?: string;
  is_active: boolean;
  is_verified: boolean;
}

export interface Alert {
  id: number;
  title: string;
  description?: string;
  alert_type: string;
  severity: string;
  priority: string;
  status: 'open' | 'investigating' | 'resolved' | 'false_positive';
  confidence_score?: number;
  triggered_at: string;
  acknowledged_at?: string;
  resolved_at?: string;
}

export interface ThreatStats {
  total_threats: number;
  active_threats: number;
  verified_threats: number;
  by_severity: Record<string, number>;
  by_type: Record<string, number>;
  by_source: Record<string, number>;
  recent_threats: number;
}

export interface LoginCredentials {
  username: string;
  password: string;
}

export interface RegisterData {
  username: string;
  email: string;
  password: string;
  full_name?: string;
  role?: string;
}

export interface AuthToken {
  access_token: string;
  token_type: string;
  expires_in: number;
}