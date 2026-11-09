export interface UserProfile {
  id: string;
  username: string;
  email: string;
  createdAt: string;
}

export interface StoredFile {
  id: string;
  ownerId: string;
  originalName: string;
  mimeType: string;
  originalSize: number;
  encryptedSize: number;
  storageBackend: 'local' | 's3';
  storageKey: string;
  ivHex: string;
  authTagHex: string;
  saltHex: string;
  keyId: string;
  createdAt: string;
  isTampered?: boolean;
}

export interface CryptoInspectionData {
  fileId: string;
  fileName: string;
  algorithm: string;
  keyDerivation: string;
  keyId: string;
  nonceIV: {
    lengthBytes: number;
    lengthBits: number;
    hex: string;
    description: string;
  };
  authTag: {
    lengthBytes: number;
    lengthBits: number;
    hex: string;
    description: string;
  };
  salt: {
    lengthBytes: number;
    hex: string;
  };
  storageBackend: string;
  storageKey: string;
  ciphertextLengthBytes: number;
  ciphertextHexPreview: string;
  isTampered: boolean;
}

export interface StorageConfig {
  backend: 'local' | 's3';
  s3Bucket: string;
  s3Region: string;
  s3Endpoint?: string;
  forcePathStyle?: boolean;
  provider?: 'minio' | 'aws' | 'custom';
  hasAwsKeys: boolean;
}

export interface TestCaseResult {
  id: number;
  name: string;
  category: string;
  status: 'PASSED' | 'FAILED';
  durationMs: number;
  description: string;
}

export interface TestSuiteSummary {
  total: number;
  passed: number;
  failed: number;
  suiteDurationMs: number;
  timestamp: string;
  tests: TestCaseResult[];
}
