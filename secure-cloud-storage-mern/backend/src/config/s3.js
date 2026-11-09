const {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
  HeadObjectCommand
} = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

// Determine if we are connecting to a local MinIO container or Amazon AWS S3
const isMinio = (process.env.STORAGE_PROVIDER || 'minio').toLowerCase() === 'minio';

const s3Config = {
  region: process.env.S3_REGION || 'us-east-1',
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID || 'minioadmin',
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || 'minioadminpassword'
  }
};

// Configure endpoint and path-style addressing for local MinIO / LocalStack
if (process.env.S3_ENDPOINT || isMinio) {
  s3Config.endpoint = process.env.S3_ENDPOINT || 'http://127.0.0.1:9000';
  s3Config.forcePathStyle = true; // MinIO requires path-style addressing (e.g., http://localhost:9000/bucket/key)
}

const s3Client = new S3Client(s3Config);
const BUCKET_NAME = process.env.S3_BUCKET_NAME || 'secure-cloud-files';

/**
 * Storage Service Abstraction Layer
 * Handles all S3 object storage operations using AWS SDK v3.
 * All objects stored and retrieved through this service are strictly ciphertext.
 */
const storageService = {
  /**
   * Uploads raw ciphertext binary buffer to Amazon S3 / MinIO.
   * @param {string} s3Key - Unique storage key (e.g., "enc_usr123_4f5a6b.enc")
   * @param {Buffer} ciphertextBuffer - Encrypted binary data
   * @param {string} mimeType - File MIME type
   * @returns {Promise<string>} S3 Object URI
   */
  async uploadCiphertext(s3Key, ciphertextBuffer, mimeType = 'application/octet-stream') {
    const command = new PutObjectCommand({
      Bucket: BUCKET_NAME,
      Key: s3Key,
      Body: ciphertextBuffer,
      ContentType: mimeType,
      Metadata: {
        'encryption-mode': 'client-side-aes-256-gcm',
        'zero-knowledge': 'true'
      }
    });
    await s3Client.send(command);
    return `s3://${BUCKET_NAME}/${s3Key}`;
  },

  /**
   * Generates a pre-signed S3 download URL valid for a temporary duration (default: 1 hour).
   * Allows the client browser to stream ciphertext directly from S3 without proxying through Express.
   * @param {string} s3Key - S3 storage key
   * @param {number} expiresIn - Expiration in seconds (default 3600 = 1 hour)
   * @returns {Promise<string>} Pre-signed download URL
   */
  async getPresignedDownloadUrl(s3Key, expiresIn = 3600) {
    const command = new GetObjectCommand({
      Bucket: BUCKET_NAME,
      Key: s3Key,
      ResponseContentType: 'application/octet-stream'
    });
    return await getSignedUrl(s3Client, command, { expiresIn });
  },

  /**
   * Retrieves an S3 object as a readable stream (for streaming through Express to the client).
   * @param {string} s3Key - S3 storage key
   * @returns {Promise<ReadableStream>} S3 Object Body Stream
   */
  async getCiphertextStream(s3Key) {
    const command = new GetObjectCommand({
      Bucket: BUCKET_NAME,
      Key: s3Key
    });
    const response = await s3Client.send(command);
    return response.Body;
  },

  /**
   * Retrieves raw ciphertext from S3 / MinIO and returns it as a Buffer.
   * @param {string} s3Key - S3 storage key
   * @returns {Promise<Buffer>} Ciphertext Buffer
   */
  async getCiphertext(s3Key) {
    const stream = await this.getCiphertextStream(s3Key);
    const chunks = [];
    for await (const chunk of stream) {
      chunks.push(chunk);
    }
    return Buffer.concat(chunks);
  },

  /**
   * Deletes an encrypted object from S3 / MinIO.
   * @param {string} s3Key - S3 storage key
   * @returns {Promise<boolean>} True on success
   */
  async deleteObject(s3Key) {
    const command = new DeleteObjectCommand({
      Bucket: BUCKET_NAME,
      Key: s3Key
    });
    await s3Client.send(command);
    return true;
  }
};

module.exports = { s3Client, storageService, BUCKET_NAME };
