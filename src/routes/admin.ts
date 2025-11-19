import { Hono } from 'hono';
import type { Env, StoredKey, KeyUploadRequest } from '../types';
import { parseAndValidateKey, extractPublicKey } from '../utils/signing';
import { logAuditEvent, getAuditLogs } from '../utils/audit';

const app = new Hono<{ Bindings: Env }>();

// Upload a new signing key
app.post('/keys', async (c) => {
  const requestId = c.req.header('X-Request-ID') || crypto.randomUUID();

  try {
    const body = await c.req.json() as KeyUploadRequest;

    if (!body.armoredPrivateKey || !body.keyId) {
      return c.json({
        error: 'Missing armoredPrivateKey or keyId',
        code: 'INVALID_REQUEST',
      }, 400);
    }

    // Validate and parse the key
    const keyInfo = await parseAndValidateKey(
      body.armoredPrivateKey,
      c.env.KEY_PASSPHRASE
    );

    const storedKey: StoredKey = {
      armoredPrivateKey: body.armoredPrivateKey,
      keyId: body.keyId,
      fingerprint: keyInfo.fingerprint,
      createdAt: new Date().toISOString(),
      algorithm: keyInfo.algorithm,
    };

    // Store in Durable Object
    const keyStorageId = c.env.KEY_STORAGE.idFromName('global');
    const keyStorage = c.env.KEY_STORAGE.get(keyStorageId);

    const storeResponse = await keyStorage.fetch(
      new Request('http://internal/store-key', {
        method: 'POST',
        body: JSON.stringify(storedKey),
        headers: { 'Content-Type': 'application/json' },
      })
    );

    if (!storeResponse.ok) {
      const error = await storeResponse.json() as { error: string };
      throw new Error(error.error || 'Failed to store key');
    }

    // Log key upload
    await logAuditEvent(c.env.AUDIT_DB, {
      requestId,
      action: 'key_upload',
      issuer: 'admin',
      subject: 'admin',
      keyId: body.keyId,
      success: true,
      metadata: JSON.stringify({
        fingerprint: keyInfo.fingerprint,
        algorithm: keyInfo.algorithm,
        userId: keyInfo.userId,
      }),
    });

    return c.json({
      success: true,
      keyId: body.keyId,
      fingerprint: keyInfo.fingerprint,
      algorithm: keyInfo.algorithm,
      userId: keyInfo.userId,
    }, 201);

  } catch (error) {
    const message = error instanceof Error ? error.message : 'Key upload failed';

    // Audit failed key upload attempt
    await logAuditEvent(c.env.AUDIT_DB, {
      requestId,
      action: 'key_upload',
      issuer: 'admin',
      subject: 'admin',
      keyId: 'unknown',
      success: false,
      errorCode: 'KEY_UPLOAD_ERROR',
      metadata: JSON.stringify({ error: message }),
    });

    return c.json({
      error: message,
      code: 'KEY_UPLOAD_ERROR',
      requestId,
    }, 500);
  }
});

// List all keys (metadata only)
app.get('/keys', async (c) => {
  try {
    const keyStorageId = c.env.KEY_STORAGE.idFromName('global');
    const keyStorage = c.env.KEY_STORAGE.get(keyStorageId);

    const response = await keyStorage.fetch(new Request('http://internal/list-keys'));
    if (!response.ok) {
      throw new Error(`Key storage returned ${response.status}`);
    }

    const result = await response.json();
    return c.json(result);
  } catch (error) {
    console.error('Failed to list keys:', error);
    return c.json({ error: 'Failed to retrieve keys', code: 'KEY_LIST_ERROR' }, 500);
  }
});

// Get public key for a specific key ID
app.get('/keys/:keyId/public', async (c) => {
  const keyId = c.req.param('keyId');

  try {
    const keyStorageId = c.env.KEY_STORAGE.idFromName('global');
    const keyStorage = c.env.KEY_STORAGE.get(keyStorageId);

    const keyResponse = await keyStorage.fetch(
      new Request(`http://internal/get-key?keyId=${encodeURIComponent(keyId)}`)
    );

    if (!keyResponse.ok) {
      return c.json({ error: 'Key not found', code: 'KEY_NOT_FOUND' }, 404);
    }

    const storedKey = await keyResponse.json() as StoredKey;
    const publicKey = await extractPublicKey(storedKey.armoredPrivateKey);

    return c.text(publicKey, 200, {
      'Content-Type': 'application/pgp-keys',
    });
  } catch (error) {
    console.error('Failed to get public key:', { keyId, error });
    return c.json({ error: 'Failed to process key', code: 'KEY_PROCESSING_ERROR' }, 500);
  }
});

// Delete a key
app.delete('/keys/:keyId', async (c) => {
  const keyId = c.req.param('keyId');
  const requestId = c.req.header('X-Request-ID') || crypto.randomUUID();

  try {
    const keyStorageId = c.env.KEY_STORAGE.idFromName('global');
    const keyStorage = c.env.KEY_STORAGE.get(keyStorageId);

    const response = await keyStorage.fetch(
      new Request(`http://internal/delete-key?keyId=${encodeURIComponent(keyId)}`, {
        method: 'DELETE',
      })
    );

    if (!response.ok) {
      throw new Error(`Key storage returned ${response.status}`);
    }

    const result = await response.json() as { success: boolean; deleted: boolean };

    // Log key deletion
    await logAuditEvent(c.env.AUDIT_DB, {
      requestId,
      action: 'key_rotate',
      issuer: 'admin',
      subject: 'admin',
      keyId,
      success: result.deleted,
    });

    return c.json(result);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Delete failed';
    console.error('Failed to delete key:', { keyId, error });

    // Audit failed deletion attempt
    await logAuditEvent(c.env.AUDIT_DB, {
      requestId,
      action: 'key_rotate',
      issuer: 'admin',
      subject: 'admin',
      keyId,
      success: false,
      errorCode: 'KEY_DELETE_ERROR',
      metadata: JSON.stringify({ error: message }),
    });

    return c.json({ error: 'Failed to delete key', code: 'KEY_DELETE_ERROR' }, 500);
  }
});

// Get audit logs
app.get('/audit', async (c) => {
  try {
    const limit = parseInt(c.req.query('limit') || '100');
    const offset = parseInt(c.req.query('offset') || '0');

    // Validate pagination parameters
    if (isNaN(limit) || isNaN(offset) || limit < 1 || limit > 1000 || offset < 0) {
      return c.json({ error: 'Invalid pagination parameters', code: 'INVALID_REQUEST' }, 400);
    }

    const action = c.req.query('action');
    const subject = c.req.query('subject');
    const startDate = c.req.query('startDate');
    const endDate = c.req.query('endDate');

    const logs = await getAuditLogs(c.env.AUDIT_DB, {
      limit,
      offset,
      action,
      subject,
      startDate,
      endDate,
    });

    return c.json({ logs, count: logs.length });
  } catch (error) {
    console.error('Failed to get audit logs:', error);
    return c.json({ error: 'Failed to retrieve audit logs', code: 'AUDIT_ERROR' }, 500);
  }
});

export default app;
