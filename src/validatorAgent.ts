import http from 'http';
import { MessageAttestationBundle, verifyMessageAttestation } from './validator';

const DEFAULT_VALIDATOR_PORT = 3103;
const PORT = resolvePort(process.env.VALIDATOR_AGENT_PORT, DEFAULT_VALIDATOR_PORT);

type ValidateRequest = {
  bundle?: MessageAttestationBundle;
  plaintext?: string;
  ciphertextBase64?: string;
};

function resolvePort(raw: string | undefined, fallback: number) {
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

const server = http.createServer(async (req, res) => {
  applyCors(res);
  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    res.end();
    return;
  }

  try {
    if (req.method === 'GET' && req.url === '/health') {
      sendJson(res, 200, { ok: true });
      return;
    }

    if (req.method === 'POST' && req.url === '/validate') {
      const body = (await readJsonBody(req)) as ValidateRequest;
      const bundle = (body.bundle ?? body) as MessageAttestationBundle;
      if (!bundle || typeof bundle.ciphertextBase64 !== 'string') {
        sendJson(res, 400, { error: 'bundle is required' });
        return;
      }
      const plaintext = typeof body.plaintext === 'string' ? body.plaintext : undefined;
      const ciphertextOverride =
        typeof body.ciphertextBase64 === 'string' ? body.ciphertextBase64 : undefined;
      const result = await verifyMessageAttestation(bundle, {
        plaintext,
        ciphertextBase64: ciphertextOverride,
      });
      console.log(
        `validator: ${bundle.senderId ?? 'unknown'} -> ${bundle.receiverId ?? 'unknown'}`,
        result,
      );
      sendJson(res, 200, { ok: true, result });
      return;
    }

    sendJson(res, 404, { error: 'Not Found' });
  } catch (err) {
    sendJson(res, 500, { error: err instanceof Error ? err.message : 'unknown error' });
  }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`validator agent listening on http://127.0.0.1:${PORT}`);
});

function applyCors(res: http.ServerResponse) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'content-type');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
}

function sendJson(res: http.ServerResponse, status: number, payload: unknown) {
  res.statusCode = status;
  res.setHeader('content-type', 'application/json');
  res.end(JSON.stringify(payload));
}

function readJsonBody(req: http.IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (chunk) => {
      chunks.push(chunk);
      total += chunk.length;
      if (total > 1_000_000) {
        reject(new Error('payload too large'));
      }
    });
    req.on('end', () => {
      if (!chunks.length) {
        resolve({});
        return;
      }
      try {
        const raw = Buffer.concat(chunks).toString('utf8');
        resolve(JSON.parse(raw));
      } catch (err) {
        reject(err);
      }
    });
    req.on('error', reject);
  });
}
