// SPDX-License-Identifier: Apache-2.0

/**
 * Mutual-TLS transport for `@tirbase/gateway-admin-sdk` (hand-written; this
 * file is not generated from the OpenAPI definition).
 *
 * The generated client is transport-agnostic: it only needs a `fetch`-shaped
 * function, supplied through `ClientOptions.fetchImpl`. Browsers cannot attach
 * a client certificate from JavaScript, so they rely on the browser/OS
 * certificate store and pass ordinary `fetch` (plus `fetchInit.credentials`
 * when the certificate is selected by cookie/session). Node has no such
 * store-backed client-certificate selection, so this module provides the Node
 * transport used by service processes, CI and the e2e suite.
 *
 * Import it from the subpath so the rest of the package stays free of
 * `node:https` (a browser bundle that imports the root entry point never pulls
 * this in):
 *
 * ```ts
 * import { GatewayAdminClient } from '@tirbase/gateway-admin-sdk';
 * import { createMtlsFetch } from '@tirbase/gateway-admin-sdk/mtls';
 *
 * const client = new GatewayAdminClient({
 *   baseUrl: 'https://gateway.internal:9443',
 *   token: biscuitTokenHex,
 *   fetchImpl: createMtlsFetch({
 *     cert: fs.readFileSync('client.pem'),
 *     key: fs.readFileSync('client.key'),
 *     ca: fs.readFileSync('ca.pem'),
 *   }),
 * });
 * ```
 */

import * as https from 'node:https';
import type { IncomingMessage } from 'node:http';

export interface MtlsFetchOptions {
  /** PEM client certificate (chain leaf first). */
  cert: string | Buffer;
  /** PEM private key for `cert`. */
  key: string | Buffer;
  /** CA bundle the server certificate must chain to. */
  ca?: string | Buffer | Array<string | Buffer>;
  /** Passphrase for an encrypted `key`. */
  passphrase?: string;
  /** TLS server name when connecting by IP but the certificate names a host. */
  servername?: string;
  /**
   * Defaults to `true`: the gateway's remote admin listener is verified
   * against `ca`. Setting this to `false` disables that verification.
   */
  rejectUnauthorized?: boolean;
}

function isBodyLike(body: unknown): body is string | Buffer | Uint8Array {
  return (
    typeof body === 'string' ||
    body instanceof Uint8Array ||
    (typeof Buffer !== 'undefined' && Buffer.isBuffer(body))
  );
}

/**
 * Build a `fetch`-compatible function that presents a client certificate.
 *
 * The gateway's remote admin surface is a deliberately small HTTP/1.1 reader:
 * one request per connection with a bounded `Content-Length` body. This
 * adapter therefore sends a single explicit-length request and never streams,
 * which also keeps the generated client unchanged.
 */
export function createMtlsFetch(options: MtlsFetchOptions): typeof fetch {
  const agent = new https.Agent({
    cert: options.cert,
    key: options.key,
    ca: options.ca,
    passphrase: options.passphrase,
    rejectUnauthorized: options.rejectUnauthorized ?? true,
  });

  return (async (input: string | URL | Request, init: RequestInit = {}) => {
    const rawUrl =
      typeof input === 'string'
        ? input
        : input instanceof URL
          ? input.toString()
          : input.url;
    const target = new URL(rawUrl);

    const headers = new Headers(init.headers);
    let payload: Buffer | undefined;
    if (init.body !== undefined && init.body !== null) {
      if (!isBodyLike(init.body)) {
        throw new TypeError(
          'createMtlsFetch supports string, Buffer and Uint8Array bodies (no streams)',
        );
      }
      payload = Buffer.from(init.body as string | Buffer | Uint8Array);
      // An explicit length is required: the remote admin reader rejects
      // chunked bodies.
      headers.set('content-length', String(payload.byteLength));
    }

    const requestHeaders: Record<string, string> = {};
    headers.forEach((value, name) => {
      requestHeaders[name] = value;
    });

    const response = await new Promise<{
      status: number;
      statusText: string;
      headers: Headers;
      body: Buffer;
    }>((resolve, reject) => {
      const request = https.request(
        {
          protocol: target.protocol,
          hostname: target.hostname,
          port: target.port,
          path: `${target.pathname}${target.search}`,
          method: init.method ?? 'GET',
          headers: requestHeaders,
          agent,
          servername: options.servername,
        },
        (incoming: IncomingMessage) => {
          const chunks: Buffer[] = [];
          incoming.on('data', (chunk: Buffer) => chunks.push(chunk));
          incoming.on('end', () => {
            const responseHeaders = new Headers();
            const entries = Object.entries(incoming.headers) as Array<
              [string, string | string[] | undefined]
            >;
            for (const [name, value] of entries) {
              if (Array.isArray(value)) {
                for (const item of value) responseHeaders.append(name, item);
              } else if (value !== undefined) {
                responseHeaders.set(name, value);
              }
            }
            resolve({
              status: incoming.statusCode ?? 0,
              statusText: incoming.statusMessage ?? '',
              headers: responseHeaders,
              body: Buffer.concat(chunks),
            });
          });
        },
      );
      request.on('error', reject);
      if (payload !== undefined) request.write(payload);
      request.end();
    });

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    });
  }) as typeof fetch;
}
