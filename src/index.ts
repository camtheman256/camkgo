/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `wrangler dev src/index.ts` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `wrangler publish src/index.ts --name my-worker` to publish your worker
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */
import signin from "./signin.html";
import { SignedCookieStore } from "@worker-tools/signed-cookie-store";
import { RequestCookieStore } from "@worker-tools/request-cookie-store";
import { createRemoteJWKSet, importJWK, JWTPayload, jwtVerify } from "jose";

const googleKeys = createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs'))

type UrlData = {
  url: string;
  owner?: string;
};

type AuthRequest = {
  token: string;
};

export interface Env {
  // Example binding to KV. Learn more at https://developers.cloudflare.com/workers/runtime-apis/kv/
  URLS: KVNamespace;
  //
  // Example binding to Durable Object. Learn more at https://developers.cloudflare.com/workers/runtime-apis/durable-objects/
  // MY_DURABLE_OBJECT: DurableObjectNamespace;
  //
  // Example binding to R2. Learn more at https://developers.cloudflare.com/workers/runtime-apis/r2/
  // MY_BUCKET: R2Bucket;
  /** Key for cookie signatures */
  COOKIE_KEY: string;
  /** Google OAuth client ID for token verification */
  CLIENT_ID: string;
}

export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext
  ): Promise<Response> {
    const cookieStore = new RequestCookieStore(request);
    const signedCookieStore = new SignedCookieStore(
      cookieStore,
      await SignedCookieStore.deriveCryptoKey({ secret: env.COOKIE_KEY })
    );
    const { pathname } = new URL(request.url);
    if (pathname.startsWith("/api/auth")) {
      const payload = await createAuthCookie(request, signedCookieStore, env);
      return Response.json(
        { message: "User signed in successfully.", payload },
        new Response(null, cookieStore)
      );
    }
    const shortName = pathname.slice(1);
    const redirect = await env.URLS.get<UrlData>(shortName, "json");
    if (redirect) {
      if (redirect.owner !== undefined) {
        const user = await signedCookieStore.get('user').catch(() => null);
        if(user?.value !== redirect.owner) {
          return renderSignInTemplate();
        }
      }
      return Response.redirect(redirect.url);
    }

    return new Response(pathname + " not found");
  },
};

async function renderSignInTemplate(): Promise<Response> {
  return new Response(signin, { headers: { "Content-Type": "text/html" } });
}

async function createAuthCookie(
  request: Request,
  cookieStore: SignedCookieStore,
  env: Env
): Promise<JWTPayload> {
  const body = (await request.json()) as AuthRequest;
  const { protectedHeader, payload } = await jwtVerify(body.token, googleKeys, {
    audience: env.CLIENT_ID,
    issuer: "https://accounts.google.com",
  });
  if (payload !== undefined) {
    await cookieStore.set({name: 'user', value: payload.email, path: '/'});
  }
  return payload;
}
