// Re:basis 操作モック — 暗号化ファイルを復号して返す Service Worker（build mufe3rw0）
const SALT = "SBgHWlVpcggQeZJR+X1D0A==";
const KEY_URL = "./__key__";
const TYPES = { html:"text/html; charset=utf-8", js:"text/javascript; charset=utf-8", mjs:"text/javascript; charset=utf-8",
  css:"text/css; charset=utf-8", json:"application/json", svg:"image/svg+xml", png:"image/png", jpg:"image/jpeg",
  jpeg:"image/jpeg", webp:"image/webp", gif:"image/gif", ico:"image/x-icon", woff2:"font/woff2", txt:"text/plain; charset=utf-8" };
const b2u = b => Uint8Array.from(atob(b), c => c.charCodeAt(0));
let keyP = null;

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", e => e.waitUntil(self.clients.claim()));

async function store(){ return caches.open("rebasis-mock-key"); }
async function getKey(){
  if(keyP) return keyP;
  const c = await store();
  const r = await c.match(KEY_URL);
  if(!r) return null;
  const raw = new Uint8Array(await r.arrayBuffer());
  keyP = crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
  return keyP;
}
self.addEventListener("message", e => {
  const d = e.data || {};
  if(d.type === "key"){
    e.waitUntil((async () => {
      const raw = new Uint8Array(d.raw);
      const c = await store();
      await c.put(KEY_URL, new Response(raw));
      keyP = crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
      e.source && e.source.postMessage({ type:"key-ok" });
    })());
  }
  if(d.type === "forget"){ keyP = null; e.waitUntil(caches.delete("rebasis-mock-key")); }
});

async function encName(path){
  const s = b2u(SALT), p = new TextEncoder().encode(path);
  const all = new Uint8Array(s.length + p.length); all.set(s); all.set(p, s.length);
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256", all));
  return [...h].map(x => x.toString(16).padStart(2, "0")).join("").slice(0, 32);
}

self.addEventListener("fetch", e => {
  const url = new URL(e.request.url);
  const scope = new URL(self.registration.scope);
  if(url.origin !== scope.origin || !url.pathname.startsWith(scope.pathname + "app/")) return;
  e.respondWith((async () => {
    let path = decodeURIComponent(url.pathname.slice((scope.pathname + "app/").length));
    if(path === "" || path.endsWith("/")) path += "index.html";
    const key = await getKey();
    if(!key){
      if(e.request.mode === "navigate") return Response.redirect(scope.href + "?next=" + encodeURIComponent(url.search + url.hash), 302);
      return new Response("locked", { status: 403 });
    }
    const r = await fetch(scope.href + "enc/" + (await encName(path)) + ".bin", { cache: "no-cache" });
    if(!r.ok) return new Response("not found", { status: 404 });
    const buf = new Uint8Array(await r.arrayBuffer());
    try{
      const plain = await crypto.subtle.decrypt({ name:"AES-GCM", iv: buf.slice(0, 12) }, key, buf.slice(12));
      const ext = path.split(".").pop().toLowerCase();
      return new Response(plain, { headers: { "Content-Type": TYPES[ext] || "application/octet-stream", "Cache-Control": "no-cache" } });
    }catch(err){
      // 合言葉が変わった（再ビルドした）等で復号できない → 入口へ
      keyP = null; await caches.delete("rebasis-mock-key");
      if(e.request.mode === "navigate") return Response.redirect(scope.href, 302);
      return new Response("locked", { status: 403 });
    }
  })());
});
