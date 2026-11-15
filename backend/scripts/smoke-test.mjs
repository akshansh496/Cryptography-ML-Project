// End-to-end check of the whole backend. Run AFTER the server is up:  npm run smoke
// Needs Node 18+ (built-in fetch / FormData). No extra packages.
import crypto from "crypto";

const BASE = process.env.BASE_URL || "http://localhost:4000";
let passed = 0;
let failed = 0;

function check(name, condition, extra = "") {
  if (condition) {
    passed++;
    console.log(`  PASS  ${name}`);
  } else {
    failed++;
    console.log(`  FAIL  ${name} ${extra}`);
  }
}

// Smallest fake file that looks like a PE: "MZ" + e_lfanew=0x80 + "PE\0\0"
function makeFakePE() {
  const buf = Buffer.alloc(512);
  buf.write("MZ", 0, "ascii");
  buf.writeUInt32LE(0x80, 0x3c);
  buf.write("PE\0\0", 0x80, "binary");
  crypto.randomBytes(100).copy(buf, 200); // makes every run unique
  return buf;
}

async function api(path, { method = "GET", token, json, form } = {}) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  let body;
  if (json) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(json);
  }
  if (form) body = form;
  return fetch(BASE + path, { method, headers, body });
}

function uploadForm(buffer, filename) {
  const form = new FormData();
  form.append("file", new Blob([buffer]), filename);
  return form;
}

async function register(email, password) {
  await api("/api/auth/register", { method: "POST", json: { email, password } });
  const res = await api("/api/auth/login", { method: "POST", json: { email, password } });
  return res.json();
}

async function main() {
  const stamp = Date.now();
  const password = "Test@1234";

  console.log("\n[1] Health");
  const health = await api("/health");
  check("GET /health = 200", health.status === 200);

  console.log("\n[2] Auth");
  const weak = await api("/api/auth/register", { method: "POST", json: { email: `weak${stamp}@t.com`, password: "abc" } });
  check("weak password rejected (400)", weak.status === 400);

  const reg = await api("/api/auth/register", { method: "POST", json: { email: `a${stamp}@t.com`, password } });
  check("register = 201", reg.status === 201);
  const dup = await api("/api/auth/register", { method: "POST", json: { email: `a${stamp}@t.com`, password } });
  check("duplicate email = 409", dup.status === 409);

  const login = await api("/api/auth/login", { method: "POST", json: { email: `a${stamp}@t.com`, password } });
  const tokens = await login.json();
  check("login = 200 with tokens", login.status === 200 && tokens.accessToken && tokens.refreshToken);

  const noToken = await api("/api/scans");
  check("no token = 401", noToken.status === 401);

  const refreshed = await api("/api/auth/refresh", { method: "POST", json: { refreshToken: tokens.refreshToken } });
  const newTokens = await refreshed.json();
  check("refresh = 200", refreshed.status === 200 && newTokens.accessToken);
  const replay = await api("/api/auth/refresh", { method: "POST", json: { refreshToken: tokens.refreshToken } });
  check("old refresh token cannot be reused (401)", replay.status === 401);

  const tokenA = newTokens.accessToken;

  console.log("\n[3] Upload validation");
  const fake = await api("/api/scans", { method: "POST", token: tokenA, form: uploadForm(Buffer.from("hello not a pe file ".repeat(10)), "fake.exe") });
  check("non-PE with .exe name = 400", fake.status === 400);

  const wrongExt = await api("/api/scans", { method: "POST", token: tokenA, form: uploadForm(makeFakePE(), "file.txt") });
  check("wrong extension = 400", wrongExt.status === 400);

  const empty = await api("/api/scans", { method: "POST", token: tokenA, form: uploadForm(Buffer.alloc(0), "empty.exe") });
  check("empty file = 400", empty.status === 400);

  const traversal = await api("/api/scans", { method: "POST", token: tokenA, form: uploadForm(makeFakePE(), "..%2f..%2fevil.exe".replace(/%2f/g, "/")) });
  check("path traversal filename = 400", traversal.status === 400);

  console.log("\n[4] Valid upload -> scan");
  const pe = makeFakePE();
  const expectedHash = crypto.createHash("sha256").update(pe).digest("hex");
  const up = await api("/api/scans", { method: "POST", token: tokenA, form: uploadForm(pe, "good.exe") });
  const scan = await up.json();
  check("valid PE = 201", up.status === 201, JSON.stringify(scan));
  check("sha256 matches", scan.sha256 === expectedHash);
  check("verdict + riskScore present", ["benign", "malicious"].includes(scan.verdict) && Number.isInteger(scan.riskScore));
  check("5 explanation features", Array.isArray(scan.explanation) && scan.explanation.length === 5);
  check("storage path not exposed", scan.storagePath === undefined);

  const up2 = await api("/api/scans", { method: "POST", token: tokenA, form: uploadForm(pe, "good-again.exe") });
  const scan2 = await up2.json();
  check("same file again flagged duplicate", scan2.duplicate === true);

  console.log("\n[5] History + detail");
  const list = await (await api("/api/scans?page=1&limit=20", { token: tokenA })).json();
  check("history has 2 items", list.total === 2 && list.items.length === 2);
  const detail = await api(`/api/scans/${scan.id}`, { token: tokenA });
  check("detail = 200", detail.status === 200);
  const missing = await api(`/api/scans/${crypto.randomUUID()}`, { token: tokenA });
  check("unknown id = 404", missing.status === 404);

  console.log("\n[6] Download + integrity");
  const dl = await api(`/api/scans/${scan.id}/download`, { token: tokenA });
  const dlBuf = Buffer.from(await dl.arrayBuffer());
  check("download = 200", dl.status === 200);
  check("downloaded bytes hash = original hash", crypto.createHash("sha256").update(dlBuf).digest("hex") === expectedHash);

  console.log("\n[7] Ownership (another user)");
  const userB = await register(`b${stamp}@t.com`, password);
  const forbidden = await api(`/api/scans/${scan.id}`, { token: userB.accessToken });
  check("other user detail = 403", forbidden.status === 403);
  const forbiddenDl = await api(`/api/scans/${scan.id}/download`, { token: userB.accessToken });
  check("other user download = 403", forbiddenDl.status === 403);
  const forbiddenDel = await api(`/api/scans/${scan.id}`, { method: "DELETE", token: userB.accessToken });
  check("other user delete = 403", forbiddenDel.status === 403);
  const listB = await (await api("/api/scans", { token: userB.accessToken })).json();
  check("other user history is empty", listB.total === 0);

  console.log("\n[8] Delete");
  const del = await api(`/api/scans/${scan.id}`, { method: "DELETE", token: tokenA });
  check("delete = 204", del.status === 204);
  const after = await api(`/api/scans/${scan.id}`, { token: tokenA });
  check("deleted scan = 404", after.status === 404);

  console.log("\n[9] Logout");
  const out = await api("/api/auth/logout", { method: "POST", json: { refreshToken: newTokens.refreshToken } });
  check("logout = 204", out.status === 204);
  const afterOut = await api("/api/auth/refresh", { method: "POST", json: { refreshToken: newTokens.refreshToken } });
  check("refresh after logout = 401", afterOut.status === 401);

  console.log("\n[10] Login rate limit (6 wrong attempts)");
  let lastStatus = 0;
  for (let i = 0; i < 6; i++) {
    const r = await api("/api/auth/login", { method: "POST", json: { email: `a${stamp}@t.com`, password: "Wrong@1234" } });
    lastStatus = r.status;
  }
  check("6th wrong attempt = 429", lastStatus === 429);

  console.log(`\nResult: ${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
}

main().catch((e) => {
  console.error("Smoke test crashed (is the server running?):", e.message);
  process.exit(1);
});
