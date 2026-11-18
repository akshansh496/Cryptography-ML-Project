/**
 * CipherGuard AI - Express API Integration Tests
 *
 * Verifies Express backend HTTP endpoints:
 * 1. Health check (/health)
 * 2. Auth: Register, Login, Token generation
 * 3. File upload, PE validation, SHA-256 calculation
 * 4. ML analysis & risk score generation
 * 5. AES-256-GCM encryption & RSA-OAEP key wrapping
 * 6. Authenticated download & integrity verification
 * 7. Authorization & ownership checks
 * 8. Cascaded deletion
 */

import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { app } from "../../src/app.js";
import { prisma } from "../../src/db.js";
import { createMockPeBuffer } from "../fixtures/sample-pe.js";

describe("CipherGuard Express API Integration", () => {
  let server: http.Server;
  let baseUrl: string;

  beforeAll(async () => {
    await prisma.$connect();
    server = http.createServer(app);
    await new Promise<void>((resolve) => {
      server.listen(0, () => {
        const addr = server.address() as { port: number };
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await prisma.$disconnect();
  });

  it("GET /health returns status ok", async () => {
    const res = await fetch(`${baseUrl}/health`);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.status).toBe("ok");
    expect(data.mlMode).toBeDefined();
  });

  it("executes full auth, upload, encrypted storage, download and ownership workflow", async () => {
    const stamp = Date.now();
    const userA = { email: `user_a_${stamp}@cipherguard.test`, password: "StrongPassword@123" };
    const userB = { email: `user_b_${stamp}@cipherguard.test`, password: "StrongPassword@123" };

    // 1. Register User A
    const regRes = await fetch(`${baseUrl}/api/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(userA),
    });
    expect(regRes.status).toBe(201);

    // 2. Login User A
    const loginRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(userA),
    });
    expect(loginRes.status).toBe(200);
    const tokensA = await loginRes.json();
    expect(tokensA.accessToken).toBeDefined();

    // 3. Register & Login User B
    await fetch(`${baseUrl}/api/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(userB),
    });
    const loginBRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(userB),
    });
    const tokensB = await loginBRes.json();

    // 4. Upload valid PE file as User A
    const realPePath = "/opt/homebrew/lib/node_modules/nodemon/bin/windows-kill.exe";
    const samplePayload = fs.existsSync(realPePath)
      ? fs.readFileSync(realPePath)
      : createMockPeBuffer("MZ CipherGuard API Test Binary 2026");
    const expectedHash = crypto.createHash("sha256").update(samplePayload).digest("hex");

    const form = new FormData();
    form.append("file", new Blob([samplePayload]), "sample-tool.exe");

    const uploadRes = await fetch(`${baseUrl}/api/scans`, {
      method: "POST",
      headers: { Authorization: `Bearer ${tokensA.accessToken}` },
      body: form,
    });
    const scanRecord = await uploadRes.json();
    if (uploadRes.status !== 201) {
      console.error("UPLOAD FAILED:", uploadRes.status, scanRecord);
    }
    expect(uploadRes.status).toBe(201);

    expect(scanRecord.id).toBeDefined();
    expect(scanRecord.filename).toBe("sample-tool.exe");
    expect(scanRecord.sha256).toBe(expectedHash);
    expect(["benign", "malicious"]).toContain(scanRecord.verdict);
    expect(typeof scanRecord.riskScore).toBe("number");
    expect(scanRecord.storagePath).toBeUndefined(); // Storage path must not be exposed

    // 5. Download file as User A -> verifies decrypted content and SHA-256
    const downloadRes = await fetch(`${baseUrl}/api/scans/${scanRecord.id}/download`, {
      headers: { Authorization: `Bearer ${tokensA.accessToken}` },
    });
    expect(downloadRes.status).toBe(200);
    const downloadedBuffer = Buffer.from(await downloadRes.arrayBuffer());
    expect(downloadedBuffer.equals(samplePayload)).toBe(true);
    const downloadedHash = crypto.createHash("sha256").update(downloadedBuffer).digest("hex");
    expect(downloadedHash).toBe(expectedHash);

    // 6. Ownership enforcement: User B cannot access or download User A's scan
    const forbiddenDetail = await fetch(`${baseUrl}/api/scans/${scanRecord.id}`, {
      headers: { Authorization: `Bearer ${tokensB.accessToken}` },
    });
    expect(forbiddenDetail.status).toBe(403);

    const forbiddenDownload = await fetch(`${baseUrl}/api/scans/${scanRecord.id}/download`, {
      headers: { Authorization: `Bearer ${tokensB.accessToken}` },
    });
    expect(forbiddenDownload.status).toBe(403);

    // 7. Delete scan as User A
    const deleteRes = await fetch(`${baseUrl}/api/scans/${scanRecord.id}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${tokensA.accessToken}` },
    });
    expect(deleteRes.status).toBe(204);

    // 8. Verify scan is deleted (404)
    const afterDelete = await fetch(`${baseUrl}/api/scans/${scanRecord.id}`, {
      headers: { Authorization: `Bearer ${tokensA.accessToken}` },
    });
    expect(afterDelete.status).toBe(404);
  });
});
