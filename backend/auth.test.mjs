import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

async function startApi() {
  const directory = await mkdtemp(join(tmpdir(), "qr-sentinel-auth-"));
  const port = 18000 + Math.floor(Math.random() * 1000);
  const child = spawn(process.execPath, ["backend/server.mjs"], {
    cwd: process.cwd(),
    env: { ...process.env, PORT: String(port), DATABASE_PATH: join(directory, "test.db") },
    stdio: ["ignore", "pipe", "pipe"],
  });

  const baseUrl = `http://127.0.0.1:${port}`;
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`API exited before startup with code ${child.exitCode}.`);
    try {
      const response = await fetch(`${baseUrl}/api/health`);
      if (response.ok) return { baseUrl, child, directory };
    } catch { /* API is still starting. */ }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  child.kill();
  await rm(directory, { recursive: true, force: true });
  throw new Error("API did not start in time.");
}

test("protects application data and supports login, registration, and logout", async (context) => {
  const api = await startApi();
  context.after(async () => {
    api.child.kill();
    await new Promise((resolve) => api.child.once("exit", resolve));
    await rm(api.directory, { recursive: true, force: true });
  });

  const unauthenticated = await fetch(`${api.baseUrl}/api/scans`);
  assert.equal(unauthenticated.status, 401);

  const login = await fetch(`${api.baseUrl}/api/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username: "qradmin", password: "qradmin123" }),
  });
  assert.equal(login.status, 200);
  assert.equal((await login.json()).user.role, "admin");
  const adminCookie = login.headers.get("set-cookie")?.split(";", 1)[0];
  assert.ok(adminCookie);

  const authorized = await fetch(`${api.baseUrl}/api/scans`, { headers: { cookie: adminCookie } });
  assert.equal(authorized.status, 200);

  const registration = await fetch(`${api.baseUrl}/api/auth/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username: "new_user", email: "new.user@gmail.com", password: "secure-pass-123" }),
  });
  assert.equal(registration.status, 201);
  assert.equal((await registration.json()).user.role, "user");

  const duplicate = await fetch(`${api.baseUrl}/api/auth/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username: "new_user", email: "another@gmail.com", password: "secure-pass-123" }),
  });
  assert.equal(duplicate.status, 409);

  const duplicateEmail = await fetch(`${api.baseUrl}/api/auth/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username: "different_user", email: "NEW.USER@gmail.com", password: "secure-pass-123" }),
  });
  assert.equal(duplicateEmail.status, 409);

  const numericUsername = await fetch(`${api.baseUrl}/api/auth/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username: "123456", email: "numbers@gmail.com", password: "secure-pass-123" }),
  });
  assert.equal(numericUsername.status, 400);

  const nonGmailAddress = await fetch(`${api.baseUrl}/api/auth/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username: "valid_user", email: "user@example.com", password: "secure-pass-123" }),
  });
  assert.equal(nonGmailAddress.status, 400);

  const logout = await fetch(`${api.baseUrl}/api/auth/logout`, {
    method: "POST",
    headers: { cookie: adminCookie },
  });
  assert.equal(logout.status, 200);
  const rejectedAfterLogout = await fetch(`${api.baseUrl}/api/scans`, { headers: { cookie: adminCookie } });
  assert.equal(rejectedAfterLogout.status, 401);
});
