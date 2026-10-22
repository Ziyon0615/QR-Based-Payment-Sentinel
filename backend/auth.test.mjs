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

  const wrongPassword = await fetch(`${api.baseUrl}/api/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username: "qradmin", password: "wrong-password" }),
  });
  assert.equal(wrongPassword.status, 401);

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
  const registrationBody = await registration.json();
  assert.equal(registrationBody.user.role, "user");
  const userCookie = registration.headers.get("set-cookie")?.split(";", 1)[0];
  assert.ok(userCookie);

  const userScan = await fetch(`${api.baseUrl}/api/analyze`, {
    method: "POST",
    headers: { "content-type": "application/json", cookie: userCookie },
    body: JSON.stringify({ payload: "https://pay.example.com/checkout?amount=100", resolveRedirects: false, source: "test" }),
  });
  assert.equal(userScan.status, 201);

  const userScans = await fetch(`${api.baseUrl}/api/scans`, { headers: { cookie: userCookie } });
  assert.equal(userScans.status, 200);
  const userScansBody = await userScans.json();
  assert.equal(userScansBody.scans.length, 1);
  assert.equal(userScansBody.scans[0].userId, registrationBody.user.id);

  const userStats = await fetch(`${api.baseUrl}/api/stats`, { headers: { cookie: userCookie } });
  assert.equal(userStats.status, 200);
  const userStatsBody = await userStats.json();
  assert.equal(userStatsBody.total, 1);
  assert.equal(userStatsBody.admin, undefined);

  const userActivity = await fetch(`${api.baseUrl}/api/activity`, { headers: { cookie: userCookie } });
  assert.equal(userActivity.status, 200);
  const userActivityBody = await userActivity.json();
  assert.ok(userActivityBody.activity.some((item) => item.action === "qr_scanned"));
  assert.ok(userActivityBody.activity.every((item) => item.userId === registrationBody.user.id));

  const forbiddenUsers = await fetch(`${api.baseUrl}/api/users`, { headers: { cookie: userCookie } });
  assert.equal(forbiddenUsers.status, 403);

  const adminScans = await fetch(`${api.baseUrl}/api/scans`, { headers: { cookie: adminCookie } });
  assert.equal(adminScans.status, 200);
  assert.ok((await adminScans.json()).scans.some((scan) => scan.username === "new_user"));

  const adminStats = await fetch(`${api.baseUrl}/api/stats`, { headers: { cookie: adminCookie } });
  assert.equal(adminStats.status, 200);
  const adminStatsBody = await adminStats.json();
  assert.equal(adminStatsBody.total, 1);
  assert.equal(adminStatsBody.admin.totalUsers, 1);

  const users = await fetch(`${api.baseUrl}/api/users`, { headers: { cookie: adminCookie } });
  assert.equal(users.status, 200);
  assert.ok((await users.json()).users.some((item) => item.username === "new_user" && item.scanCount === 1));

  const selectedUserActivity = await fetch(`${api.baseUrl}/api/activity?userId=${registrationBody.user.id}`, { headers: { cookie: adminCookie } });
  assert.equal(selectedUserActivity.status, 200);
  assert.ok((await selectedUserActivity.json()).activity.every((item) => item.userId === registrationBody.user.id));

  const userIndicator = await fetch(`${api.baseUrl}/api/iocs`, {
    method: "POST",
    headers: { "content-type": "application/json", cookie: userCookie },
    body: JSON.stringify({ indicator: "reported.example", indicatorType: "domain", severity: "high", source: "User report" }),
  });
  assert.equal(userIndicator.status, 201);
  const userIndicatorBody = await userIndicator.json();
  assert.equal(userIndicatorBody.ioc.indicator, "reported.example");

  const activityAfterIndicator = await fetch(`${api.baseUrl}/api/activity`, { headers: { cookie: userCookie } });
  assert.equal(activityAfterIndicator.status, 200);
  assert.ok((await activityAfterIndicator.json()).activity.some((item) => item.action === "indicator_added"));

  const forbiddenDelete = await fetch(`${api.baseUrl}/api/iocs/${userIndicatorBody.ioc.id}`, {
    method: "DELETE",
    headers: { cookie: userCookie },
  });
  assert.equal(forbiddenDelete.status, 403);

  const adminDelete = await fetch(`${api.baseUrl}/api/iocs/${userIndicatorBody.ioc.id}`, {
    method: "DELETE",
    headers: { cookie: adminCookie },
  });
  assert.equal(adminDelete.status, 200);
  assert.equal((await adminDelete.json()).ioc.id, userIndicatorBody.ioc.id);

  const indicatorsAfterDelete = await fetch(`${api.baseUrl}/api/iocs`, { headers: { cookie: adminCookie } });
  assert.equal(indicatorsAfterDelete.status, 200);
  assert.ok(!(await indicatorsAfterDelete.json()).iocs.some((item) => item.id === userIndicatorBody.ioc.id));

  const activityAfterDelete = await fetch(`${api.baseUrl}/api/activity`, { headers: { cookie: adminCookie } });
  assert.equal(activityAfterDelete.status, 200);
  assert.ok((await activityAfterDelete.json()).activity.some((item) => item.action === "indicator_deleted"));

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

  const invalidUsernameCharacters = await fetch(`${api.baseUrl}/api/auth/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username: "invalid user!", email: "valid@gmail.com", password: "secure-pass-123" }),
  });
  assert.equal(invalidUsernameCharacters.status, 400);

  const shortPassword = await fetch(`${api.baseUrl}/api/auth/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username: "valid_user", email: "valid@gmail.com", password: "short" }),
  });
  assert.equal(shortPassword.status, 400);

  const missingGmail = await fetch(`${api.baseUrl}/api/auth/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username: "valid_user", password: "secure-pass-123" }),
  });
  assert.equal(missingGmail.status, 400);

  const logout = await fetch(`${api.baseUrl}/api/auth/logout`, {
    method: "POST",
    headers: { cookie: adminCookie },
  });
  assert.equal(logout.status, 200);
  const rejectedAfterLogout = await fetch(`${api.baseUrl}/api/scans`, { headers: { cookie: adminCookie } });
  assert.equal(rejectedAfterLogout.status, 401);
});
