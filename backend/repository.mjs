const repositoryPromise = process.env.DATABASE_URL
  ? import("./postgres-database.mjs")
  : import("./database.mjs");

async function call(method, ...args) {
  const repository = await repositoryPromise;
  return repository[method](...args);
}

export const registerUser = (input) => call("registerUser", input);
export const authenticateUser = (username, password) => call("authenticateUser", username, password);
export const createSession = (userId) => call("createSession", userId);
export const getSessionUser = (token) => call("getSessionUser", token);
export const deleteSession = (token) => call("deleteSession", token);
export const findIocMatches = (observables) => call("findIocMatches", observables);
export const saveScan = (result, input) => call("saveScan", result, input);
export const listScans = (limit, userId) => call("listScans", limit, userId);
export const listIocs = (activeOnly) => call("listIocs", activeOnly);
export const addIoc = (input) => call("addIoc", input);
export const deleteIoc = (id) => call("deleteIoc", id);
export const reviewIoc = (id, action) => call("reviewIoc", id, action);
export const getStats = (userId) => call("getStats", userId);
export const logActivity = (userId, action, detail) => call("logActivity", userId, action, detail);
export const listActivity = (limit, userId) => call("listActivity", limit, userId);
export const listUsers = () => call("listUsers");
