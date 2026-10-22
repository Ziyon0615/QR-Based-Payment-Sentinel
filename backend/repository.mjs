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
export const listScans = (limit) => call("listScans", limit);
export const listIocs = () => call("listIocs");
export const addIoc = (input) => call("addIoc", input);
export const getStats = () => call("getStats");
