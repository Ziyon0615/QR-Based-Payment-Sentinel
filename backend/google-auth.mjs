import { OAuth2Client } from "google-auth-library";

let verifier;

function googleClientId() {
  const clientId = process.env.GOOGLE_CLIENT_ID || process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID;
  if (!clientId) throw new Error("Google Sign-In is not configured on the server.");
  return clientId;
}

export async function verifyGoogleCredential(credentialInput) {
  const credential = String(credentialInput || "").trim();
  if (!credential) throw new Error("Google credential is required.");
  if (credential.length > 8192) throw new Error("Google credential is invalid.");

  const clientId = googleClientId();
  verifier ||= new OAuth2Client(clientId);

  let payload;
  try {
    const ticket = await verifier.verifyIdToken({ idToken: credential, audience: clientId });
    payload = ticket.getPayload();
  } catch {
    throw new Error("Google authentication could not be verified. Please try again.");
  }

  if (!payload?.sub || !payload.email || payload.email_verified !== true) {
    throw new Error("Google did not provide a verified email address.");
  }

  return {
    subject: payload.sub,
    email: payload.email.toLowerCase(),
    emailVerified: true,
    name: payload.name || null,
    picture: payload.picture || null,
  };
}
