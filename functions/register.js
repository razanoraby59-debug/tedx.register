
const BRANCHES = ["AbuQir", "Miami", "Alamein"];

function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function signPayload(payload, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(payload)
  );

  return toBase64Url(new Uint8Array(signature));
}

export async function onRequestPost({ request, env }) {
  try {
    if (!env.APPS_SCRIPT_SECRET) {
      return Response.json(
        { error: "Registration service is not configured." },
        { status: 500 }
      );
    }

    const data = await request.json();

    const name = String(data.name || "").trim();
    const registration_number = String(data.registration_number || "").trim();
    const email = String(data.email || "").trim().toLowerCase();
    const branch = String(data.branch || "").trim();

    if (!name || !/^\d{9}$/.test(registration_number) ||
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
        !BRANCHES.includes(branch)) {
      return Response.json(
        { error: "Please check your registration details." },
        { status: 400 }
      );
    }

    const registration = {
      name,
      registration_number,
      email,
      branch,
      registeredAt: new Date().toISOString(),
      ticketId: "TDX-" + crypto.randomUUID().replace(/-/g, "").slice(0, 12).toUpperCase()
    };

    const payload = toBase64Url(
      new TextEncoder().encode(JSON.stringify(registration))
    );

    const signature = await signPayload(payload, env.APPS_SCRIPT_SECRET);

    registration.ticketToken = payload + "." + signature;

    return Response.json({
      registration,
      alreadyRegistered: false
    });

  } catch (error) {
    return Response.json(
      { error: "Could not complete registration. Please try again." },
      { status: 500 }
    );
  }
}
