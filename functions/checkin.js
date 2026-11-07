
function decodeBase64Url(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - base64.length % 4) % 4);
  const binary = atob(padded);

  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

async function verifyTicket(payload, signature, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );

  return crypto.subtle.verify(
    "HMAC",
    key,
    decodeBase64Url(signature),
    new TextEncoder().encode(payload)
  );
}

export async function onRequestPost({ request, env }) {
  try {
    // Organizer authentication
    const suppliedPin = request.headers.get("X-Checkin-Pin");

    if (!env.CHECKIN_PIN || suppliedPin !== env.CHECKIN_PIN) {
      return Response.json(
        { success: false, error: "Unauthorized organizer." },
        { status: 401 }
      );
    }

    if (!env.APPS_SCRIPT_URL || !env.APPS_SCRIPT_SECRET) {
      return Response.json(
        { success: false, error: "Check-in service is not configured." },
        { status: 500 }
      );
    }

    const body = await request.json();
    const ticketToken = String(body.ticketToken || "");

    if (ticketToken.length > 10000) {
      return Response.json(
        { success: false, error: "Invalid ticket." },
        { status: 400 }
      );
    }

    const parts = ticketToken.split(".");

    if (parts.length !== 2) {
      return Response.json(
        { success: false, error: "Invalid ticket format." },
        { status: 400 }
      );
    }

    const [payload, signature] = parts;

    const validSignature = await verifyTicket(
      payload,
      signature,
      env.APPS_SCRIPT_SECRET
    );

    if (!validSignature) {
      return Response.json(
        { success: false, error: "Invalid or forged ticket." },
        { status: 401 }
      );
    }

    let registration;

    try {
      registration = JSON.parse(
        new TextDecoder().decode(decodeBase64Url(payload))
      );
    } catch {
      return Response.json(
        { success: false, error: "Invalid ticket data." },
        { status: 400 }
      );
    }

    if (
      !registration.name ||
      !/^\d{9}$/.test(String(registration.registration_number || "")) ||
      !registration.email ||
      !["AbuQir", "Miami", "Alamein"].includes(registration.branch) ||
      !registration.ticketId ||
      !registration.registeredAt
    ) {
      return Response.json(
        { success: false, error: "Incomplete ticket details." },
        { status: 400 }
      );
    }

    const response = await fetch(env.APPS_SCRIPT_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        apiSecret: env.APPS_SCRIPT_SECRET,
        registration
      })
    });

    const result = await response.json();

    return Response.json(result, {
      status: result.success ? 200 : 409
    });

  } catch (error) {
    return Response.json(
      { success: false, error: "Check-in failed. Please try again." },
      { status: 500 }
    );
  }
}
