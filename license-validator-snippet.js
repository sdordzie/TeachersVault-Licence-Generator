/*
Teacher FileVault Enterprise Secure License Validator
Paste this into your main app. Replace TFV_PUBLIC_KEY_JWK with the public key from license-generator-secure.html.
*/
const TFV_PUBLIC_KEY_JWK = null; // paste public JWK object here

async function tfvImportPublicKey() {
  if (!TFV_PUBLIC_KEY_JWK) throw new Error("License public key is not installed.");
  return await crypto.subtle.importKey(
    "jwk",
    TFV_PUBLIC_KEY_JWK,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"]
  );
}

function tfvBase64UrlToBuffer(value) {
  value = String(value).replace(/-/g, "+").replace(/_/g, "/");
  while (value.length % 4) value += "=";
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function tfvValidateLicense(licenseKey, options = {}) {
  const parts = String(licenseKey || "").trim().split(".");
  if (parts.length !== 3 || parts[0] !== "TFV2") {
    return { ok: false, reason: "Invalid license format." };
  }

  try {
    const publicKey = await tfvImportPublicKey();
    const validSignature = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      tfvBase64UrlToBuffer(parts[2]),
      new TextEncoder().encode(parts[1])
    );

    if (!validSignature) return { ok: false, reason: "License signature failed." };

    const payloadText = new TextDecoder().decode(tfvBase64UrlToBuffer(parts[1]));
    const payload = JSON.parse(payloadText);

    if (payload.exp && new Date(payload.exp + "T23:59:59") < new Date()) {
      return { ok: false, reason: "License expired on " + payload.exp, payload };
    }

    if (options.requiredFeature && !payload.features?.includes(options.requiredFeature)) {
      return { ok: false, reason: "Feature not included in license.", payload };
    }

    return { ok: true, payload };
  } catch (error) {
    return { ok: false, reason: error.message };
  }
}

async function tfvCheckOnlineLicenseRegistry({ supabaseUrl, anonKey, licensePayload, deviceId, deviceName }) {
  if (!supabaseUrl || !anonKey || !licensePayload?.license_id) {
    return { ok: true, online: false, reason: "Online registry not configured." };
  }

  const headers = {
    apikey: anonKey,
    Authorization: "Bearer " + anonKey,
    "Content-Type": "application/json"
  };

  const base = supabaseUrl.replace(/\/$/, "");
  const licenseUrl =
    base + "/rest/v1/tfv_licenses?license_id=eq." +
    encodeURIComponent(licensePayload.license_id) + "&select=*";

  const res = await fetch(licenseUrl, { headers });
  if (!res.ok) return { ok: false, online: true, reason: await res.text() };

  const rows = await res.json();
  if (!rows.length) return { ok: false, online: true, reason: "License not registered online." };

  const lic = rows[0];
  if (lic.status === "revoked") return { ok: false, online: true, reason: "License has been revoked." };
  if (lic.status === "suspended") return { ok: false, online: true, reason: "License has been suspended." };

  const activationUrl =
    base + "/rest/v1/tfv_license_activations?license_id=eq." +
    encodeURIComponent(licensePayload.license_id) + "&select=*";

  const actRes = await fetch(activationUrl, { headers });
  const activations = actRes.ok ? await actRes.json() : [];
  const already = activations.find(a => a.device_id === deviceId);

  if (!already && activations.length >= Number(lic.max_devices || licensePayload.max_devices || 1)) {
    return { ok: false, online: true, reason: "Device limit reached for this license." };
  }

  await fetch(base + "/rest/v1/tfv_license_activations", {
    method: "POST",
    headers: { ...headers, Prefer: "resolution=merge-duplicates" },
    body: JSON.stringify([{
      license_id: licensePayload.license_id,
      device_id: deviceId,
      device_name: deviceName || navigator.userAgent,
      school_id: licensePayload.school_id,
      app_version: "enterprise-secure",
      last_seen_at: new Date().toISOString()
    }])
  });

  await fetch(base + "/rest/v1/tfv_license_audit", {
    method: "POST",
    headers,
    body: JSON.stringify([{
      license_id: licensePayload.license_id,
      event_type: "license_verified",
      device_id: deviceId,
      details: { school_id: licensePayload.school_id, plan: licensePayload.plan }
    }])
  });

  return { ok: true, online: true, registry: lic };
}
