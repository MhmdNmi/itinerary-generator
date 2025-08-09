export default {
	async fetch(request, env, ctx) {
		if (request.method !== 'POST') return jsonResponse({ error: 'Only POST is allowed!' }, 405);

		let body;
		try {
			body = await request.json();
		} catch (e) {
			return jsonResponse({ error: 'Invalid JSON!' }, 400);
		}

		const { destination, durationDays } = body;
		if (!destination || typeof destination !== "string" || !Number.isInteger(durationDays) || durationDays <= 0) {
			return jsonResponse({ error: 'Fields destination (string) and durationDays (positive integer) are required!' }, 400);
		}

		const jobId = crypto.randomUUID();
		const createdAt = new Date().toISOString();
		const projectId = env.GCP_PROJECT_ID || (() => { throw new Error('GCP_PROJECT_ID is missing!'); })();

		// Build Firestore initial doc in Firestore REST format
		const initialDoc = {
			fields: {
				status: { stringValue: 'processing' },
				destination: { stringValue: destination },
				durationDays: { integerValue: durationDays.toString() },
				createdAt: { timestampValue: createdAt },
				completedAt: { nullValue: null },
				itinerary: { arrayValue: { values: [] } },
				error: { nullValue: null }
			}
		};

		// Create the document in Firestore BEFORE responding
		try {
			const token = await getGoogleAccessToken(env);
			const createUrl = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/itineraries?documentId=${jobId}`;
			const res = await fetch(createUrl, {
				method: 'POST',
				headers: {
					Authorization: `Bearer ${token}`,
					'Content-Type': 'application/json'
				},
				body: JSON.stringify(initialDoc)
			});
			if (!res.ok) {
				const err = await res.text();
				console.error('Firestore create failed:', res.status, err);
				return jsonResponse({ error: 'Failed to create Firestore document!' }, 500);
			}
		} catch (err) {
			console.error('Error creating initial Firestore doc', err);
			return jsonResponse({ error: 'Server error creating job!' }, 500);
		}

		// Now schedule background work (LLM call + Firestore update)
		ctx.waitUntil(processJob(jobId, destination, durationDays, env));
		
		// Immediately return jobId
		const responseBody = { jobId };
		return jsonResponse(responseBody, 202);
	}
};

/* -------------------------
   Background processing
   ------------------------- */

function buildPrompt(destination, durationDays) {
	return `You are a travel itinerary generator. Return ONLY a single JSON object (no explanation, no markdown, nothing else)
that exactly matches this schema:

{
  "destination": "string",
  "durationDays": integer,
  "itinerary": [
    {
      "day": integer,
      "theme": "string",
      "activities": [
        { "time": "Morning|Afternoon|Evening", "description": "string (concise)", "location": "string" }
      ]
    }
    // ... repeated for each day
  ]
}

Constraints:
- The outer "destination" must equal: "${destination}"
- "durationDays" must equal ${durationDays}
- "itinerary" array MUST have exactly ${durationDays} items.
- Each day's "activities" should be 2-4 items (Morning/Afternoon/Evening recommended).
- Keep descriptions concise (one or two short sentences).
- Use common local places / neighborhoods (no invented 'companies').
- Return only valid JSON.`;
}

async function processJob(jobId, destination, durationDays, env) {
	const projectId = env.GCP_PROJECT_ID;

	try {
		// 1) Call LLM to get itinerary JSON
		const prompt = buildPrompt(destination, durationDays)
		const llmText = await callOpenAI(env.OPENAI_API_KEY, prompt);

		// 2) Parse JSON (LLM is instructed to return only JSON)
		let parsed;
		try {
			parsed = JSON.parse(llmText);
		} catch (e) {
			throw new Error('LLM returned invalid JSON: ' + e.message + ' --- raw: ' + llmText.slice(0, 2000));
		}

		// 3) Basic validation: has itinerary array length === durationDays
		if (!Array.isArray(parsed.itinerary) || parsed.itinerary.length !== durationDays) {
			throw new Error(`Parsed itinerary array invalid or length !== durationDays (${durationDays})`);
		}

		// 4) Convert parsed JS object to Firestore fields
		const docUpdate = {
			fields: {
				status: { stringValue: 'completed' },
				destination: { stringValue: destination },
				durationDays: { integerValue: durationDays.toString() },
				completedAt: { timestampValue: new Date().toISOString() },
				itinerary: jsToFirestoreValue(parsed.itinerary),
				error: { nullValue: null }
			}
		};

		// 5) Write back to Firestore (PATCH the document)
		const token = await getGoogleAccessToken(env);
		const updateUrl = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/itineraries/${jobId}`;
		const res = await fetch(updateUrl, {
			method: 'PATCH',
			headers: {
				Authorization: `Bearer ${token}`,
				'Content-Type': 'application/json'
			},
			body: JSON.stringify(docUpdate)
		});

		if (!res.ok) {
			const text = await res.text();
			throw new Error(`Failed to update Firestore doc: ${res.status} ${text}`);
		}

	} catch (err) {
		console.error('Job failed', jobId, err);
		// Write failure status / error message back to Firestore
		try {
			const token = await getGoogleAccessToken(env);
			const failDoc = {
				fields: {
					status: { stringValue: 'failed' },
					completedAt: { timestampValue: new Date().toISOString() },
					error: { stringValue: String(err.message).slice(0, 1500) }
				}
			};
			const projectId = env.GCP_PROJECT_ID;
			const updateUrl = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/itineraries/${jobId}?mask.fieldPaths=status&mask.fieldPaths=completedAt&mask.fieldPaths=error`;
			await fetch(updateUrl, {
				method: 'PATCH',
				headers: {
					Authorization: `Bearer ${token}`,
					'Content-Type': 'application/json'
				},
				body: JSON.stringify(failDoc)
			});
		} catch (e2) {
			console.error('Failed to write failure state to Firestore', e2);
		}
	}
}

/* -------------------------
   LLM call (OpenAI example)
   ------------------------- */

async function callOpenAI(apiKey, prompt) {
	// Uses Chat Completions
	const body = {
		model: "gpt-4o-mini",
		messages: [
			{ role: 'system', content: 'You are a helpful assistant that returns a strict JSON object as requested.' },
			{ role: 'user', content: prompt }
		],
		temperature: 0.2,
	};

	const r = await fetch('https://api.openai.com/v1/chat/completions', {
		method: 'POST',
		headers: {
			Authorization: `Bearer ${apiKey}`,
			'Content-Type': 'application/json'
		},
		body: JSON.stringify(body)
	});

	if (!r.ok) {
		const txt = await r.text();
		throw new Error('OpenAI error: ' + r.status + ' ' + txt);
	}
	const data = await r.json();
	// get assistant message
	const msg = data.choices?.[0]?.message?.content;
	if (!msg) throw new Error('OpenAI returned no message');
	return msg;
}

/* -------------------------
   Utilities: Firestore JSON mapping, Google OAuth JWT
   ------------------------- */
function jsonResponse(data, status) {
    return new Response(JSON.stringify(data), {
        status,
        headers: { 'Content-Type': 'application/json' }
    });
}

function jsToFirestoreValue(value) {
	// returns a Firestore "Value" object
	if (value === null) return { nullValue: null };
	if (Array.isArray(value)) return { arrayValue: { values: value.map(jsToFirestoreValue) } };
	if (typeof value === 'string') return { stringValue: value };
	if (typeof value === 'boolean') return { booleanValue: value };
	if (typeof value === 'number') {
		if (Number.isInteger(value)) return { integerValue: value.toString() };
		return { doubleValue: value };
	}
	// object/map
	const fields = {};
	for (const [k, v] of Object.entries(value)) fields[k] = jsToFirestoreValue(v);
	return { mapValue: { fields } };
}

/* -------------------------
   Google service-account JWT -> access_token
   Requires env.GCP_SA_KEY to contain the full JSON service account key
   ------------------------- */

async function getGoogleAccessToken(env) {
	const saJson = env.GCP_SA_KEY;
	if (!saJson) throw new Error('GCP_SA_KEY missing (service account JSON)');
	const sa = typeof saJson === 'string' ? JSON.parse(saJson) : saJson;

	const iat = Math.floor(Date.now() / 1000);
	const exp = iat + 3600; // 1 hour
	const header = { alg: 'RS256', typ: 'JWT' };
	const scope = 'https://www.googleapis.com/auth/datastore https://www.googleapis.com/auth/cloud-platform';
	const payload = {
		iss: sa.client_email,
		scope,
		aud: 'https://oauth2.googleapis.com/token',
		exp,
		iat
	};

	const jwt = await signJwtWithPrivateKey(header, payload, sa.private_key);
	// exchange for access_token
	const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
		method: 'POST',
		headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({
			grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
			assertion: jwt
		})
	});
	if (!tokenRes.ok) {
		const t = await tokenRes.text();
		throw new Error('Failed to obtain Google access token: ' + tokenRes.status + ' ' + t);
	}
	const tokenJson = await tokenRes.json();
	if (!tokenJson.access_token) throw new Error('No access_token in token response');
	return tokenJson.access_token;
}

async function signJwtWithPrivateKey(header, payload, privateKeyPem) {
	const enc = new TextEncoder();
	const headerB64 = base64UrlEncode(JSON.stringify(header));
	const payloadB64 = base64UrlEncode(JSON.stringify(payload));
	const toSign = `${headerB64}.${payloadB64}`;

	// import private key (pkcs8)
	const keyData = pemToArrayBuffer(privateKeyPem);
	const cryptoKey = await crypto.subtle.importKey(
		'pkcs8',
		keyData,
		{ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
		false,
		['sign']
	);

	const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', cryptoKey, enc.encode(toSign));
	const sigB64 = base64UrlEncode(new Uint8Array(signature));
	return `${toSign}.${sigB64}`;
}

function pemToArrayBuffer(pem) {
	// strip header/footer
	const b64 = pem.replace(/-----BEGIN [^-]+-----/, '').replace(/-----END [^-]+-----/, '').replace(/\s+/g, '');
	const binary = atob(b64);
	const len = binary.length;
	const bytes = new Uint8Array(len);
	for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
	return bytes.buffer;
}

function base64UrlEncode(input) {
	if (typeof input === 'string') {
		const b = btoa(unescape(encodeURIComponent(input)));
		return b.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
	} else {
		// Uint8Array or ArrayBuffer
		const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
		let binary = '';
		for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
		const b = btoa(binary);
		return b.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
	}
}
