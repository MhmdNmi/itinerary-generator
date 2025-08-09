# Cloudflare Worker + GCP Firestore Integration with LLM Processing

This project uses a **Cloudflare Worker** to accept incoming requests, send an immediate `202 Accepted` response, and then run a background Large Language Model (LLM) call and store results in **Google Cloud Firestore**.

---

## 1. Setup

### 1.1 Create a GCP Service Account
1. Go to [Google Cloud Console](https://console.cloud.google.com/).
2. Create a **new project** or choose an existing one.
3. Enable the **Firestore API**:
   - Navigation menu → `APIs & Services` → `Enable APIs and Services` → search for `Firestore API` → Enable.
4. Create a **Service Account**:
   - Navigation menu → `IAM & Admin` → `Service Accounts` → Create Service Account.
5. Assign roles:
   - Minimum required role: **Cloud Datastore User** (for Firestore access).
6. Create a **JSON key** for this service account and download it.

---

### 1.2 Set Cloudflare Secrets
Login and configure Wrangler:
```bash
wrangler login
# Follow the link to login Cloudflare
```

Store your GCP credentials (GCP project ID, and GCP service account JSON) securely in Cloudflare.
```bash
wrangler secret put GCP_PROJECT_ID
# Enter your project ID (e.g., my-gcp-project-123)

# Store the entire GCP service account JSON as a single secret
wrangler secret put GCP_SA_KEY
# Paste the JSON content (from the file you downloaded) when prompted
```

Store your OpenAI API Key securely in Cloudflare.
```bash
wrangler secret put OPENAI_API_KEY
# Paste the OpenAI API Key (e.g., sk-proj-...) when prompted
```

### 1.3 Deploy the Worker
```bash
wrangler deploy
```

## 2. How It Works
- Immediate Response: The Worker returns '202 Accepted' right away to the client to avoid long waits.
- Background Processing: The LLM API call and Firestore writes happen inside an new thread, so they run asynchronously after the HTTP response is sent.

## 3. Prompt Design Rationale
This Worker is built so that:
- The prompt sent to the LLM is deterministic and structured for parsing.
- The Worker ensures no blocking of the client request.
- Firestore writes are separated from request-response flow, improving latency.

## 4. Examples
### 4.1 Using curl
```bash
curl -X POST "https://your-worker.your-subdomain.workers.dev" -k \
  -H "Content-Type: application/json" \
  -d '{
    "destination":"New York, US",
    "durationDays":10
}'
```

### 4.2 Using JavaScript fetch
```js
fetch(
    "https://your-worker.your-subdomain.workers.dev/",
    {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            "destination": "New York, US",
            "durationDays": -10
        }),
        redirect: "follow"
    }
).then((response) => response.text())
.then((result) => console.log(result))
.catch((error) => console.error(error));
```

## 5. Security Notes
- Rotate keys regularly — delete and recreate your GCP Service Account keys periodically.
- Restrict roles — the service account should have only the permissions needed (e.g., Firestore access only).
- Never commit your service account JSON to Git or any public repository.
- Keep your Cloudflare secrets secure.