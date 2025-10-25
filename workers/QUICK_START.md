# ⚡ Quick Start: GitHub → Cloudflare Deployment

## 🎯 5-Minute Setup

### 1️⃣ Download & Push to GitHub
```bash
# In your local folder
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/YOUR-USERNAME/REPO-NAME.git
git push -u origin main
```

### 2️⃣ Get Cloudflare API Token
- Go to: https://dash.cloudflare.com/profile/api-tokens
- Click "Create Token"
- Use "Edit Cloudflare Workers" template
- Copy the token

### 3️⃣ Add Token to GitHub
- GitHub repo → Settings → Secrets → Actions
- New secret: `CLOUDFLARE_API_TOKEN`
- Paste your token

### 4️⃣ Create KV Namespaces
```bash
cd workers
wrangler login
wrangler kv:namespace create "SSL_CACHE"
wrangler kv:namespace create "CT_CACHE"
wrangler kv:namespace create "GEO_CACHE"
```

### 5️⃣ Update KV IDs in `workers/wrangler.toml`
Replace the placeholder IDs with your real KV namespace IDs.

### 6️⃣ Push & Deploy! 🚀
```bash
git add .
git commit -m "Update KV IDs"
git push
```

**Done!** GitHub Actions will automatically deploy to Cloudflare.

---

## 📍 Your Live API
After deployment, your API will be at:
```
https://url-inspector-api.YOUR-SUBDOMAIN.workers.dev
```

## ✅ Test It
```bash
curl "https://YOUR-WORKER-URL.workers.dev/api/status"
```

## 🔄 Future Updates
Just push to GitHub - automatic deployment! ✨

---

**Need detailed help?** See [DEPLOYMENT_GUIDE.md](../DEPLOYMENT_GUIDE.md)
