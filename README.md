# 🖥️ PBX SHIELD — Standalone Decoupled Frontend

This repository contains the **Standalone Frontend Dashboard** for **PBX Shield**. It can be deployed on any web host (**Vercel, Netlify, GitHub Pages, AWS S3**) or run locally on any laptop.

---

## 🚀 1-Click Deployment Instructions

### Option 1: Deploy on Vercel
1. Import this repository (`PBX_ml_frontend`) into **Vercel**.
2. Click **Deploy**! (Vercel automatically detects `index.html`).

### Option 2: Deploy on Netlify
1. Drag and drop this folder into **Netlify Drop**, or connect this repository.
2. Click **Deploy Site**!

### Option 3: Deploy on GitHub Pages
1. Go to Repository **Settings -> Pages**.
2. Set Source to `main` branch and `/ (root)`.
3. Click **Save**!

### Option 4: Run Locally
```bash
npm install
npm start
```
Open **`http://localhost:3000`** in your browser.

---

## 🔑 Connecting to Your Remote Backend

When opening the Frontend for the first time, enter your Asterisk Server details:

* **Remote Server Host / IP**: `13.126.90.199` (Your Asterisk Server IP)
* **Port Number**: `5000`
* **API Secret Authentication Key**: `pbx-shield-secret-2026`
