// Development Proxy Server for Pakasir API
// Run with: node server/dev-proxy.js  (dari root project)

import { createRequire } from 'module';
import { fileURLToPath } from 'url';
import path from 'path';

// ── Muat .env dari root project ────────────────────────────────────────────
// File ini ada di /server/dev-proxy.js, root project ada satu level di atas
const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..');
const require = createRequire(import.meta.url);

try {
  const dotenv = require('dotenv');
  // Coba muat dari root project dulu
  const result = dotenv.config({ path: path.join(projectRoot, '.env') });
  if (result.error) {
    // Fallback: coba dari CWD (berguna jika dijalankan dari root)
    const fallback = dotenv.config();
    if (fallback.error) {
      console.warn('⚠️  .env tidak ditemukan di', path.join(projectRoot, '.env'), 'maupun CWD:', process.cwd());
    } else {
      console.log('✅ .env dimuat dari CWD:', process.cwd());
    }
  } else {
    console.log('✅ .env dimuat dari:', path.join(projectRoot, '.env'));
  }
} catch (e) {
  console.warn('⚠️  dotenv tidak tersedia:', e.message, '— pastikan dotenv sudah di-install (npm install dotenv)');
}

// ── Verifikasi kritis: cetak status env var ────────────────────────────────
console.log('🔑 PAKASIR_API_KEY loaded:', !!process.env.PAKASIR_API_KEY);
console.log('📦 Project slug:', process.env.PAKASIR_SLUG || process.env.PAKASIR_PROJECT || '(fallback: feelin)');
// ──────────────────────────────────────────────────────────────────────────

import express from 'express';
import cors from 'cors';

const app = express();
const PORT = process.env.PORT || 3001;

// Enable CORS for local development
app.use(cors());
app.use(express.json());

// Pakasir API credentials (read from env in dev)
// .env pakai PAKASIR_SLUG, dengan fallback ke PAKASIR_PROJECT untuk backward compat
const PAKASIR_PROJECT = process.env.PAKASIR_SLUG || process.env.PAKASIR_PROJECT || 'feelin';
const PAKASIR_API_KEY = process.env.PAKASIR_API_KEY;
if (!PAKASIR_API_KEY) {
  console.warn('⚠️  PAKASIR_API_KEY not set — returning mocked responses');
}

// Proxy endpoint for creating QRIS transactions
app.post('/api/pakasir-create-transaction', async (req, res) => {
  try {
    const { order_id, amount, payment_method = 'qris' } = req.body;

    console.log('📦 Creating Pakasir transaction:', { order_id, amount, payment_method });
    console.log('📥 Incoming request body:', JSON.stringify(req.body));

    if (!order_id || !amount) {
      return res.status(400).json({ error: 'order_id and amount are required' });
    }

    // If API key is not set, return a mocked response to allow local development
    if (!PAKASIR_API_KEY) {
      console.warn('PAKASIR_API_KEY not set — returning mocked Pakasir response for local development');
      const mockPayment = {
        payment_number: `MOCKQR:${order_id}:${amount}`,
        payment_method: payment_method,
        total_payment: amount,
        expired_at: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
        project: PAKASIR_PROJECT,
        order_id
      };
      return res.status(200).json({ success: true, payment: mockPayment });
    }

    // Ensure fetch implementation is available (lazy import of node-fetch)
    let fetchImpl = globalThis.fetch;
    if (!fetchImpl) {
      try {
        const nf = await import('node-fetch');
        fetchImpl = nf.default || nf;
        globalThis.fetch = fetchImpl;
      } catch (e) {
        console.error('Fetch implementation unavailable and node-fetch could not be imported', e);
        return res.status(500).json({ error: 'Server misconfiguration: fetch not available' });
      }
    }

    // Call Pakasir API via the resolved fetch implementation
    let pakasirResponse;
    try {
      pakasirResponse = await fetchImpl(
        `https://app.pakasir.com/api/transactioncreate/${payment_method}`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            project: PAKASIR_PROJECT,
            order_id: order_id,
            amount: parseInt(amount, 10),
            api_key: PAKASIR_API_KEY,
          }),
        }
      );
    } catch (fetchError) {
      console.error('❌ Network/fetch error when calling Pakasir:', fetchError && fetchError.stack ? fetchError.stack : fetchError);
      return res.status(502).json({ error: 'Network error when calling Pakasir', message: (fetchError && fetchError.message) || String(fetchError) });
    }

    let data;
    try {
      data = await pakasirResponse.json();
    } catch (e) {
      // Try to get plain text for diagnostics
      let txt = '';
      try { txt = await pakasirResponse.text(); } catch (ee) { txt = `failed-to-read-text: ${ee.message}`; }
      console.error('Failed to parse Pakasir response as JSON', e, 'raw:', txt);
      return res.status(502).json({ error: 'Invalid response from Pakasir', details: txt });
    }

    console.log('✅ Pakasir response:', data);

    if (!pakasirResponse.ok) {
      console.error('❌ Pakasir API error:', data);
      return res.status(pakasirResponse.status).json({ 
        error: 'Failed to create transaction',
        details: data 
      });
    }

    // Return the payment data
    return res.status(200).json(data);

  } catch (error) {
    console.error('❌ Error creating Pakasir transaction:', error && error.stack ? error.stack : error);
    return res.status(500).json({ 
      error: 'Internal server error',
      message: error && error.message ? error.message : String(error) 
    });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ── /api/pakasir?action=status|cancel|simulate ─────────────────────────────
// Dipakai oleh pakasirService.getTransactionStatus, cancelTransaction, simulatePayment

app.get('/api/pakasir', async (req, res) => {
  const { action, orderId, amount } = req.query;
  if (action !== 'status') {
    return res.status(400).json({ error: 'GET hanya mendukung action=status' });
  }
  if (!orderId || !amount) {
    return res.status(400).json({ error: 'orderId dan amount wajib diisi' });
  }
  if (!PAKASIR_API_KEY) {
    // Mock response supaya development tetap berjalan tanpa API key
    console.warn('⚠️  PAKASIR_API_KEY tidak di-set — mengembalikan mock status response');
    return res.status(200).json({
      success: true,
      data: {
        order_id: orderId,
        amount: parseInt(amount, 10),
        status: 'pending',
        found: false,
        payment_method: 'qris',
        completed_at: null
      }
    });
  }
  try {
    let fetchImpl = globalThis.fetch;
    if (!fetchImpl) {
      const nf = await import('node-fetch');
      fetchImpl = nf.default || nf;
      globalThis.fetch = fetchImpl;
    }
    const url = `https://app.pakasir.com/api/transactiondetail?project=${PAKASIR_PROJECT}&amount=${encodeURIComponent(amount)}&order_id=${encodeURIComponent(orderId)}&api_key=${PAKASIR_API_KEY}`;
    const response = await fetchImpl(url);
    const data = await response.json();
    console.log('📊 Pakasir status response:', data);
    if (data.transaction) {
      return res.status(200).json({
        success: true,
        data: {
          order_id: data.transaction.order_id,
          amount: data.transaction.amount,
          status: data.transaction.status,
          found: true,
          payment_method: data.transaction.payment_method,
          completed_at: data.transaction.completed_at
        }
      });
    }
    return res.status(200).json({ success: false, found: false, data: data });
  } catch (error) {
    console.error('❌ Error getting transaction status:', error);
    return res.status(500).json({ error: 'Internal server error', message: error.message });
  }
});

app.post('/api/pakasir', async (req, res) => {
  const { action } = req.query;
  const { orderId, amount } = req.body;

  if (!orderId || !amount) {
    return res.status(400).json({ error: 'orderId dan amount wajib diisi' });
  }
  if (!PAKASIR_API_KEY) {
    console.warn('⚠️  PAKASIR_API_KEY tidak di-set — mengembalikan mock response untuk action:', action);
    return res.status(200).json({ success: true, data: { order_id: orderId, action, mocked: true } });
  }

  let endpoint;
  if (action === 'cancel') endpoint = 'transactioncancel';
  else if (action === 'simulate') endpoint = 'paymentsimulation';
  else return res.status(400).json({ error: 'POST mendukung action=cancel atau action=simulate' });

  try {
    let fetchImpl = globalThis.fetch;
    if (!fetchImpl) {
      const nf = await import('node-fetch');
      fetchImpl = nf.default || nf;
      globalThis.fetch = fetchImpl;
    }
    const response = await fetchImpl(`https://app.pakasir.com/api/${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        project: PAKASIR_PROJECT,
        order_id: orderId,
        amount: parseInt(amount, 10),
        api_key: PAKASIR_API_KEY
      })
    });
    const data = await response.json();
    return res.status(200).json({ success: true, data });
  } catch (error) {
    console.error(`❌ Error on action=${action}:`, error);
    return res.status(500).json({ error: 'Internal server error', message: error.message });
  }
});
// ──────────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n🚀 Dev Proxy Server running on http://localhost:${PORT}`);
  console.log(`📡 Pakasir API proxy available at: POST http://localhost:${PORT}/api/pakasir-create-transaction`);
  console.log('\n💡 Make sure Vite dev server is also running on port 3000\n');
});