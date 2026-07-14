require('dotenv').config();
const cron = require('node-cron');
const axios = require('axios');
const { createClient } = require('@supabase/supabase-js');
const tls = require('tls');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

async function checkDomain(webApp) {
  const start = Date.now();
  let isOnline = false;
  let statusCode = null;
  let responseTime = null;

  try {
    const res = await axios.get(webApp.url, {
      timeout: 10000,
      maxRedirects: 5,
      validateStatus: () => true
    });
    isOnline = res.status < 500;
    statusCode = res.status;
    responseTime = Date.now() - start;
  } catch (err) {
    isOnline = false;
    statusCode = null;
    responseTime = null;
  }

  await supabase.from('DomainCheck').insert({
    id: crypto.randomUUID(),
    webAppId: webApp.id,
    isOnline,
    statusCode,
    responseTime,
    checkedAt: new Date().toISOString()
  });

  console.log(`[${new Date().toISOString()}] ${webApp.url} → ${isOnline ? 'ONLINE' : 'OFFLINE'} (${statusCode}) ${responseTime}ms`);
}


async function checkSsl(webApp) {
  return new Promise((resolve) => {
    try {
      const url = new URL(webApp.url);
      if (url.protocol !== 'https:') {
        supabase.from('SslCheck').insert({
          id: crypto.randomUUID(),
          webAppId: webApp.id,
          isValid: false,
          issuer: null,
          expiryDate: null,
          daysRemaining: null,
          checkedAt: new Date().toISOString()
        }).then(() => resolve());
        return;
      }

      const socket = tls.connect(443, url.hostname, { servername: url.hostname }, async () => {
        const cert = socket.getPeerCertificate();
        const expiryDate = new Date(cert.valid_to);
        const daysRemaining = Math.floor((expiryDate - Date.now()) / (1000 * 60 * 60 * 24));
        const issuer = cert.issuer?.O || null;
        const isValid = socket.authorized && daysRemaining > 0;

        await supabase.from('SslCheck').insert({
          id: crypto.randomUUID(),
          webAppId: webApp.id,
          isValid,
          issuer,
          expiryDate: expiryDate.toISOString(),
          daysRemaining,
          checkedAt: new Date().toISOString()
        });

        console.log(`[SSL] ${webApp.url} → ${isValid ? 'VALID' : 'INVALID'} | Expires: ${expiryDate.toDateString()} (${daysRemaining} hari)`);
        socket.destroy();
        resolve();
      });

      socket.on('error', async (err) => {
        await supabase.from('SslCheck').insert({
          id: crypto.randomUUID(),
          webAppId: webApp.id,
          isValid: false,
          issuer: null,
          expiryDate: null,
          daysRemaining: null,
          checkedAt: new Date().toISOString()
        });
        console.log(`[SSL] ${webApp.url} → ERROR: ${err.message}`);
        resolve();
      });

      socket.setTimeout(10000, () => {
        socket.destroy();
        resolve();
      });

    } catch (err) {
      console.log(`[SSL] ${webApp.url} → PARSE ERROR: ${err.message}`);
      resolve();
    }
  });
}

async function checkSecurityHeaders(webApp) {
  try {
    const res = await axios.get(webApp.url, {
      timeout: 10000,
      maxRedirects: 5,
      validateStatus: () => true
    });

    const headers = res.headers;
    const hasHsts = !!headers['strict-transport-security'];
    const hasXFrame = !!headers['x-frame-options'];
    const hasXContent = !!headers['x-content-type-options'];
    const hasCsp = !!headers['content-security-policy'];
    const score = [hasHsts, hasXFrame, hasXContent, hasCsp].filter(Boolean).length * 25;

    await supabase.from('SecurityHeaderCheck').insert({
      id: crypto.randomUUID(),
      webAppId: webApp.id,
      hasHsts,
      hasXFrame,
      hasXContent,
      hasCsp,
      score,
      checkedAt: new Date().toISOString()
    });

    console.log(`[HEADERS] ${webApp.url} → Score: ${score}/100 | HSTS:${hasHsts} XFrame:${hasXFrame} XContent:${hasXContent} CSP:${hasCsp}`);
  } catch (err) {
    console.log(`[HEADERS] ${webApp.url} → ERROR: ${err.message}`);
  }
}

async function checkPageSpeed(webApp) {
  const apiKey = process.env.PAGESPEED_API_KEY;
  if (!apiKey) return;

  try {
    const url = `https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=${encodeURIComponent(webApp.url)}&key=${apiKey}&strategy=mobile&category=performance&category=accessibility&category=best-practices&category=seo`;
    
    const res = await axios.get(url, { timeout: 30000 });
    const categories = res.data.lighthouseResult?.categories;

    const performance = Math.round((categories?.performance?.score ?? 0) * 100);
    const accessibility = Math.round((categories?.accessibility?.score ?? 0) * 100);
    const bestPractices = Math.round((categories?.['best-practices']?.score ?? 0) * 100);
    const seo = Math.round((categories?.seo?.score ?? 0) * 100);
    const overall = Math.round((performance + accessibility + bestPractices + seo) / 4);

    // Upsert — update kalau sudah ada, insert kalau belum
    const { data: existing } = await supabase
      .from('AuditTeknis')
      .select('id')
      .eq('webAppId', webApp.id)
      .limit(1);

    if (existing && existing.length > 0) {
      await supabase.from('AuditTeknis').update({
        pageSpeedScore: overall,
        pageSpeedPerformance: performance,
        pageSpeedAccessibility: accessibility,
        pageSpeedBestPractices: bestPractices,
        pageSpeedSeo: seo,
        pageSpeedCheckedAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      }).eq('webAppId', webApp.id);
    } else {
      await supabase.from('AuditTeknis').insert({
        id: crypto.randomUUID(),
        webAppId: webApp.id,
        pageSpeedScore: overall,
        pageSpeedPerformance: performance,
        pageSpeedAccessibility: accessibility,
        pageSpeedBestPractices: bestPractices,
        pageSpeedSeo: seo,
        pageSpeedCheckedAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      });
    }

    console.log(`[PAGESPEED] ${webApp.url} → Score: ${overall}/100 (P:${performance} A:${accessibility} BP:${bestPractices} SEO:${seo})`);
  } catch (err) {
    console.log(`[PAGESPEED] ${webApp.url} → ERROR: ${err.message}`);
  }
}

async function createFindingIfNeeded(webApp, checkResults) {
  const { isOnline, statusCode, sslValid, daysRemaining, headersScore } = checkResults;
  const candidates = [];

  if (!isOnline) {
    candidates.push({
      judul: 'Website Offline',
      deskripsi: `${webApp.url} tidak dapat diakses. HTTP status: ${statusCode || 'timeout'}`,
      severity: 'HIGH'
    });
  }

  if (sslValid === false) {
    candidates.push({
      judul: 'SSL Certificate Bermasalah',
      deskripsi: `${webApp.url} memiliki SSL tidak valid atau gagal handshake`,
      severity: 'HIGH'
    });
  }

  if (daysRemaining !== null && daysRemaining <= 30) {
    candidates.push({
      judul: 'SSL Certificate Akan Expired',
      deskripsi: `${webApp.url} SSL akan expired dalam ${daysRemaining} hari`,
      severity: daysRemaining <= 7 ? 'HIGH' : 'MEDIUM'
    });
  }

  if (headersScore !== null && headersScore < 50) {
    candidates.push({
      judul: 'Security Headers Tidak Lengkap',
      deskripsi: `${webApp.url} mendapat skor security headers ${headersScore}/100`,
      severity: 'MEDIUM'
    });
  }

  for (const candidate of candidates) {
    // Cek apakah finding dengan judul sama sudah OPEN
    const { data: existing } = await supabase
      .from('Finding')
      .select('id')
      .eq('webAppId', webApp.id)
      .eq('judul', candidate.judul)
      .eq('status', 'OPEN')
      .limit(1);

    if (existing && existing.length > 0) {
      console.log(`[FINDING] ${webApp.url} → "${candidate.judul}" sudah ada, skip`);
      continue;
    }

    await supabase.from('Finding').insert({
      id: crypto.randomUUID(),
      webAppId: webApp.id,
      judul: candidate.judul,
      deskripsi: candidate.deskripsi,
      severity: candidate.severity,
      status: 'OPEN',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    });

    console.log(`[FINDING] ${webApp.url} → "${candidate.judul}" dibuat`);
await sendTelegram(
  `🚨 <b>Temuan Baru</b>\n\n` +
  `🌐 <b>Domain:</b> ${webApp.url}\n` +
  `📋 <b>Temuan:</b> ${candidate.judul}\n` +
  `⚠️ <b>Severity:</b> ${candidate.severity}\n\n` +
  `Cek dashboard: https://simdom.vercel.app/dashboard/monitoring/temuan`
);
  }
}

async function sendTelegram(message) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;
  if (!token || !chatId) return;

  try {
    await axios.post(`https://api.telegram.org/bot${token}/sendMessage`, {
      chat_id: chatId,
      text: message,
      parse_mode: 'HTML'
    });
  } catch (err) {
    console.log(`[TELEGRAM] ERROR: ${err.message}`);
  }
}

async function runChecks() {
  const { data: webApps, error } = await supabase
    .from('WebApp')
    .select('id, url, nama')
    .eq('status', 'AKTIF');

  if (error) {
    console.error('Gagal ambil data WebApp:', error.message);
    return;
  }

  console.log(`Checking ${webApps.length} domains...`);

  for (const webApp of webApps) {
    const checkResults = {
      isOnline: false,
      statusCode: null,
      sslValid: null,
      daysRemaining: null,
      headersScore: null
    };

    // HTTP check
    try {
      const start = Date.now();
      const res = await axios.get(webApp.url, {
        timeout: 10000,
        maxRedirects: 5,
        validateStatus: () => true
      });
      checkResults.isOnline = res.status < 500;
      checkResults.statusCode = res.status;
      const responseTime = Date.now() - start;

      await supabase.from('DomainCheck').insert({
        id: crypto.randomUUID(),
        webAppId: webApp.id,
        isOnline: checkResults.isOnline,
        statusCode: checkResults.statusCode,
        responseTime,
        checkedAt: new Date().toISOString()
      });

      console.log(`[HTTP] ${webApp.url} → ${checkResults.isOnline ? 'ONLINE' : 'OFFLINE'} (${checkResults.statusCode})`);
    } catch (err) {
      await supabase.from('DomainCheck').insert({
        id: crypto.randomUUID(),
        webAppId: webApp.id,
        isOnline: false,
        statusCode: null,
        responseTime: null,
        checkedAt: new Date().toISOString()
      });
      console.log(`[HTTP] ${webApp.url} → OFFLINE (timeout)`);
    }

    // SSL check
    await new Promise((resolve) => {
      try {
        const url = new URL(webApp.url);
        if (url.protocol !== 'https:') {
          checkResults.sslValid = false;
          resolve();
          return;
        }
        const socket = tls.connect(443, url.hostname, { servername: url.hostname }, async () => {
          const cert = socket.getPeerCertificate();
          const expiryDate = new Date(cert.valid_to);
          checkResults.daysRemaining = Math.floor((expiryDate - Date.now()) / (1000 * 60 * 60 * 24));
          checkResults.sslValid = socket.authorized && checkResults.daysRemaining > 0;

          await supabase.from('SslCheck').insert({
            id: crypto.randomUUID(),
            webAppId: webApp.id,
            isValid: checkResults.sslValid,
            issuer: cert.issuer?.O || null,
            expiryDate: expiryDate.toISOString(),
            daysRemaining: checkResults.daysRemaining,
            checkedAt: new Date().toISOString()
          });

          console.log(`[SSL] ${webApp.url} → ${checkResults.sslValid ? 'VALID' : 'INVALID'} (${checkResults.daysRemaining} hari)`);
          socket.destroy();
          resolve();
        });

        socket.on('error', async (err) => {
          checkResults.sslValid = false;
          await supabase.from('SslCheck').insert({
            id: crypto.randomUUID(),
            webAppId: webApp.id,
            isValid: false,
            issuer: null,
            expiryDate: null,
            daysRemaining: null,
            checkedAt: new Date().toISOString()
          });
          console.log(`[SSL] ${webApp.url} → ERROR: ${err.message}`);
          resolve();
        });

        socket.setTimeout(10000, () => { socket.destroy(); resolve(); });
      } catch (err) {
        checkResults.sslValid = false;
        resolve();
      }
    });

    // Security headers check
    try {
      const res = await axios.get(webApp.url, {
        timeout: 10000,
        maxRedirects: 5,
        validateStatus: () => true
      });
      const headers = res.headers;
      const hasHsts = !!headers['strict-transport-security'];
      const hasXFrame = !!headers['x-frame-options'];
      const hasXContent = !!headers['x-content-type-options'];
      const hasCsp = !!headers['content-security-policy'];
      checkResults.headersScore = [hasHsts, hasXFrame, hasXContent, hasCsp].filter(Boolean).length * 25;

      await supabase.from('SecurityHeaderCheck').insert({
        id: crypto.randomUUID(),
        webAppId: webApp.id,
        hasHsts,
        hasXFrame,
        hasXContent,
        hasCsp,
        score: checkResults.headersScore,
        checkedAt: new Date().toISOString()
      });

      console.log(`[HEADERS] ${webApp.url} → Score: ${checkResults.headersScore}/100`);
    } catch (err) {
      console.log(`[HEADERS] ${webApp.url} → ERROR: ${err.message}`);
    }

    // Auto-create finding
    await createFindingIfNeeded(webApp, checkResults);
  }
}

async function runPageSpeedChecks() {
  const { data: webApps, error } = await supabase
    .from('WebApp')
    .select('id, url, nama')
    .eq('status', 'AKTIF');

  if (error) return;

  console.log(`PageSpeed checking ${webApps.length} domains...`);
  
  // Cek satu per satu dengan delay 2 detik — hindari rate limit
  for (const webApp of webApps) {
    await checkPageSpeed(webApp);
    await new Promise(r => setTimeout(r, 2000));
  }
}



// Jalankan setiap 5 menit
// Cron setiap 5 menit — HTTP, SSL, Headers
cron.schedule('*/5 * * * *', () => {
  console.log('--- Cron triggered ---');
  runChecks();
});

// Cron 1x sehari jam 07.00 — PageSpeed
cron.schedule('0 7 * * *', () => {
  console.log('--- PageSpeed Check ---');
  runPageSpeedChecks();
});

// Jalankan sekali saat start
console.log('Worker started...');
runChecks();
