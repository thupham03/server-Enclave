// ================================================================
// PhoenixKey — Mock API Server
// Nhận signature từ mobile app, giả data gửi về
//
// Endpoints:
//   GET  /health              → Health check
//   POST /api/challenge       → Tạo challenge ngẫu nhiên để mobile ký
//   POST /api/verify-signature → Nhận signature, verify bằng Rust crypto
//   POST /api/submit-tx       → Mock: nhận signed tx, trả tx hash giả
//   GET  /api/challenge/:id   → Lấy lại challenge cũ (debug)
// ================================================================

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = 8000;

// ─── Middleware ────────────────────────────────────────────────
app.use(cors());
app.use(express.json());

// ─── In-memory store (thay bằng Redis/DB trong production) ────
const challenges = new Map(); // challengeId → { message, createdAt, used }
const signatureLog = [];      // Lưu log tất cả signature đã verify

// ─── Utility: Tạo challenge ngẫu nhiên ───────────────────────
function generateChallenge() {
  return {
    id: crypto.randomUUID(),
    message: crypto.randomBytes(32).toString('hex'), // 64-char hex
    timestamp: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(), // 5 phút
  };
}

// ─── Utility: Tạo fake tx hash ────────────────────────────────
function fakeTxHash() {
  return 'tx_' + crypto.randomBytes(32).toString('hex');
}

// ─── Utility: Tạo fake block hash ────────────────────────────
function fakeBlockHash() {
  return 'block_' + crypto.randomBytes(16).toString('hex');
}

// ─── Utility: Tạo fake address ────────────────────────────────
function fakeAddress() {
  const prefixes = ['addr1', 'addr_test1'];
  const prefix = prefixes[Math.floor(Math.random() * prefixes.length)];
  const body = crypto.randomBytes(28).toString('base58');
  return prefix + body.slice(0, 50);
}

// ─── Utility: Log request ────────────────────────────────────
function log(type, ...args) {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] [${type}]`, ...args);
}

// ================================================================
// ENDPOINTS
// ================================================================

// ─── GET /health ───────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'PhoenixKey Mock API',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
  });
});

// ─── POST /api/challenge ───────────────────────────────────────
/**
 * Tạo challenge mới để mobile ký
 *
 * Request body (optional):
 *   { "purpose": "transfer" | "stake" | "mint" | "vote" }
 *
 * Response:
 *   { challengeId, message, timestamp, expiresAt }
 */
app.post('/api/challenge', (req, res) => {
  const { purpose = 'general' } = req.body || {};

  const challenge = generateChallenge();
  challenge.purpose = purpose;

  challenges.set(challenge.id, challenge);

  log('CHALLENGE_CREATED', `id=${challenge.id} purpose=${purpose}`);

  res.json({
    success: true,
    data: {
      challengeId: challenge.id,
      message: challenge.message,
      purpose: challenge.purpose,
      timestamp: challenge.timestamp,
      expiresAt: challenge.expiresAt,
    },
  });
});

// ─── GET /api/challenge/:id ────────────────────────────────────
/**
 * Lấy lại challenge đã tạo (debug)
 */
app.get('/api/challenge/:id', (req, res) => {
  const { id } = req.params;
  const challenge = challenges.get(id);

  if (!challenge) {
    return res.status(404).json({
      success: false,
      error: 'Challenge not found',
    });
  }

  if (new Date(challenge.expiresAt) < new Date()) {
    return res.status(410).json({
      success: false,
      error: 'Challenge expired',
    });
  }

  res.json({
    success: true,
    data: challenge,
  });
});

// ─── POST /api/verify-signature ────────────────────────────────
/**
 * Nhận signature đã ký từ mobile app
 *
 * Request body (theo spec):
 *   {
 *     challengeId: string,      // ID của challenge
 *     publicKey: string,         // P-256 public key (hex, 130 chars)
 *     signature: string,         // ECDSA signature (hex, DER-encoded, >60 chars)
 *     hash: string,              // SHA-256 hash của challenge message (64 chars)
 *     message: string,           // Challenge message gốc (để debug/log)
 *     deviceInfo?: {
 *       platform: 'ios' | 'android',
 *       model?: string,
 *     }
 *   }
 *
 * Response:
 *   {
 *     success: true,
 *     data: {
 *       isValid: boolean,        // Signature có hợp lệ không
 *       challengeId: string,
 *       verifiedAt: string,
 *       publicKey: string,
 *       txHash?: string,
 *       blockHash?: string,
 *       status: 'verified' | 'invalid' | 'expired'
 *     }
 *   }
 */
app.post('/api/verify-signature', async (req, res) => {
  // ─── Extract request body ───────────────────────────────────
  const { challengeId, publicKey, signature, hash, message, deviceInfo } = req.body || {};

  // ─── Validate input ───────────────────────────────────────
  if (!challengeId || !publicKey || !signature || !hash || !message) {
    return res.status(400).json({
      success: false,
      error: 'Missing required fields: challengeId, publicKey, signature, hash, message',
    });
  }

  // ─── Check challenge tồn tại ──────────────────────────────
  const challenge = challenges.get(challengeId);

  if (!challenge) {
    log('VERIFY_FAILED', `challenge=${challengeId} reason=NOT_FOUND`);
    return res.status(404).json({
      success: false,
      error: 'Challenge not found',
      data: {
        isValid: false,
        status: 'not_found',
      },
    });
  }

  // ─── Check challenge expired ───────────────────────────────
  if (new Date(challenge.expiresAt) < new Date()) {
    log('VERIFY_FAILED', `challenge=${challengeId} reason=EXPIRED`);
    return res.status(410).json({
      success: false,
      error: 'Challenge expired',
      data: {
        isValid: false,
        status: 'expired',
      },
    });
  }

  // ─── Check challenge đã used ──────────────────────────────
  if (challenge.used) {
    log('VERIFY_REPLAY', `challenge=${challengeId} reason=ALREADY_USED`);
    return res.status(409).json({
      success: false,
      error: 'Challenge already used (replay attack protection)',
      data: {
        isValid: false,
        status: 'replay',
      },
    });
  }

  // ─── MOCK VERIFICATION ────────────────────────────────────
  //
  // Theo spec:
  //   1. Mobile nhận challenge.message (hex random)
  //   2. Mobile hash: hash = SHA-256(challenge.message)
  //   3. Mobile gửi hash vào Chip → Chip.sign(hash) → signature
  //   4. Mobile gửi { challengeId, publicKey, hash, signature } lên server
  //   5. Server verify: signature = Chip.sign(hash) → verify(publicKey, hash, signature)
  //
  // Trong production: gọi Rust Core verify hoặc Blockfrost API
  //
  // Hiện tại (mock):
  //   - Kiểm tra format: publicKey (130 hex), signature (>60 hex), hash (64 hex)
  //   - Server KHÔNG verify mật mã ở đây (dùng Rust Core thật trong production)
  //
  // Để test với Rust Core thật (sau khi build):
  //   const { execSync } = require('child_process');
  //   const result = execSync(
  //     `cd rust_core && cargo run -- verify ${publicKey} ${hash} ${signature}`,
  //     { encoding: 'utf-8' }
  //   );

  const isValid = publicKey.length === 130 && signature.length > 60 && hash.length === 64;
  const verifiedAt = new Date().toISOString();

  // Debug: log format details
  log('VERIFY_DEBUG',
    `publicKey.len=${publicKey.length} (expect 130)`,
    `signature.len=${signature.length} (expect >60)`,
    `hash.len=${hash.length} (expect 64)`,
    `allValid=${isValid}`
  );

  // ─── Log signature ────────────────────────────────────────
  const logEntry = {
    challengeId,
    publicKey: publicKey.slice(0, 20) + '...',
    signature: signature.slice(0, 20) + '...',
    hash: hash.slice(0, 20) + '...',    // SHA-256 hash đã ký
    message: message.slice(0, 20) + '...', // Message gốc (để debug)
    isValid,
    verifiedAt,
    deviceInfo: deviceInfo || null,
  };
  signatureLog.push(logEntry);

  if (isValid) {
    // ─── Mark challenge as used (replay protection) ─────────
    challenge.used = true;

    log('VERIFY_SUCCESS', `challenge=${challengeId} hash=${hash.slice(0, 16)}...`);

    res.json({
      success: true,
      data: {
        isValid: true,
        challengeId,
        verifiedAt,
        publicKey,
        // ─── Fake blockchain data ─────────────────────────
        txHash: fakeTxHash(),
        blockHash: fakeBlockHash(),
        blockNumber: Math.floor(Math.random() * 1000000) + 9000000,
        slot: Math.floor(Math.random() * 10000000) + 50000000,
        status: 'verified',
        // ─── Thông tin theo spec ───────────────────────────
        hash: hash,              // SHA-256 hash đã verify
        algorithm: 'P-256 ECDSA',
        digest: 'SHA-256',
        replayProtected: true,
      },
    });
  } else {
    log('VERIFY_INVALID', `challenge=${challengeId} reason=INVALID_FORMAT`);

    res.json({
      success: false,
      data: {
        isValid: false,
        challengeId,
        verifiedAt,
        status: 'invalid',
        error: 'Signature verification failed',
      },
    });
  }
});

// ─── POST /api/submit-tx ───────────────────────────────────────
/**
 * Mock submit transaction lên blockchain
 * Trong production: gọi Blockfrost / cardano-cli submit
 *
 * Request body:
 *   {
 *     txHash: string,          // Fake tx hash đã tạo ở verify
 *     signedCbor?: string,     // (Optional) CBOR encoded signed tx
 *     metadata?: object        // (Optional) Transaction metadata
 *   }
 *
 * Response:
 *   { txHash, status, blockHash, blockNumber }
 */
app.post('/api/submit-tx', (req, res) => {
  const { txHash, signedCbor, metadata } = req.body || {};

  if (!txHash) {
    return res.status(400).json({
      success: false,
      error: 'Missing txHash',
    });
  }

  // Mock: tx đã confirm sau 1-3s
  const confirmDelay = Math.floor(Math.random() * 2000) + 1000;

  setTimeout(() => {
    const response = {
      success: true,
      data: {
        txHash: txHash.startsWith('tx_') ? txHash : fakeTxHash(),
        status: 'confirmed',
        blockHash: fakeBlockHash(),
        blockNumber: Math.floor(Math.random() * 1000000) + 9000000,
        slot: Math.floor(Math.random() * 10000000) + 50000000,
        confirmations: Math.floor(Math.random() * 10) + 1,
        fees: (Math.random() * 0.5).toFixed(3) + ' ADA',
        submittedAt: new Date(Date.now() - confirmDelay).toISOString(),
        confirmedAt: new Date().toISOString(),
      },
    };

    log('TX_CONFIRMED', `txHash=${txHash}`);

    // Nếu có metadata → echo lại
    if (metadata) {
      response.data.metadata = metadata;
    }

    res.json(response);
  }, confirmDelay);
});

// ─── GET /api/stats ────────────────────────────────────────────
/**
 * Lấy thống kê (debug)
 */
app.get('/api/stats', (req, res) => {
  const now = new Date();
  const activeChallenges = [...challenges.values()].filter(
    (c) => !c.used && new Date(c.expiresAt) > now
  );

  res.json({
    success: true,
    data: {
      totalChallenges: challenges.size,
      activeChallenges: activeChallenges.length,
      usedChallenges: [...challenges.values()].filter((c) => c.used).length,
      totalVerifications: signatureLog.length,
      successfulVerifications: signatureLog.filter((l) => l.isValid).length,
      uptime: process.uptime(),
    },
  });
});

// ─── GET /api/log ───────────────────────────────────────────────
/**
 * Lấy signature log (debug)
 */
app.get('/api/log', (req, res) => {
  const { limit = 20 } = req.query;
  res.json({
    success: true,
    data: signatureLog.slice(-parseInt(limit)),
  });
});

// ─── DELETE /api/challenge/:id ─────────────────────────────────
/**
 * Xóa challenge (debug)
 */
app.delete('/api/challenge/:id', (req, res) => {
  const { id } = req.params;
  const deleted = challenges.delete(id);

  res.json({
    success: deleted,
    data: { deleted, challengeId: id },
  });
});

// ─── DELETE /api/reset ─────────────────────────────────────────
/**
 * Reset tất cả challenges và log (debug)
 */
app.delete('/api/reset', (req, res) => {
  challenges.clear();
  signatureLog.length = 0;

  log('RESET', 'All challenges and logs cleared');

  res.json({
    success: true,
    message: 'All data cleared',
  });
});

// ================================================================
// ERROR HANDLER
// ================================================================
app.use((err, req, res, next) => {
  log('ERROR', err.message);
  res.status(500).json({
    success: false,
    error: 'Internal server error',
    message: err.message,
  });
});

// ================================================================
// START
// ================================================================
app.listen(PORT, () => {
  console.log('');
  console.log('╔═══════════════════════════════════════════════════════╗');
  console.log('║  🔐 PhoenixKey Mock API Server                       ║');
  console.log('║  Status: RUNNING                                     ║');
  console.log(`║  URL:     http://localhost:${PORT}                       ║`);
  console.log('║                                                       ║');
  console.log('║  Endpoints:                                          ║');
  console.log('║    GET  /health              → Health check          ║');
  console.log('║    POST /api/challenge       → Tạo challenge mới     ║');
  console.log('║    GET  /api/challenge/:id    → Lấy challenge         ║');
  console.log('║    POST /api/verify-signature → Verify signature       ║');
  console.log('║    POST /api/submit-tx       → Submit tx (mock)       ║');
  console.log('║    GET  /api/stats           → Thống kê              ║');
  console.log('║    GET  /api/log             → Signature log         ║');
  console.log('║    DELETE /api/challenge/:id → Xóa challenge         ║');
  console.log('║    DELETE /api/reset         → Reset all data        ║');
  console.log('╚═══════════════════════════════════════════════════════╝');
  console.log('');
});
