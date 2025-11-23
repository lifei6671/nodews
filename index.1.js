'use strict';

const http = require('http');
const fs = require('fs');
const net = require('net');
const path = require('path');
const crypto = require('crypto');
const dns = require('dns').promises;
const axios = require('axios');
const { Buffer } = require('buffer');
const { WebSocketServer, createWebSocketStream } = require('ws');
const { TextDecoder } = require('util');

// ====== 配置 & 环境变量 ======
const UUID = process.env.UUID || 'b1ae9375-7664-4eb7-872d-d003f8b798f1'; // VLESS/Trojan 密钥
const DOMAIN = process.env.DOMAIN || 'verge.disign.me';                  // 你的对外域名（建议填已经反代的域名）
const AUTO_ACCESS = process.env.AUTO_ACCESS === 'true';                  // 显式设置 AUTO_ACCESS=true 才开启保活
const WSPATH = process.env.WSPATH || UUID.slice(0, 8);                   // WebSocket 节点路径（不带 /）
const SUB_PATH = process.env.SUB_PATH || 'd003f8b798f1';                 // 订阅路径（不带 /）
const NAME = process.env.NAME || 'HuggingFace';                          // 节点名称
const PORT = Number(process.env.PORT) || 7860;                           // HTTP + WS 监听端口

// ====== ISP 信息（订阅标记用，不影响主逻辑）======
let ISP = 'Unknown';
(async () => {
  try {
    const res = await axios.get('https://speed.cloudflare.com/meta', { timeout: 5000 });
    const data = res.data || {};
    ISP = `${data.country || 'XX'}-${data.asOrganization || 'Unknown'}`.replace(/ /g, '_');
  } catch (e) {
    ISP = 'Unknown';
  }
})();

// ====== 工具函数 ======

const textDecoder = new TextDecoder();

// simple ip check
function isIp(str) {
  return net.isIP(str) !== 0;
}

// SSRF 防护：判断是否内网 IP
function isPrivateIp(ip) {
  if (!isIp(ip)) return false;

  // IPv4 私网段 + 回环
//  if (/^(10\.|127\.)/.test(ip)) return true;
  //if (/^192\.168\./.test(ip)) return true;
  //if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip)) return true;

  // IPv6 回环/链路本地/ULA
  //if (ip === '::1') return true;
  //if (/^fc00:/i.test(ip) || /^fd00:/i.test(ip) || /^fe80:/i.test(ip)) return true;

  return false;
}

// 解析域名 → IPv4，内部带 SSRF 防护；失败返回原 host 让系统决定
async function resolveHost(host) {
  if (isIp(host)) {
    if (isPrivateIp(host)) throw new Error('blocked private ip');
    return host;
  }

  const lower = host.toLowerCase();
  if (lower === 'localhost' || lower.endsWith('.local')) {
    throw new Error('blocked local hostname');
  }

  try {
    const addrs = await dns.resolve4(host);
    if (addrs && addrs.length > 0) {
      const ip = addrs[0];
      if (isPrivateIp(ip)) {
        throw new Error('blocked private ip');
      }
      return ip;
    }
    return host;
  } catch (_) {
    // DNS 失败时退回由系统自行解析
    return host;
  }
}

// 去掉 UUID 中的连字符，用于 VLESS 身份验证
const uuidHex = UUID.replace(/-/g, "");

// ====== HTTP Server：主页 + 订阅 ======
const httpServer = http.createServer((req, res) => {
  if (req.url === '/') {
    const filePath = path.join(__dirname, 'index.html');
    fs.readFile(filePath, 'utf8', (err, content) => {
      if (err) {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end('Hello world!');
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(content);
    });
    return;
  }

  if (req.url === `/${SUB_PATH}`) {
    const tag = encodeURIComponent(`${NAME}-${ISP}`);
    const vlessURL =
      `vless://${UUID}@${DOMAIN}:443?` +
      `encryption=none&security=tls&sni=${DOMAIN}` +
      `&fp=chrome&type=ws&host=${DOMAIN}&path=%2F${WSPATH}#${tag}`;

    const trojanURL =
      `trojan://${UUID}@${DOMAIN}:443?` +
      `security=tls&sni=${DOMAIN}` +
      `&fp=chrome&type=ws&host=${DOMAIN}&path=%2F${WSPATH}#${tag}`;

    const subscription = `${vlessURL}\n${trojanURL}`;
    const base64Content = Buffer.from(subscription).toString('base64');
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(base64Content + '\n');
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('Not Found\n');
});

// ====== WebSocket Server（VLESS + Trojan） ======
const wss = new WebSocketServer({ server: httpServer });

// VLESS 处理
function handleVlessConnection(ws, msg) {
  const VERSION = msg[0];
  const id = msg.slice(1, 17);

  // 校验 UUID
  const valid = id.every((v, i) => v === parseInt(uuidHex.substr(i * 2, 2), 16));
  if (!valid) return false;

  // 解析 header length
  let i = msg.slice(17, 18).readUInt8() + 19;
  const port = msg.slice(i, i += 2).readUInt16BE(0);
  const ATYP = msg.slice(i, i += 1).readUInt8();

  let host;
  if (ATYP === 1) {
    // IPv4
    host = msg.slice(i, i += 4).join('.');
  } else if (ATYP === 2) {
    // 域名
    const len = msg.slice(i, i + 1).readUInt8();
    host = textDecoder.decode(msg.slice(i + 1, i + 1 + len));
    i += 1 + len;
  } else if (ATYP === 3) {
    // IPv6
    const raw = msg.slice(i, i += 16);
    const parts = [];
    for (let j = 0; j < 16; j += 2) {
      parts.push(raw.readUInt16BE(j).toString(16));
    }
    host = parts.join(':');
  } else {
    return false;
  }

  if (isPrivateIp(host)) return false;

  // 回应客户端：VERSION, 0
  ws.send(new Uint8Array([VERSION, 0]));

  const duplex = createWebSocketStream(ws, { encoding: 'binary' });

  const connectAndPipe = (targetHost) => {
    const socket = net.connect({ host: targetHost, port }, function () {
      // 首包（剩余数据）写入
      if (i < msg.length) {
        this.write(msg.slice(i));
      }
      this.setNoDelay(true);

      // 双向管道
      duplex.pipe(this);
      this.pipe(duplex);

      const cleanup = () => {
        this.destroy();
        duplex.destroy();
      };

      duplex.on('error', cleanup);
      duplex.on('close', cleanup);
      this.on('error', cleanup);
      this.on('close', cleanup);
    });

    socket.on('error', () => {
      try { ws.close(); } catch { }
    });
  };

  resolveHost(host)
    .then(connectAndPipe)
    .catch(() => connectAndPipe(host));

  return true;
}

// Trojan 处理
function handleTrojanConnection(ws, msg) {
  try {
    if (msg.length < 58) return false;

    const receivedPasswordHash = msg.slice(0, 56).toString();
    const candidatePasswords = [UUID].filter(Boolean);

    let matched = false;
    for (const pwd of candidatePasswords) {
      const hash = crypto.createHash('sha224').update(pwd).digest('hex');
      if (hash === receivedPasswordHash) {
        matched = true;
        break;
      }
    }
    if (!matched) return false;

    let offset = 56;
    if (msg[offset] === 0x0d && msg[offset + 1] === 0x0a) {
      offset += 2;
    }

    const cmd = msg[offset];
    if (cmd !== 0x01) return false; // 只处理 CONNECT
    offset += 1;

    const atyp = msg[offset];
    offset += 1;

    let host, port;

    if (atyp === 0x01) {
      // IPv4
      host = msg.slice(offset, offset + 4).join('.');
      offset += 4;
    } else if (atyp === 0x03) {
      // 域名
      const hostLen = msg[offset];
      offset += 1;
      host = msg.slice(offset, offset + hostLen).toString();
      offset += hostLen;
    } else if (atyp === 0x04) {
      // IPv6
      const raw = msg.slice(offset, offset + 16);
      const parts = [];
      for (let j = 0; j < 16; j += 2) {
        parts.push(raw.readUInt16BE(j).toString(16));
      }
      host = parts.join(':');
      offset += 16;
    } else {
      return false;
    }

    port = msg.readUInt16BE(offset);
    offset += 2;

    if (offset + 1 < msg.length && msg[offset] === 0x0d && msg[offset + 1] === 0x0a) {
      offset += 2;
    }

    if (isPrivateIp(host)) return false;

    const duplex = createWebSocketStream(ws, { encoding: 'binary' });

    const connectAndPipe = (targetHost) => {
      const socket = net.connect({ host: targetHost, port }, function () {
        if (offset < msg.length) {
          this.write(msg.slice(offset));
        }
        this.setNoDelay(true);

        duplex.pipe(this);
        this.pipe(duplex);

        const cleanup = () => {
          this.destroy();
          duplex.destroy();
        };

        duplex.on('error', cleanup);
        duplex.on('close', cleanup);
        this.on('error', cleanup);
        this.on('close', cleanup);
      });

      socket.on('error', () => {
        try { ws.close(); } catch { }
      });
    };

    resolveHost(host)
      .then(connectAndPipe)
      .catch(() => connectAndPipe(host));

    return true;
  } catch (_) {
    return false;
  }
}

// WS 连接处理：限制 path，对 v2rayN 友好
wss.on('connection', (ws, req) => {
  const url = req.url || '/';

  // 允许：
  // /WSPATH
  // /WSPATH/
  // /WSPATH?...
  // /WSPATH/... （兼容某些 padding 用法）
  if (
    !(
      url === `/${WSPATH}` ||
      url.startsWith(`/${WSPATH}/`) ||
      url.startsWith(`/${WSPATH}?`)
    )
  ) {
    ws.close();
    return;
  }

  ws.once('message', (rawMsg) => {
    let msg = rawMsg;
    if (typeof msg === 'string') {
      msg = Buffer.from(msg);
    }

    // VLESS: 第一个字节 VERSION=0，后 16 字节为 UUID
    if (msg.length > 17 && msg[0] === 0) {
      const id = msg.slice(1, 17);
      const isVless = id.every((v, i) => v === parseInt(uuidHex.substr(i * 2, 2), 16));
      if (isVless) {
        if (!handleVlessConnection(ws, msg)) {
          ws.close();
        }
        return;
      }
    }

    // 否则尝试 Trojan
    if (!handleTrojanConnection(ws, msg)) {
      ws.close();
    }
  }).on('error', () => {
    try { ws.close(); } catch { }
  });
});

// 自动访问任务（可选，用于保活）
async function addAccessTask() {
  if (!AUTO_ACCESS) return;
  if (!DOMAIN) return;

  const fullURL = `https://${DOMAIN}`;
  try {
    await axios.post(
      'https://oooo.serv00.net/add-url',
      { url: fullURL },
      {
        headers: { 'Content-Type': 'application/json' },
        timeout: 5000
      }
    );
    console.log('Automatic Access Task added successfully');
  } catch (_) {
    // 静默失败
  }
}

// 启动 HTTP + WS 服务
httpServer.listen(PORT, () => {
  console.log(
    `Server is running on port ${PORT}, ws path: /${WSPATH}, sub path: /${SUB_PATH}`
  );
  addAccessTask();
});
