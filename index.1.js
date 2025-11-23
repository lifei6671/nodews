const os = require('os');
const http = require('http');
const fs = require('fs');
const axios = require('axios');
const net = require('net');
const path = require('path');
const crypto = require('crypto');
const { Buffer } = require('buffer');
const { exec, execSync } = require('child_process');
const { WebSocket, createWebSocketStream } = require('ws');

// --- 环境变量处理 ---
const UUID = process.env.UUID || 'b1ae9375-7664-4eb7-872d-d003f8b798f1';
const NEZHA_SERVER = process.env.NEZHA_SERVER || '';       // 哪吒地址
const NEZHA_PORT = process.env.NEZHA_PORT || '';           // 哪吒V1端口
const NEZHA_KEY = process.env.NEZHA_KEY || '';             // 密钥
const DOMAIN = process.env.DOMAIN || 'lifeilin-verge.hf.space';       // 域名
// 修正布尔值判断逻辑
const AUTO_ACCESS = process.env.AUTO_ACCESS !== 'false';   
const WSPATH = process.env.WSPATH || UUID.slice(0, 8);     // WS路径
const SUB_PATH = process.env.SUB_PATH || 'd003f8b798f1';            // 订阅路径
const NAME = process.env.NAME || 'Hug';                    // 节点名称
const PORT = process.env.PORT || 7860;                     // 监听端口

let ISP = 'Unknown';

// --- 获取 ISP 信息 ---
const GetISP = async () => {
  try {
    const res = await axios.get('https://speed.cloudflare.com/meta', { timeout: 3000 });
    const data = res.data;
    ISP = `${data.country}-${data.asOrganization}`.replace(/ /g, '_');
  } catch (e) {
    console.log('Failed to get ISP info, using default.');
  }
};
GetISP();

// --- HTTP Server (页面与订阅) ---
const httpServer = http.createServer((req, res) => {
  const urlPath = req.url.split('?')[0]; // 忽略查询参数
  
  if (urlPath === '/') {
    const filePath = path.join(__dirname, 'index.html');
    fs.readFile(filePath, 'utf8', (err, content) => {
      if (err) {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('Hello world!');
      } else {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(content);
      }
    });
  } else if (urlPath === `/${SUB_PATH}`) {
    const vlessURL = `vless://${UUID}@${DOMAIN}:443?encryption=none&security=tls&sni=${DOMAIN}&fp=chrome&type=ws&host=${DOMAIN}&path=%2F${WSPATH}#${NAME}-${ISP}`;
    const trojanURL = `trojan://${UUID}@${DOMAIN}:443?security=tls&sni=${DOMAIN}&fp=chrome&type=ws&host=${DOMAIN}&path=%2F${WSPATH}#${NAME}-${ISP}`;
    const subscription = vlessURL + '\n' + trojanURL;
    const base64Content = Buffer.from(subscription).toString('base64');
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(base64Content + '\n');
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found\n');
  }
});

// --- WebSocket Server ---
const wss = new WebSocket.Server({ noServer: true }); // 手动处理升级以验证路径

httpServer.on('upgrade', (request, socket, head) => {
  // 安全检查：只允许指定路径的 WS 连接
  if (request.url.indexOf(WSPATH) === -1) {
    socket.destroy();
    return;
  }
  wss.handleUpgrade(request, socket, head, (ws) => {
    wss.emit('connection', ws, request);
  });
});

const uuid = UUID.replace(/-/g, "");
const DNS_SERVERS = ['8.8.4.4', '1.1.1.1'];

// --- 自定义 DNS 解析 ---
function resolveHost(host) {
  return new Promise(async (resolve, reject) => {
    // 如果是 IP 直接返回
    if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(host)) {
      resolve(host);
      return;
    }

    for (const dnsServer of DNS_SERVERS) {
      try {
        const dnsQuery = `https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`;
        const response = await axios.get(dnsQuery, {
          timeout: 3000,
          headers: { 'Accept': 'application/dns-json' }
        });
        const data = response.data;
        if (data.Status === 0 && data.Answer && data.Answer.length > 0) {
          const ipRecord = data.Answer.find(record => record.type === 1);
          if (ipRecord) {
            resolve(ipRecord.data);
            return;
          }
        }
      } catch (e) {
        // continue to next DNS
      }
    }
    reject(new Error(`Failed to resolve ${host}`));
  });
}

// --- VLESS 处理 ---
function handleVlessConnection(ws, msg) {
  const [VERSION] = msg;
  const id = msg.slice(1, 17);
  if (!id.every((v, i) => v == parseInt(uuid.substr(i * 2, 2), 16))) return false;
  
  let i = msg.slice(17, 18).readUInt8() + 19;
  const port = msg.slice(i, i += 2).readUInt16BE(0);
  const ATYP = msg.slice(i, i += 1).readUInt8();
  const host = ATYP == 1 ? msg.slice(i, i += 4).join('.') :
    (ATYP == 2 ? new TextDecoder().decode(msg.slice(i + 1, i += 1 + msg.slice(i, i + 1).readUInt8())) :
    (ATYP == 3 ? msg.slice(i, i += 16).reduce((s, b, i, a) => (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), []).map(b => b.readUInt16BE(0).toString(16)).join(':') : ''));
  
  ws.send(new Uint8Array([VERSION, 0]));
  const duplex = createWebSocketStream(ws);
  
  const connectTarget = (ip) => {
    net.connect({ host: ip, port }, function() {
      this.write(msg.slice(i));
      duplex.on('error', () => {}).pipe(this).on('error', () => {}).pipe(duplex);
    }).on('error', (err) => {
        // console.error('Target connect error:', err);
    });
  };

  resolveHost(host).then(connectTarget).catch(() => connectTarget(host));
  return true;
}

// --- Trojan 处理 ---
function handleTrojanConnection(ws, msg) {
  try {
    if (msg.length < 58) return false;
    const receivedPasswordHash = msg.slice(0, 56).toString();
    const possiblePasswords = [UUID];
    
    let matchedPassword = null;
    for (const pwd of possiblePasswords) {
      const hash = crypto.createHash('sha224').update(pwd).digest('hex');
      if (hash === receivedPasswordHash) {
        matchedPassword = pwd;
        break;
      }
    }
    
    if (!matchedPassword) return false;
    
    let offset = 56;
    if (msg[offset] === 0x0d && msg[offset + 1] === 0x0a) {
      offset += 2;
    }
    
    const cmd = msg[offset];
    if (cmd !== 0x01) return false; // 只支持 CONNECT
    offset += 1;
    const atyp = msg[offset];
    offset += 1;
    let host, port;
    
    if (atyp === 0x01) {
      host = msg.slice(offset, offset + 4).join('.');
      offset += 4;
    } else if (atyp === 0x03) {
      const hostLen = msg[offset];
      offset += 1;
      host = msg.slice(offset, offset + hostLen).toString();
      offset += hostLen;
    } else if (atyp === 0x04) {
      // IPv6 logic...
      host = msg.slice(offset, offset + 16).reduce((s, b, i, a) => 
        (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), [])
        .map(b => b.readUInt16BE(0).toString(16)).join(':');
      offset += 16;
    } else {
      return false;
    }
    
    port = msg.readUInt16BE(offset);
    offset += 2;
    
    if (offset < msg.length && msg[offset] === 0x0d && msg[offset + 1] === 0x0a) {
      offset += 2;
    }
    
    const duplex = createWebSocketStream(ws);
    const connectTarget = (ip) => {
        net.connect({ host: ip, port }, function() {
          if (offset < msg.length) {
            this.write(msg.slice(offset));
          }
          duplex.on('error', () => {}).pipe(this).on('error', () => {}).pipe(duplex);
        }).on('error', () => {});
    }

    resolveHost(host).then(connectTarget).catch(() => connectTarget(host));
    return true;
  } catch (error) {
    return false;
  }
}

// --- WS 连接分发 ---
wss.on('connection', (ws) => {
  ws.once('message', msg => {
    // VLESS 头部特征判断
    if (msg.length > 17 && msg[0] === 0) {
      const id = msg.slice(1, 17);
      const isVless = id.every((v, i) => v == parseInt(uuid.substr(i * 2, 2), 16));
      if (isVless) {
        if (!handleVlessConnection(ws, msg)) ws.close();
        return;
      }
    }
    // 否则尝试 Trojan
    if (!handleTrojanConnection(ws, msg)) {
      ws.close();
    }
  }).on('error', () => {});
});

// --- 哪吒客户端逻辑 ---
const getDownloadUrl = () => {
  const arch = os.arch(); 
  const prefix = NEZHA_PORT ? 'agent' : 'v1'; // 有端口视为V1/V0新版agent，否则旧版
  // 替换为更稳定的 GitHub release 链接或保持原有 CDN
  if (arch === 'arm' || arch === 'arm64' || arch === 'aarch64') {
    return `https://arm64.ssss.nyc.mn/${prefix}`;
  } else {
    return `https://amd64.ssss.nyc.mn/${prefix}`;
  }
};

const downloadFile = async () => {
  if ((!NEZHA_SERVER && !NEZHA_KEY)) return; // 缺少必要参数
  
  try {
    const url = getDownloadUrl();
    const response = await axios({
      method: 'get',
      url: url,
      responseType: 'stream'
    });

    const writer = fs.createWriteStream('npm');
    response.data.pipe(writer);

    return new Promise((resolve, reject) => {
      writer.on('finish', () => {
        console.log('Agent binary downloaded');
        exec('chmod +x npm', (err) => {
          if (err) reject(err);
          resolve();
        });
      });
      writer.on('error', reject);
    });
  } catch (err) {
    console.error('Download agent failed:', err.message);
  }
};

const runnz = async () => {
  // 检查是否已运行
  try {
    // grep 时排除自身
    execSync('pgrep -f "./npm"');
    console.log('npm process is already running.');
    return;
  } catch (e) {
    // pgrep 返回非0表示未找到进程，继续执行
  }

  if (!fs.existsSync('npm')) {
    await downloadFile();
  }
  
  if (!fs.existsSync('npm')) {
      console.log('Agent binary not found, skipping.');
      return;
  }

  let command = '';
  let tlsPorts = ['443', '8443', '2096', '2087', '2083', '2053'];
  
  if (NEZHA_SERVER && NEZHA_PORT && NEZHA_KEY) {
    // 哪吒 V1 模式
    const NEZHA_TLS = tlsPorts.includes(NEZHA_PORT) ? '--tls' : '';
    command = `setsid ./npm -s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} ${NEZHA_TLS} --disable-auto-update --report-delay 4 --skip-conn --skip-procs >/dev/null 2>&1 &`;
  } else if (NEZHA_SERVER && NEZHA_KEY) {
    // 哪吒 V0 模式 (生成配置文件)
    if (!NEZHA_PORT) {
        // 尝试从 Server 字符串解析端口判断 TLS
        const parts = NEZHA_SERVER.split(':');
        const portStr = parts.length > 1 ? parts[parts.length - 1] : '80';
        const NZ_TLS = tlsPorts.includes(portStr) ? 'true' : 'false';
        
        const configYaml = `client_secret: ${NEZHA_KEY}
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: true
ip_report_period: 1800
report_delay: 4
server: ${NEZHA_SERVER}
skip_connection_count: true
skip_procs_count: true
temperature: false
tls: ${NZ_TLS}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: ${UUID}`;
        fs.writeFileSync('config.yaml', configYaml);
    }
    command = `setsid ./npm -c config.yaml >/dev/null 2>&1 &`;
  } else {
    return;
  }

  exec(command, { shell: '/bin/bash' }, (err) => {
    if (err) console.error('Agent start error:', err);
    else console.log('Agent started.');
  });
};

// --- 自动保活任务 ---
async function addAccessTask() {
  if (!AUTO_ACCESS || !DOMAIN) return;
  
  const fullURL = `https://${DOMAIN}`;
  try {
    await axios.post("https://oooo.serv00.net/add-url", { url: fullURL }, {
      headers: { 'Content-Type': 'application/json' }
    });
    console.log('Keep-alive task added.');
  } catch (error) {
    // 忽略报错
  }
}

// --- 清理文件 ---
const delFiles = () => {
  // 延时删除，给程序启动留出时间
  setTimeout(() => {
      fs.unlink('npm', () => {});
      fs.unlink('config.yaml', () => {});
  }, 60000);
};

// --- 启动入口 ---
httpServer.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  runnz();
  delFiles();
  addAccessTask();
});
