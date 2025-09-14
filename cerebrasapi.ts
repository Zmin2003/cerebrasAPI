import { serve } from "https://deno.land/std@0.192.0/http/server.ts";

// --- 配置项 ---
const CEREBRAS_API_URL = 'https://api.cerebras.ai/v1/chat/completions';
// 设置处理请求的间隔时间（毫秒）。例如 200ms 表示每秒最多处理 5 个请求。
// 1000ms / RATE_LIMIT_MS = 每秒最大请求数
const RATE_LIMIT_MS = 200; 

// --- CORS 头 ---
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

// --- 核心状态管理 ---

// 请求队列，用于存储待处理的请求
// 每个元素包含请求体和用于响应客户端的 resolve 函数
const requestQueue: { body: any; resolve: (response: Response) => void }[] = [];

// API Key 池
let apiKeys: string[] = [];
let currentKeyIndex = 0;

// --- 初始化 API Keys ---
function initializeKeys() {
  const keysString = Deno.env.get("CEREBRAS_API_KEYS");
  if (keysString) {
    apiKeys = keysString.split(',').map(key => key.trim()).filter(key => key);
    console.log(`Initialized with ${apiKeys.length} API keys.`);
  } else {
    console.error("CEREBRAS_API_KEYS environment variable not set!");
  }
}

// --- 请求处理器（工人） ---
async function processQueue() {
  // 如果队列为空或没有可用的 Key，则不处理
  if (requestQueue.length === 0 || apiKeys.length === 0) {
    return;
  }

  // 从队列头部取出一个请求
  const { body, resolve } = requestQueue.shift()!;

  // 轮询选择一个 Key
  const apiKey = apiKeys[currentKeyIndex];
  currentKeyIndex = (currentKeyIndex + 1) % apiKeys.length;
  
  console.log(`Processing request with key index: ${currentKeyIndex}`);

  try {
    const apiResponse = await fetch(CEREBRAS_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
      },
      body: JSON.stringify(body),
    });

    // 复制响应头并添加 CORS
    const responseHeaders = new Headers(apiResponse.headers);
    Object.entries(CORS_HEADERS).forEach(([key, value]) => {
      responseHeaders.set(key, value);
    });

    // 将最终响应返回给等待的客户端
    resolve(new Response(apiResponse.body, {
      status: apiResponse.status,
      statusText: apiResponse.statusText,
      headers: responseHeaders,
    }));

  } catch (error) {
    console.error("Error forwarding request to Cerebras:", error);
    resolve(new Response(`Proxy error: ${error.message}`, { status: 502, headers: CORS_HEADERS }));
  }
}

// --- HTTP 服务器主处理函数 ---
async function handler(req: Request): Promise<Response> {
  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  if (req.method !== 'POST') {
    return new Response("Method Not Allowed", { status: 405, headers: CORS_HEADERS });
  }

  if (apiKeys.length === 0) {
     return new Response("Server configuration error: No API keys configured.", { status: 500, headers: CORS_HEADERS });
  }

  try {
    const requestBody = await req.json();

    // 创建一个 Promise，将 resolve 函数存入队列
    // 这个 Promise 会一直等待，直到队列处理器调用 resolve
    return new Promise((resolve) => {
      requestQueue.push({ body: requestBody, resolve });
    });

  } catch (error) {
    return new Response(`Invalid JSON body: ${error.message}`, { status: 400, headers: CORS_HEADERS });
  }
}

// --- 启动服务和处理器 ---
initializeKeys(); // 启动时立即加载 Keys
serve(handler);
// 每隔 RATE_LIMIT_MS 毫秒，就尝试处理一次队列中的请求
setInterval(processQueue, RATE_LIMIT_MS);

console.log(`Cerebras smart proxy started.`);
console.log(`- Request processing interval: ${RATE_LIMIT_MS}ms`);
console.log(`- Max requests per second (approx): ${1000 / RATE_LIMIT_MS}`);
