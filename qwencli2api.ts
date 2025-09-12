// 导入 Deno 标准库中的 serve 函数，用于快速创建一个 HTTP 服务器
import { serve } from "https://deno.land/std@0.192.0/http/server.ts";

// 定义目标 API 地址
const CEREBRAS_API_URL = 'https://api.cerebras.ai/v1/chat/completions';

// 定义 CORS 响应头，允许任何来源的跨域请求
// 这对于在前端网页中调用此代理至关重要
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*', // 允许任何来源
  'Access-Control-Allow-Methods': 'POST, OPTIONS', // 允许的方法
  'Access-Control-Allow-Headers': 'Content-Type', // 允许的请求头
};

// 主处理函数，每个请求都会进入这里
async function handler(req: Request): Promise<Response> {
  // 浏览器在发送跨域的 POST 请求前，会先发送一个 OPTIONS "预检"请求
  // 我们需要正确响应这个预检请求，否则浏览器会阻止后续的 POST 请求
  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  // 只处理 POST 请求，其他方法返回错误
  if (req.method !== 'POST') {
    return new Response("Method Not Allowed", { status: 405, headers: CORS_HEADERS });
  }

  // 从环境变量中安全地获取 API 密钥
  // 这是在 Deno Deploy 网站上设置的，不会暴露在代码里
  const apiKey = Deno.env.get("CEREBRAS_API_KEY");
  if (!apiKey) {
    console.error("CEREBRAS_API_KEY is not set in environment variables.");
    return new Response("Server configuration error: API key not found.", { status: 500, headers: CORS_HEADERS });
  }

  try {
    // 解析客户端发来的 JSON 请求体
    const requestBody = await req.json();

    // 使用 fetch API 向真正的 Cerebras API 发起请求
    // 1. 使用目标 URL
    // 2. 方法是 POST
    // 3. 设置必要的请求头，特别是 Content-Type 和 Authorization
    // 4. 将客户端的请求体转换成字符串后作为我们的请求体
    const apiResponse = await fetch(CEREBRAS_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
      },
      body: JSON.stringify(requestBody),
    });

    // 创建一个新的 Headers 对象，复制来自 Cerebras API 的响应头
    const responseHeaders = new Headers(apiResponse.headers);
    
    // 在响应头上添加我们自己的 CORS 设置
    Object.entries(CORS_HEADERS).forEach(([key, value]) => {
      responseHeaders.set(key, value);
    });

    // 将 Cerebras API 的响应（包括状态码、响应头和响应体）直接返回给客户端
    // apiResponse.body 是一个 ReadableStream，Deno 会自动处理流式传输
    // 这意味着如果 Cerebras API 是流式输出（"stream": true），我们的代理也能完美支持
    return new Response(apiResponse.body, {
      status: apiResponse.status,
      statusText: apiResponse.statusText,
      headers: responseHeaders,
    });

  } catch (error) {
    // 如果请求体不是有效的 JSON，或者发生其他网络错误，捕获并返回错误信息
    console.error("Error processing request:", error);
    return new Response(`Error: ${error.message}`, { status: 400, headers: CORS_HEADERS });
  }
}

// 启动服务器
console.log("Cerebras proxy server starting on port 8000...");
serve(handler);