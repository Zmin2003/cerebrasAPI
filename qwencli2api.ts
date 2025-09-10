/**
 * Qwen Code API 服务器
 * 支持Web界面上传oauth_creds.json文件，自动管理token，并提供API调用功能
 * 包含简单的密码认证保护
 */

// Deno类型声明
declare global {
  const Deno: {
    env: {
      get(key: string): string | undefined;
    };
    openKv(): Promise<Deno.Kv>;
    Kv: {
      new(): Deno.Kv;
    };
  };
}

// 导入Deno标准库
import { serve } from "https://deno.land/std@0.208.0/http/server.ts";
import { contentType } from "https://deno.land/std@0.208.0/media_types/mod.ts";

let kv: Deno.Kv | null = null;
try {
  kv = await Deno.openKv();
} catch (error) {
  console.error("无法打开KV存储:", error);
}

// 配置常量
const PORT = Number(Deno.env.get("PORT")) || 8000;
const API_PASSWORD = Deno.env.get("API_PASSWORD") || "qwen123"; // 默认密码，生产环境应通过环境变量设置

// OAuth2 端点配置
const QWEN_OAUTH_BASE_URL = "https://chat.qwen.ai";
const QWEN_OAUTH_DEVICE_CODE_ENDPOINT = `${QWEN_OAUTH_BASE_URL}/api/v1/oauth2/device/code`;
const QWEN_OAUTH_TOKEN_ENDPOINT = `${QWEN_OAUTH_BASE_URL}/api/v1/oauth2/token`;

// OAuth 客户端配置
const QWEN_OAUTH_CLIENT_ID = "f0304373b74a44d2b584a3fb70ca9e56";
const QWEN_OAUTH_SCOPE = "openid profile email model.completion";
const QWEN_OAUTH_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";

interface OAuthState {
  deviceCode?: string;
  userCode?: string;
  verificationUri?: string;
  verificationUriComplete?: string;
  codeVerifier?: string;
  expiresAt?: number;
  pollInterval?: number;
  createdAt?: number;
  lastUsedAt?: number;
}

const oauthStates: Map<string, OAuthState> = new Map();

async function saveOAuthStateToKv(stateId: string, state: OAuthState): Promise<void> {
  if (!kv) return;
  try {
    await kv.set(["oauth_states", stateId], state);
  } catch (error) {
    console.error(`保存OAuth状态 ${stateId} 到KV存储失败:`, error);
  }
}

async function loadOAuthStateFromKv(stateId: string): Promise<OAuthState | null> {
  if (!kv) return null;
  try {
    const result = await kv.get<OAuthState>(["oauth_states", stateId]);
    return result.value;
  } catch (error) {
    console.error(`从KV存储加载OAuth状态 ${stateId} 失败:`, error);
    return null;
  }
}

async function deleteOAuthStateFromKv(stateId: string): Promise<void> {
  if (!kv) return;
  try {
    await kv.delete(["oauth_states", stateId]);
  } catch (error) {
    console.error(`从KV存储删除OAuth状态 ${stateId} 失败:`, error);
  }
}


// 互斥锁保护 oauthStates 的并发访问
let lockAcquired = false;

// 获取锁的辅助函数
async function acquireLock(): Promise<void> {
  while (lockAcquired) {
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  lockAcquired = true;
}

// 释放锁的辅助函数
function releaseLock(): void {
  lockAcquired = false;
}

async function updateOAuthStateUsage(stateId: string): Promise<void> {
  const state = oauthStates.get(stateId);
  if (state) {
    state.lastUsedAt = Date.now();
    oauthStates.set(stateId, state);
    await saveOAuthStateToKv(stateId, state);
  }
}

async function safeDeleteOAuthState(stateId: string): Promise<void> {
  try {
    if (oauthStates.has(stateId)) {
      oauthStates.delete(stateId);
    }
    await deleteOAuthStateFromKv(stateId);
  } catch (error) {
    console.error(`删除OAuth状态 ${stateId} 失败:`, error);
  }
}

async function validateOAuthState(stateId: string): Promise<boolean> {
  try {
    const state = oauthStates.get(stateId);
    if (!state) {
      return false;
    }
    
    const now = Date.now();
    
    if (state.expiresAt && now > state.expiresAt + 60000) {
      await safeDeleteOAuthState(stateId);
      return false;
    }
    
    if (state.lastUsedAt && now - state.lastUsedAt > 30 * 60 * 1000) {
      await safeDeleteOAuthState(stateId);
      return false;
    }
    
    if (state.createdAt && now - state.createdAt > 60 * 60 * 1000) {
      await safeDeleteOAuthState(stateId);
      return false;
    }
    
    return true;
  } catch (error) {
    console.error(`验证OAuth状态 ${stateId} 失败:`, error);
    return false;
  }
}

let cleanupTimer: number | null = null;

async function cleanupExpiredOAuthStates(): Promise<void> {
  await acquireLock();
  try {
    const now = Date.now();
    const expiredStates: string[] = [];
    
    for (const [stateId, state] of oauthStates.entries()) {
      let shouldDelete = false;
      
      if (state.expiresAt && now > state.expiresAt + 60000) {
        shouldDelete = true;
      }
      
      if (!shouldDelete && state.lastUsedAt && now - state.lastUsedAt > 30 * 60 * 1000) {
        shouldDelete = true;
      }
      
      if (!shouldDelete && state.createdAt && now - state.createdAt > 60 * 60 * 1000) {
        shouldDelete = true;
      }
      
      if (shouldDelete) {
        expiredStates.push(stateId);
      }
    }
    
    for (const stateId of expiredStates) {
      await safeDeleteOAuthState(stateId);
    }
    
    if (kv) {
      try {
        const entries = kv.list<OAuthState>({ prefix: ["oauth_states"] });
        
        for await (const entry of entries) {
          const stateId = entry.key[1] as string;
          const state = entry.value;
          let shouldDelete = false;
          
          if (state.expiresAt && now > state.expiresAt + 60000) {
            shouldDelete = true;
          }
          
          if (!shouldDelete && state.lastUsedAt && now - state.lastUsedAt > 30 * 60 * 1000) {
            shouldDelete = true;
          }
          
          if (!shouldDelete && state.createdAt && now - state.createdAt > 60 * 60 * 1000) {
            shouldDelete = true;
          }
          
          if (shouldDelete) {
            await deleteOAuthStateFromKv(stateId);
          }
        }
      } catch (error) {
        console.error('清理KV中的过期状态失败:', error);
      }
    }
  } catch (error) {
    console.error('清理过期OAuth状态失败:', error);
  } finally {
    releaseLock();
  }
}

function startPeriodicCleanup(): void {
  cleanupTimer = setInterval(cleanupExpiredOAuthStates, 2 * 60 * 1000);
}

function stopPeriodicCleanup(): void {
  if (cleanupTimer) {
    clearInterval(cleanupTimer);
    cleanupTimer = null;
  }
}

// 生成PKCE代码验证器和挑战码
async function generatePKCEPair(): Promise<{ codeVerifier: string; codeChallenge: string }> {
  // 生成 code_verifier (43-128 字符的随机字符串)
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  const codeVerifier = btoa(String.fromCharCode(...array))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
  
  // 生成 code_challenge (code_verifier 的 SHA256 哈希)
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const hash = await crypto.subtle.digest('SHA-256', data);
  const codeChallenge = btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
  
  return { codeVerifier, codeChallenge };
}

// 生成随机状态ID
function generateStateId(): string {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

// 请求设备授权
async function requestDeviceAuthorization(codeChallenge: string): Promise<OAuthState> {
  const bodyData = {
    client_id: QWEN_OAUTH_CLIENT_ID,
    scope: QWEN_OAUTH_SCOPE,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256'
  };

  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Accept': 'application/json',
    'x-request-id': generateStateId()
  };

  const response = await fetch(QWEN_OAUTH_DEVICE_CODE_ENDPOINT, {
    method: 'POST',
    headers,
    body: new URLSearchParams(bodyData)
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Device authorization failed: ${response.status} ${response.statusText}. Response: ${errorText}`);
  }

  const result = await response.json();
  
  // 检查是否包含错误
  if ('error' in result) {
    throw new Error(`Device authorization failed: ${result.error} - ${result.error_description}`);
  }

  return {
    deviceCode: result.device_code,
    userCode: result.user_code,
    verificationUri: result.verification_uri,
    verificationUriComplete: result.verification_uri_complete,
    expiresAt: Date.now() + result.expires_in * 1000,
    pollInterval: result.interval || 2
  };
}

// 轮询获取token
async function pollDeviceToken(deviceCode: string, codeVerifier: string): Promise<any> {
  const bodyData = {
    grant_type: QWEN_OAUTH_GRANT_TYPE,
    client_id: QWEN_OAUTH_CLIENT_ID,
    device_code: deviceCode,
    code_verifier: codeVerifier
  };

  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Accept': 'application/json'
  };

  const response = await fetch(QWEN_OAUTH_TOKEN_ENDPOINT, {
    method: 'POST',
    headers,
    body: new URLSearchParams(bodyData)
  });

  if (!response.ok) {
    try {
      const errorData = await response.json();

      // 处理标准 OAuth 错误
      if (response.status === 400 && errorData.error === 'authorization_pending') {
        return { status: 'pending' };
      }

      if (response.status === 429 && errorData.error === 'slow_down') {
        return { status: 'pending', slowDown: true };
      }

      // 其他错误
      throw new Error(`Device token poll failed: ${errorData.error} - ${errorData.error_description}`);

    } catch (error) {
      if (error instanceof SyntaxError) {
        const errorText = await response.text();
        throw new Error(`Device token poll failed: ${response.status} ${response.statusText}. Response: ${errorText}`);
      }
      throw error;
    }
  }

  return response.json();
}

// 轮询直到获取token或超时
async function pollUntilTokenReceived(stateId: string, maxAttempts: number = 300): Promise<TokenData | null> {
  await acquireLock();
  try {
    const state = oauthStates.get(stateId);
    if (!state || !state.deviceCode || !state.codeVerifier) {
      throw new Error('Invalid OAuth state');
    }

    let pollInterval = state.pollInterval || 2;
    const startTime = Date.now();
    
    // 完全基于服务器返回的 expiresAt 来确定超时时间
    if (!state.expiresAt) {
      throw new Error('OAuth state missing expiresAt');
    }
    const timeoutMs = state.expiresAt - startTime;
      
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      // 更新使用时间（每轮询一次就更新）
      await updateOAuthStateUsage(stateId);
      
      // 检查是否超时
      if (Date.now() - startTime > timeoutMs) {
        await safeDeleteOAuthState(stateId);
        throw new Error('Authentication timed out');
      }
      
      try {
        const tokenResponse = await pollDeviceToken(state.deviceCode, state.codeVerifier);
        
        // 检查是否成功获取令牌
        if (tokenResponse.access_token) {
          // 转换为 TokenData 格式
          const tokenData: TokenData = {
            access_token: tokenResponse.access_token,
            refresh_token: tokenResponse.refresh_token,
            expires_at: Date.now() + (tokenResponse.expires_in || 3600) * 1000,
            uploaded_at: Date.now()
          };
          
          // 清理OAuth状态
          await safeDeleteOAuthState(stateId);
          
          return tokenData;
        }
        
        // 检查是否为待处理状态
        if (tokenResponse.status === 'pending') {
          if (tokenResponse.slowDown) {
            pollInterval = Math.min(pollInterval * 1.5, 10); // 增加间隔，最大10秒
          }
          
          // 等待下一次轮询
          await new Promise(resolve => setTimeout(resolve, pollInterval * 1000));
          continue;
        }
        
      } catch (error) {
        console.error(`Poll attempt ${attempt + 1} failed:`, error);
        
        // 如果是设备码过期或无效的错误，停止轮询
        if (error.message.includes('401') || error.message.includes('invalid_device_code') || error.message.includes('expired_token')) {
          await safeDeleteOAuthState(stateId);
          throw new Error('Device code expired or invalid');
        }
        
        // 其他错误，继续轮询
        await new Promise(resolve => setTimeout(resolve, pollInterval * 1000));
      }
    }
    
    // 超时处理
    await safeDeleteOAuthState(stateId);
    throw new Error('Authentication timed out after maximum attempts');
  } finally {
    releaseLock();
  }
}

// Token存储结构
interface TokenData {
  access_token: string;
  refresh_token: string;
  expires_at?: number; // 过期时间戳
  uploaded_at: number;  // 上传时间
}

// 使用Map存储多个token，以refresh_token前8位作为键
const tokenStore: Map<string, TokenData> = new Map();

// KV存储的token管理函数
async function saveTokenToKv(tokenId: string, tokenData: TokenData): Promise<void> {
  if (!kv) return;
  try {
    await kv.set(["tokens", tokenId], tokenData);
      } catch (error) {
    console.error(`保存Token ${tokenId} 到KV存储失败:`, error);
  }
}

async function loadTokensFromKv(): Promise<void> {
  if (!kv) return;
  try {
    const entries = kv.list<string, TokenData>({ prefix: ["tokens"] });
    tokenStore.clear();
    for await (const entry of entries) {
      tokenStore.set(entry.key[1], entry.value);
    }
      } catch (error) {
    console.error("从KV存储加载token失败:", error);
  }
}

async function deleteTokenFromKv(tokenId: string): Promise<void> {
  if (!kv) return;
  try {
    await kv.delete(["tokens", tokenId]);
      } catch (error) {
    console.error(`删除Token ${tokenId} 从KV存储失败:`, error);
  }
}

// HTML模板
const HTML_TEMPLATE = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Qwen Code API 管理器</title>
    <link rel=icon href=https://assets.alicdn.com/g/qwenweb/qwen-webui-fe/0.0.190/favicon.png>
    <link rel=apple-touch-icon href=https://assets.alicdn.com/g/qwenweb/qwen-webui-fe/0.0.190/favicon.png>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
            overflow-x: hidden;
        }
        .container {
            background-color: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        h1 {
            color: #2c3e50;
            text-align: center;
            margin-bottom: 30px;
        }
        .section {
            margin-bottom: 30px;
            padding: 15px;
            border: 1px solid #ddd;
            border-radius: 5px;
        }
        
            .section h2 {
            margin-top: 0;
            color: #3498db;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="password"],
        input[type="text"],
        textarea {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        button {
            background-color: #3498db;
            color: white;
            border: none;
            padding: 10px 15px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
        }
        button:hover {
            background-color: #2980b9;
        }
        .drop-zone {
            border: 2px dashed #3498db;
            border-radius: 5px;
            padding: 25px;
            text-align: center;
            color: #3498db;
            cursor: pointer;
            transition: all 0.3s;
        }
        .drop-zone:hover,
        .drop-zone.dragover {
            background-color: #f0f8ff;
            border-color: #2980b9;
        }
        .status {
            padding: 10px;
            margin: 10px 0;
            border-radius: 4px;
        }
        
        .status.floating {
            position: fixed;
            top: 20px;
            left: 50%;
            transform: translateX(-50%);
            z-index: 1000;
            min-width: 300px;
            max-width: 80%;
            text-align: center;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
            font-weight: 500;
            padding: 12px 20px;
        }
        .success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .error {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        .info {
            background-color: #d1ecf1;
            color: #0c5460;
            border: 1px solid #bee5eb;
        }
        .hidden {
            display: none;
        }
        pre {
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            overflow-x: auto;
            white-space: pre-wrap;
        }
        .token-info {
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            margin: 10px 0;
        }
        .token-info strong {
            color: #495057;
        }
        .token-card {
            background-color: #ffffff;
            border: 1px solid #e0e0e0;
            border-top: 3px solid transparent;
            border-radius: 8px;
            padding: 12px;
            margin: 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            transition: all 0.3s ease, border-top-color 0.3s ease;
            box-sizing: border-box;
            width: 100%;
        }
        
        .token-card:hover {
            box-shadow: 0 4px 8px rgba(0,0,0,0.15);
            transform: translateY(-2px);
            border-top-color: #3498db;
        }
        
        .token-card:active,
        .token-card:focus {
            border-top-color: #3498db;
            box-shadow: 0 6px 12px rgba(0,0,0,0.2);
            transform: translateY(-1px);
        }
        
        .token-list-wrapper {
            display: flex;
            justify-content: center;
            width: 100%;
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        .token-list {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 15px;
            width: 100%;
            margin: 0;
        }

        .token-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .token-id {
            font-weight: bold;
            color: #2c3e50;
            font-size: 16px;
            word-break: break-all;
            overflow-wrap: break-word;
            max-width: 300px;
        }
        .token-status {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
        }
        .status-valid {
            background-color: #d4edda;
            color: #155724;
        }
        .status-expired {
            background-color: #f8d7da;
            color: #721c24;
        }
        .token-details {
            font-size: 13px;
            color: #666;
            margin-bottom: 8px;
        }
        
        .token-details div {
            margin-bottom: 4px;
            word-break: break-word;
            overflow-wrap: break-word;
        }
        
        @media (max-width: 1200px) {
            .token-list {
                grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
            }
        }
        
        @media (max-width: 768px) {
            .token-list {
                grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
                gap: 10px;
            }
            
            .token-id {
                max-width: 200px;
            }
        }
        
        @media (max-width: 480px) {
            .token-list {
                grid-template-columns: 1fr;
                gap: 15px;
            }
            
            .token-card {
                margin: 0;
            }
            
            .token-id {
                max-width: 100%;
                word-break: break-word;
                overflow-wrap: break-word;
            }
            
            .token-details {
                font-size: 12px;
            }
            
            .token-details div {
                font-size: 12px;
            }
            
            .container {
                padding: 15px;
                overflow-x: hidden;
            }
            
            .section {
                margin-bottom: 20px;
            }
            
            body {
                padding: 10px;
            }
            
            .container {
                padding: 10px;
            }
            
            #oauth-details {
                padding: 10px !important;
            }
            
            #oauth-details .oauth-button-container {
                text-align: center !important;
                display: flex !important;
                flex-direction: column !important;
                gap: 10px !important;
                align-items: center !important;
                width: 100% !important;
                margin-top: 15px !important;
            }
            
            #manual-open-btn,
            #oauth-cancel-btn {
                width: 100% !important;
                max-width: 250px !important;
                padding: 12px 16px !important;
                font-size: 14px !important;
                border-radius: 4px !important;
                border: none !important;
                cursor: pointer !important;
                text-align: center !important;
                box-sizing: border-box !important;
                margin: 0 !important;
                height: auto !important;
                line-height: 1.2 !important;
                white-space: normal !important;
                word-wrap: break-word !important;
                display: inline-block !important;
                vertical-align: middle !important;
            }
            
            #manual-open-btn {
                background-color: #007bff !important;
                color: white !important;
                order: 1 !important;
            }
            
            #oauth-cancel-btn {
                background-color: #dc3545 !important;
                color: white !important;
                order: 2 !important;
            }
            
            #manual-open-btn:hover,
            #oauth-cancel-btn:hover {
                opacity: 0.9 !important;
            }
            
            #manual-open-btn:disabled,
            #oauth-cancel-btn:disabled {
                opacity: 0.6 !important;
                cursor: not-allowed !important;
            }
        }
        .token-actions {
            display: flex;
            gap: 10px;
            justify-content: center;
            margin-top: 10px;
        }
        
        .token-status-buttons {
            display: flex;
            justify-content: center;
            gap: 10px;
            margin: 15px 0;
        }
        
        /* OAuth按钮桌面端样式 */
        #oauth-details .oauth-button-container {
            text-align: center;
            display: flex;
            justify-content: center;
            gap: 10px;
            align-items: center;
            width: 100%;
            margin-top: 15px;
        }
        
        #manual-open-btn,
        #oauth-cancel-btn {
            padding: 8px 16px;
            font-size: 14px;
            border-radius: 4px;
            border: none;
            cursor: pointer;
            text-align: center;
            box-sizing: border-box;
            margin: 0;
            height: auto;
            line-height: 1.2;
            white-space: nowrap;
            display: inline-block;
        }
        
        #manual-open-btn {
            background-color: #007bff;
            color: white;
        }
        
        #oauth-cancel-btn {
            background-color: #dc3545;
            color: white;
        }
        
        #manual-open-btn:hover,
        #oauth-cancel-btn:hover {
            opacity: 0.9;
        }
        
        #manual-open-btn:disabled,
        #oauth-cancel-btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }
        
        #refresh-status {
            text-align: center;
            margin: 10px 0;
            border: none;
            border-radius: 0;
            padding: 0;
            background: none;
        }
        
        #token-status {
            margin-bottom: 15px;
            background-color: #f8f9fa;
            border-radius: 4px;
            padding: 15px;
            border: 1px solid #e9ecef;
        }
        
        #token-status.status {
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            background-color: white;
        }
        
        #refresh-token-btn, #delete-all-tokens-btn {
            display: inline-block;
            margin: 0;
        }
        .btn-refresh, .btn-delete {
            padding: 6px 12px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            font-weight: bold;
            transition: all 0.3s ease;
        }
        .btn-refresh {
            background-color: #3498db;
            color: white;
        }
        .btn-refresh:hover {
            background-color: #2980b9;
        }
        .btn-delete {
            background-color: #e74c3c;
            color: white;
        }
        .btn-delete:hover {
            background-color: #c0392b;
        }
        .btn-refresh:disabled, .btn-delete:disabled {
            background-color: #bdc3c7;
            cursor: not-allowed;
        }
        
        .api-test-section {
            background-color: white;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 30px;
        }
        
        .api-test-section h2 {
            color: #3498db;
            margin-top: 0;
            margin-bottom: 20px;
            text-align: left;
        }
        
        .api-test-section .form-group {
            margin-bottom: 15px;
        }
        
        .api-test-section .form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
            color: #333;
        }
        
        #message {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
            font-size: 14px;
            line-height: 1.6;
            color: #333;
            background-color: white;
            resize: vertical;
            min-height: 80px;
            transition: border-color 0.3s ease;
        }
        
        #message:focus {
            outline: none;
            border-color: #3498db;
        }
        
        #message:hover {
            border-color: #3498db;
        }
        
        #model {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
            font-size: 14px;
            background-color: white;
            color: #333;
            cursor: pointer;
            transition: border-color 0.3s ease;
        }
        
        #model:focus {
            outline: none;
            border-color: #3498db;
        }
        
        #model:hover {
            border-color: #3498db;
        }
        
        #send-btn {
            background-color: #3498db;
            color: white;
            border: none;
            padding: 10px 15px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            transition: background-color 0.3s ease;
            display: block;
            margin: 20px auto 0;
        }
        
        #send-btn:hover {
            background-color: #2980b9;
        }
        
        #api-response {
            margin-top: 20px;
            border: 1px solid #ddd;
            border-radius: 4px;
            background-color: white;
        }
        
        #api-response h3 {
            background-color: #f8f9fa;
            color: #2c3e50;
            margin: 0;
            padding: 10px;
            font-size: 16px;
            font-weight: bold;
            border-bottom: 1px solid #ddd;
        }
        
        #response-content {
            padding: 10px;
            background-color: #f8f9fa;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            line-height: 1.4;
            max-height: 200px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
            color: #333;
        }
        
        #response-content::-webkit-scrollbar {
            width: 6px;
        }
        
        #response-content::-webkit-scrollbar-track {
            background: #f1f1f1;
            border-radius: 3px;
        }
        
        #response-content::-webkit-scrollbar-thumb {
            background: #3498db;
            border-radius: 3px;
        }
        
        #response-content::-webkit-scrollbar-thumb:hover {
            background: #2980b9;
        }
        
        #api-status {
            text-align: center;
            margin: 10px 0;
            padding: 10px;
            border-radius: 4px;
            font-weight: 500;
        }
        
        #login-section {
            background-color: white;
            border: none;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 30px;
            text-align: center;
        }
        
        #login-section h2 {
            color: #3498db;
            margin-top: 0;
            margin-bottom: 20px;
            text-align: center;
        }
        
        #login-section .form-group {
            margin-bottom: 15px;
        }
        
        .login-input-group {
            display: flex;
            justify-content: center;
            align-items: stretch;
            max-width: 400px;
            margin: 0 auto;
        }
        
        #password {
            flex: 1;
            padding: 10px 15px;
            border: 1px solid #ddd;
            border-radius: 4px 0 0 4px;
            box-sizing: border-box;
            font-size: 14px;
            line-height: 1.6;
            color: #333;
            background-color: white;
            transition: border-color 0.3s ease;
            height: 42px;
        }
        
        #password:focus {
            outline: none;
            border-color: #3498db;
        }
        
        #password:hover {
            border-color: #3498db;
        }
        
        #login-btn {
            background-color: #3498db;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 0 4px 4px 0;
            cursor: pointer;
            font-size: 14px;
            transition: background-color 0.3s ease;
            height: 42px;
            margin: 0;
            display: inline-block;
            white-space: nowrap;
            min-width: 80px;
        }
        
        #login-btn:hover {
            background-color: #2980b9;
        }
        
        #login-btn:disabled {
            background-color: #bdc3c7;
            cursor: not-allowed;
        }
        
        #login-status {
            text-align: center;
            margin: 10px 0;
            padding: 10px;
            border-radius: 4px;
            font-weight: 500;
        }
    </style>
</head>
<body>
    <!-- Floating status message element -->
    <div id="floating-status" class="status floating" style="display: none;"></div>
    
    <div class="container">
        <h1>🤖 Qwen Code API 管理器</h1>
        
        <!-- 登录表单 -->
        <div id="login-section" class="section">
            <h2>🔐 登录</h2>
            <div class="form-group">
                <div class="login-input-group">
                    <input type="password" id="password" placeholder="请输入密码">
                    <button id="login-btn">登录</button>
                </div>
            </div>
            <div id="login-status" class="status"></div>
        </div>
        
        <!-- 主界面 -->
        <div id="main-section" class="hidden">
            <!-- 凭证获取区域 -->
            <div class="section">
                <h2>🔐 获取 OAuth 凭证</h2>
                
                <!-- OAuth 登录按钮 -->
                <div style="margin-bottom: 20px; text-align: center;">
                    <button id="oauth-login-btn" style="background-color: #28a745; color: white; padding: 12px 24px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px;">
                        🔑 OAuth 登录获取 Token
                    </button>
                    <div style="margin-top: 10px;">
                        <span style="color: #666; font-size: 14px;">通过 Qwen 官网 OAuth 认证自动获取凭证</span>
                    </div>
                </div>
                
                <!-- OAuth 登录状态显示 -->
                <div id="oauth-status" class="status" style="display: none;"></div>
                
                <!-- OAuth 登录详情（初始隐藏） -->
                <div id="oauth-details" class="hidden" style="background-color: #f8f9fa; padding: 15px; border-radius: 4px; margin-bottom: 15px;">
                    <div id="oauth-instructions"></div>
                    <div class="oauth-button-container">
                        <button id="manual-open-btn">
                            🔗 打开授权页面
                        </button>
                        <button id="oauth-cancel-btn">
                            ❌ 取消授权
                        </button>
                    </div>
                </div>
                
                <!-- 文件上传区域 -->
                <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #ddd;">
                    <h3>📁 或上传现有凭证文件</h3>
                    <div id="drop-zone" class="drop-zone">
                        <p>拖拽 oauth_creds.json 文件到此处，或点击选择文件</p>
                        <input type="file" id="file-input" accept=".json" style="display: none;">
                    </div>
                    <div id="upload-status" class="status"></div>
                </div>
            </div>
            
            <!-- Token状态 -->
            <div class="section">
                <h2 style="margin-top: 0; margin-bottom: 15px; color: #3498db;">🔑 Token 状态</h2>
                <div id="token-status" class="status info" style="display: none;">
                    <div>尚未上传凭证文件</div>
                </div>
                <div class="token-status-buttons" style="display: none;">
                    <button id="refresh-token-btn">刷新所有 Token</button>
                    <button id="delete-all-tokens-btn" style="background-color: #e74c3c;">删除所有 Token</button>
                </div>
                <div id="refresh-status" class="status"></div>
            </div>
            
            <!-- API测试 -->
            <div class="section api-test-section">
                <h2>💬 API 测试</h2>
                <div class="form-group">
                    <label for="message">消息:</label>
                    <textarea id="message" rows="3" placeholder="输入要发送给Qwen的消息">你好，请介绍一下你自己</textarea>
                </div>
                <div class="form-group">
                    <label for="model">模型:</label>
                    <select id="model">
                        <option value="qwen3-coder-plus">qwen3-coder-plus</option>
                    </select>
                </div>
                <button id="send-btn">发送请求</button>
                <div id="api-status" class="status"></div>
                <div id="api-response" class="hidden">
                    <h3>响应:</h3>
                    <pre id="response-content"></pre>
                </div>
            </div>
            
            <!-- 使用说明 -->
            <div class="section">
                <h2>📖 使用说明</h2>
                <h3>🔑 OAuth 登录方式（推荐）</h3>
                <ol>
                    <li>点击"OAuth 登录获取 Token"按钮</li>
                    <li>系统自动打开 QWen 授权页面</li>
                    <li>授权完成后，系统会自动获取并保存 token</li>
                </ol>
                
                <h3>📁 文件上传方式</h3>
                <ol>
                    <li>从本地 ~/.qwen/oauth_creds.json 文件复制内容</li>
                    <li>将文件拖拽到上传区域或点击选择文件</li>
                    <li>系统会自动解析并显示token状态</li>
                </ol>
                
                <h3>💬 使用 API</h3>
                <ol>
                    <li>使用API测试区域与Qwen Code进行交互</li>
                    <li>系统会自动刷新过期的token，无需手动操作</li>
                </ol>
                
            </div>
        </div>
    </div>

    <script>
        // 等待DOM完全加载后再执行JavaScript代码
        document.addEventListener('DOMContentLoaded', function() {
                        
            // DOM元素
            const loginSection = document.getElementById('login-section');
            const mainSection = document.getElementById('main-section');
            const passwordInput = document.getElementById('password');
            const loginBtn = document.getElementById('login-btn');
            const loginStatus = document.getElementById('login-status');
            const dropZone = document.getElementById('drop-zone');
            const fileInput = document.getElementById('file-input');
            const uploadStatus = document.getElementById('upload-status');
            const tokenStatus = document.getElementById('token-status');
            const refreshTokenBtn = document.getElementById('refresh-token-btn');
            const deleteAllTokensBtn = document.getElementById('delete-all-tokens-btn');
            const refreshStatus = document.getElementById('refresh-status');
            const messageInput = document.getElementById('message');
            const modelSelect = document.getElementById('model');
            const sendBtn = document.getElementById('send-btn');
            const apiStatus = document.getElementById('api-status');
            const apiResponse = document.getElementById('api-response');
            const responseContent = document.getElementById('response-content');
            const floatingStatus = document.getElementById('floating-status');
            
            // OAuth 相关元素
            const oauthLoginBtn = document.getElementById('oauth-login-btn');
            const oauthStatus = document.getElementById('oauth-status');
            const oauthDetails = document.getElementById('oauth-details');
            const oauthInstructions = document.getElementById('oauth-instructions');
            const oauthCancelBtn = document.getElementById('oauth-cancel-btn');
            
            // 验证DOM元素是否正确获取
            if (!loginBtn) {
                console.error('无法获取登录按钮元素'); 
                // 不要直接返回，尝试延迟加载
                setTimeout(() => {
                    const delayedLoginBtn = document.getElementById('login-btn');
                    if (!delayedLoginBtn) {
                        console.error('延迟后仍无法获取登录按钮元素');
                        return;
                    }
                                        // 重新绑定事件
                    delayedLoginBtn.addEventListener('click', async function() {
                         
                        const password = passwordInput ? passwordInput.value : '';
                         
                        
                        if (!password) {
                            if (loginStatus) showStatus(loginStatus, '请输入密码', 'error');
                            return;
                        }
                        
                        // 禁用登录按钮，防止重复提交
                        delayedLoginBtn.disabled = true;
                        delayedLoginBtn.textContent = '登录中...';
                        if (loginStatus) showStatus(loginStatus, '正在登录，请稍候...', 'info');
                        
                        try {
                             
                            const response = await fetch('/api/login', {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json',
                                },
                                body: JSON.stringify({ password }),
                            });
                            
                             
                            
                            // 检查响应内容类型
                            const contentType = response.headers.get('content-type');
                             
                            
                            let data;
                            if (contentType && contentType.includes('application/json')) {
                                data = await response.json();
                                 
                            } else {
                                const textResponse = await response.text();
                                 
                                throw new Error('服务器返回了非JSON格式的响应');
                            }
                            
                            if (response.ok) {
                                if (loginStatus) showStatus(loginStatus, '登录成功', 'success');
                                userPassword = password; // 保存密码用于后续API调用
                                if (loginSection) loginSection.classList.add('hidden');
                                if (mainSection) mainSection.classList.remove('hidden');
                                checkTokenStatus();
                                // 登录成功后清除登录状态信息
                                setTimeout(() => {
                                    if (loginStatus) {
                                        loginStatus.style.display = 'none';
                                    }
                                }, 3000);
                            } else {
                                if (loginStatus) showStatus(loginStatus, data.error || '登录失败', 'error');
                            }
                        } catch (error) {
                            console.error('登录过程中发生错误:', error); 
                            if (loginStatus) showStatus(loginStatus, '网络错误: ' + error.message, 'error');
                        } finally {
                            // 恢复登录按钮状态
                            delayedLoginBtn.disabled = false;
                            delayedLoginBtn.textContent = '登录';
                        }
                    });
                }, 100);
            } else {
                 
            }
            
             
            
            // 存储用户密码用于API认证
            let userPassword = '';
            
            // 登录功能
            loginBtn.addEventListener('click', async function() {
                 
                const password = passwordInput ? passwordInput.value : '';
                 
                
                if (!password) {
                    if (loginStatus) showStatus(loginStatus, '请输入密码', 'error');
                    return;
                }
                
                // 禁用登录按钮，防止重复提交
                loginBtn.disabled = true;
                loginBtn.textContent = '登录中...';
                if (loginStatus) showStatus(loginStatus, '正在登录，请稍候...', 'info');
                
                try {
                     
                    const response = await fetch('/api/login', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({ password }),
                    });
                    
                     
                    
                    // 检查响应内容类型
                    const contentType = response.headers.get('content-type');
                     
                    
                    let data;
                    if (contentType && contentType.includes('application/json')) {
                        data = await response.json();
                         
                    } else {
                        const textResponse = await response.text();
                         
                        throw new Error('服务器返回了非JSON格式的响应');
                    }
                    
                    if (response.ok) {
                        if (loginStatus) showStatus(loginStatus, '登录成功', 'success');
                        userPassword = password; // 保存密码用于后续API调用
                        if (loginSection) loginSection.classList.add('hidden');
                        if (mainSection) mainSection.classList.remove('hidden');
                        checkTokenStatus();
                        // 登录成功后清除登录状态信息
                        setTimeout(() => {
                            if (loginStatus) {
                                loginStatus.style.display = 'none';
                            }
                        }, 3000);
                    } else {
                        if (loginStatus) showStatus(loginStatus, data.error || '登录失败', 'error');
                    }
                } catch (error) {
                    console.error('登录过程中发生错误:', error); 
                    if (loginStatus) showStatus(loginStatus, '网络错误: ' + error.message, 'error');
                } finally {
                    // 恢复登录按钮状态
                    loginBtn.disabled = false;
                    loginBtn.textContent = '登录';
                }
            });
            
            // 文件上传功能
            if (dropZone && fileInput) {
                dropZone.addEventListener('click', function() { fileInput.click(); });
                
                dropZone.addEventListener('dragover', function(e) {
                    e.preventDefault();
                    dropZone.classList.add('dragover');
                });
                
                dropZone.addEventListener('dragleave', function() {
                    dropZone.classList.remove('dragover');
                });
                
                dropZone.addEventListener('drop', function(e) {
                    e.preventDefault();
                    dropZone.classList.remove('dragover');
                    
                    if (e.dataTransfer.files.length) {
                        handleFileUpload(e.dataTransfer.files[0]);
                    }
                });
                
                fileInput.addEventListener('change', function(e) {
                    if (e.target.files.length) {
                        handleFileUpload(e.target.files[0]);
                    }
                });
            }
            
            // OAuth 登录按钮事件
            if (oauthLoginBtn) {
                oauthLoginBtn.addEventListener('click', startOAuthLogin);
            }
            
            if (oauthCancelBtn) {
                oauthCancelBtn.addEventListener('click', cancelOAuthLogin);
            }
            
            // 手动打开授权页面按钮事件（初始时禁用）
            const manualOpenBtn = document.getElementById('manual-open-btn');
            if (manualOpenBtn) {
                manualOpenBtn.disabled = true;
            }
            
            // 处理文件上传
            async function handleFileUpload(file) {
                if (!uploadStatus) return;
                
                if (file.name !== 'oauth_creds.json') {
                    showStatus(uploadStatus, '请上传 oauth_creds.json 文件', 'error');
                    return;
                }
                
                try {
                    const content = await file.text();
                    const creds = JSON.parse(content);
                    
                    if (!creds.access_token || !creds.refresh_token) {
                        showStatus(uploadStatus, '文件格式不正确，缺少access_token或refresh_token', 'error');
                        return;
                    }
                    
                    const response = await fetch('/api/upload-token', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': 'Bearer ' + userPassword,
                        },
                        body: JSON.stringify(creds),
                    });
                    
                    const data = await response.json();
                    
                    if (response.ok) {
                        showStatus(uploadStatus, '凭证上传成功', 'success');
                        checkTokenStatus();
                    } else {
                        showStatus(uploadStatus, data.error || '上传失败', 'error');
                    }
                } catch (error) {
                    showStatus(uploadStatus, '文件处理错误: ' + error.message, 'error');
                }
            }
            
            // OAuth 登录状态管理
            let oauthStateId = null;
            let oauthPollTimer = null;
            let oauthStartTime = null;
            let oauthCountdownTimer = null;
            let oauthExpiresAt = null;
            
            // 开始 OAuth 登录流程
            async function startOAuthLogin() {
                if (!oauthLoginBtn || !oauthStatus || !oauthDetails || !oauthInstructions) return;
                
                try {
                    // 禁用登录按钮
                    oauthLoginBtn.disabled = true;
                    oauthLoginBtn.textContent = '正在初始化...';
                    
                    showStatus(oauthStatus, '正在初始化 OAuth 认证...', 'info');
                    
                    // 调用后端初始化 OAuth
                    const response = await fetch('/api/oauth-init', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': 'Bearer ' + userPassword,
                        }
                    });
                    
                    const data = await response.json();
                    
                    if (response.ok && data.success) {
                        oauthStateId = data.stateId;
                        // 使用服务器返回的实际超时时间
                        oauthExpiresAt = data.expiresAt;
                        oauthStartTime = Date.now(); // 记录开始时间
                        
                        // 更新按钮状态为等待授权
                        oauthLoginBtn.textContent = '⏳ 等待授权...';
                        
                        // 自动打开授权页面
                        let autoOpened = false;
                        try {
                            window.open(data.verificationUriComplete, '_blank');
                            autoOpened = true;
                        } catch (e) {
                            console.error('自动打开授权页面失败:', e);
                        }
                        
                        // 显示授权说明（简化版）
                        const expiresAt = new Date(oauthExpiresAt);
                        const totalSeconds = Math.floor((oauthExpiresAt - oauthStartTime) / 1000);
                        const minutes = Math.floor(totalSeconds / 60);
                        oauthInstructions.innerHTML = 
                            '<div style="text-align: center; margin-bottom: 20px;">' +
                                '<p style="margin-bottom: 15px; color: #666;">' + 
                                    '如授权页面未自动打开，请点击下方按钮' +
                                '</p>' +
                                '<p style="margin-top: 15px; font-size: 12px; color: #999;">' +
                                    '授权完成后将自动获取 Token' +
                                '</p>' +
                                '<p style="margin-top: 5px; font-size: 12px; color: #999;">' +
                                    '⏰ 过期时间: ' + expiresAt.toLocaleString() + ' (' + minutes + '分钟)' +
                                '</p>' +
                            '</div>';
                        
                        // 显示详情区域
                        oauthDetails.classList.remove('hidden');
                        showStatus(oauthStatus, '⏳ 等待授权完成...', 'info');
                        
                        // 设置手动打开按钮事件
                        const manualOpenBtn = document.getElementById('manual-open-btn');
                        if (manualOpenBtn) {
                            // 启用按钮
                            manualOpenBtn.disabled = false;
                            // 移除之前的事件监听器（如果有）
                            manualOpenBtn.replaceWith(manualOpenBtn.cloneNode(true));
                            // 添加新的事件监听器
                            const newManualOpenBtn = document.getElementById('manual-open-btn');
                            if (newManualOpenBtn) {
                                newManualOpenBtn.addEventListener('click', () => {
                                    window.open(data.verificationUriComplete, '_blank');
                                });
                            }
                        }
                        
                        // 开始轮询状态和倒计时
                        startOAuthPolling();
                        startOAuthCountdown();
                        
                    } else {
                        showStatus(oauthStatus, data.error || 'OAuth 初始化失败', 'error');
                        resetOAuthLogin();
                    }
                } catch (error) {
                    showStatus(oauthStatus, '网络错误: ' + error.message, 'error');
                    resetOAuthLogin();
                }
            }
            
            // 开始轮询 OAuth 状态
            function startOAuthPolling() {
                if (!oauthStateId) return;
                
                // 立即执行一次
                pollOAuthStatus();
                
                // 然后每3秒轮询一次
                oauthPollTimer = setInterval(pollOAuthStatus, 3000);
            }
            
            // 开始倒计时
            function startOAuthCountdown() {
                if (!oauthExpiresAt || !oauthStatus) return;
                
                // 立即更新一次
                updateCountdown();
                
                // 每秒更新倒计时
                oauthCountdownTimer = setInterval(updateCountdown, 1000);
            }
            
            // 更新倒计时显示
            function updateCountdown() {
                if (!oauthExpiresAt || !oauthStatus) return;
                
                const now = Date.now();
                const remainingTime = Math.max(0, Math.floor((oauthExpiresAt - now) / 1000));
                const totalTime = Math.floor((oauthExpiresAt - oauthStartTime) / 1000);
                const timeRatio = remainingTime / totalTime;
                
                if (remainingTime > 0) {
                    const minutes = Math.floor(remainingTime / 60);
                    const seconds = remainingTime % 60;
                    const timeString = minutes + ':' + seconds.toString().padStart(2, '0');
                    
                    // 根据剩余时间比例改变显示样式
                    let statusMessage = '⏳ 等待授权完成... 剩余时间: ' + timeString;
                    let statusType = 'info';
                    
                    if (timeRatio < 0.2) { // 剩余时间少于20%
                        statusMessage = '⚠️ 授权即将过期! 剩余时间: ' + timeString;
                        statusType = 'error';
                    } else if (timeRatio < 0.5) { // 剩余时间少于50%
                        statusMessage = '⏰ 请尽快完成授权! 剩余时间: ' + timeString;
                        statusType = 'info';
                    }
                    
                    showStatus(oauthStatus, statusMessage, statusType);
                } else {
                    // 倒计时结束（包括 remainingTime === 0 或负数）
                    showStatus(oauthStatus, '⏰ 授权码已过期，请重新获取', 'error');
                    stopOAuthCountdown();
                }
            }
            
            // 停止倒计时
            function stopOAuthCountdown() {
                if (oauthCountdownTimer) {
                    clearInterval(oauthCountdownTimer);
                    oauthCountdownTimer = null;
                }
            }
            
            // 轮询 OAuth 状态
            async function pollOAuthStatus() {
                if (!oauthStateId || !oauthStatus) return;
                
                try {
                    const response = await fetch('/api/oauth-poll', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': 'Bearer ' + userPassword,
                        },
                        body: JSON.stringify({ stateId: oauthStateId })
                    });
                    
                    const data = await response.json();
                    
                    if (response.ok) {
                        if (data.success) {
                            // 认证成功
                            showStatus(oauthStatus, '🎉 OAuth 认证成功！Token 已自动保存', 'success');
                            resetOAuthLogin();
                            checkTokenStatus(); // 刷新 token 状态
                        } else if (data.status === 'pending') {
                            // 仍在等待授权，显示警告信息（如果有）
                            if (data.warning) {
                                showStatus(oauthStatus, '⚠️ ' + data.warning, 'info');
                            }
                            // 确保倒计时在运行
                            if (!oauthCountdownTimer && oauthExpiresAt) {
                                startOAuthCountdown();
                            }
                            
                        } else {
                            // 认证失败
                            showStatus(oauthStatus, data.error || 'OAuth 认证失败', 'error');
                            resetOAuthLogin();
                        }
                    } else {
                        showStatus(oauthStatus, data.error || '轮询失败', 'error');
                        resetOAuthLogin();
                    }
                } catch (error) {
                    console.error('OAuth 轮询错误:', error);
                    // 网络错误时继续轮询，但不更新UI避免频繁闪烁
                }
            }
            
            // 重置 OAuth 登录状态
            function resetOAuthLogin() {
                // 清除轮询定时器
                if (oauthPollTimer) {
                    clearInterval(oauthPollTimer);
                    oauthPollTimer = null;
                }
                
                // 清除倒计时定时器
                stopOAuthCountdown();
                
                // 重置状态
                oauthStateId = null;
                oauthExpiresAt = null;
                oauthStartTime = null;
                
                // 恢复按钮状态
                if (oauthLoginBtn) {
                    oauthLoginBtn.disabled = false;
                    oauthLoginBtn.textContent = '🔑 OAuth 登录获取 Token';
                }
                
                // 禁用手动打开按钮
                const manualOpenBtn = document.getElementById('manual-open-btn');
                if (manualOpenBtn) {
                    manualOpenBtn.disabled = true;
                }
                
                // 隐藏详情区域
                if (oauthDetails) {
                    oauthDetails.classList.add('hidden');
                }
            }
            
            // 取消 OAuth 登录
            async function cancelOAuthLogin() {
                if (!oauthStateId) {
                    resetOAuthLogin();
                    return;
                }
                
                try {
                    await fetch('/api/oauth-cancel', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': 'Bearer ' + userPassword,
                        },
                        body: JSON.stringify({ stateId: oauthStateId })
                    });
                } catch (error) {
                    console.error('取消 OAuth 登录失败:', error);
                } finally {
                    if (oauthStatus) {
                        showStatus(oauthStatus, 'OAuth 授权已取消', 'info');
                    }
                    resetOAuthLogin();
                }
            }
            
                
            // 确认对话框函数
            function showConfirmDialog(message, onConfirm, onCancel, title = "确认删除") {
                const modal = document.createElement('div');
                modal.style.cssText = 
                    'position: fixed;' +
                    'top: 0;' +
                    'left: 0;' +
                    'width: 100%;' +
                    'height: 100%;' +
                    'background-color: rgba(0, 0, 0, 0.5);' +
                    'display: flex;' +
                    'justify-content: center;' +
                    'align-items: center;' +
                    'z-index: 1000;';
                
                const dialog = document.createElement('div');
                dialog.style.cssText = 
                    'background-color: white;' +
                    'padding: 20px;' +
                    'border-radius: 8px;' +
                    'box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);' +
                    'max-width: 400px;' +
                    'width: 90%;';
                
                dialog.innerHTML = 
                    '<h3 style="margin-top: 0; color: #e74c3c;">⚠️ ' + title + '</h3>' +
                    '<p style="margin-bottom: 20px;">' + message + '</p>' +
                    '<div style="display: flex; gap: 10px; justify-content: flex-end;">' +
                    '<button id="confirm-cancel" style="padding: 8px 16px; border: 1px solid #ddd; background-color: #f8f9fa; border-radius: 4px; cursor: pointer; color: #333; font-weight: 500;">取消</button>' +
                    '<button id="confirm-ok" style="padding: 8px 16px; border: none; background-color: #e74c3c; color: white; border-radius: 4px; cursor: pointer; font-weight: 500;">确认删除</button>' +
                    '</div>';
                
                modal.appendChild(dialog);
                document.body.appendChild(modal);
                
                // 处理确认按钮点击
                document.getElementById('confirm-ok').onclick = function() {
                    document.body.removeChild(modal);
                    if (onConfirm) onConfirm();
                };
                
                // 处理取消按钮点击
                document.getElementById('confirm-cancel').onclick = function() {
                    document.body.removeChild(modal);
                    if (onCancel) onCancel();
                };
                
                // 点击背景关闭
                modal.onclick = function(e) {
                    if (e.target === modal) {
                        document.body.removeChild(modal);
                        if (onCancel) onCancel();
                    }
                };
            }

            // 事件委托处理token按钮点击
            document.addEventListener('click', function(e) {
                const target = e.target;
                if (target.classList.contains('btn-refresh')) {
                    const tokenId = decodeURIComponent(target.getAttribute('data-token-id') || '');
                    if (tokenId) {
                        e.preventDefault();
                        refreshSingleToken(tokenId);
                    }
                } else if (target.classList.contains('btn-delete')) {
                    const tokenId = decodeURIComponent(target.getAttribute('data-token-id') || '');
                    if (tokenId) {
                        e.preventDefault();
                        showConfirmDialog(
                            '确定要删除Token "' + tokenId + '" 吗?此操作不可撤销。',
                            function() {
                                deleteSingleToken(tokenId);
                            },
                            null,
                            "删除单个Token"
                        );
                    }
                }
            });

            // 检查token状态
            async function checkTokenStatus() {
                if (!tokenStatus || !refreshTokenBtn) return;
                
                try {
                    const response = await fetch('/api/token-status', {
                        headers: {
                            'Authorization': 'Bearer ' + userPassword
                        }
                    });
                    const data = await response.json();
                    
                    if (response.ok && data.hasToken) {
                        // 显示token数量和详细列表
                        let tokenListHtml = '';
                        if (data.tokens && data.tokens.length > 0) {
                            tokenListHtml = '<div class="token-list-wrapper"><div class="token-list">';
                            data.tokens.forEach(function(token) {
                                const expiresAt = token.expiresAt ? new Date(token.expiresAt).toLocaleString() : '未知';
                                const status = token.isExpired ? '已过期' : '有效';
                                const statusClass = token.isExpired ? 'status-expired' : 'status-valid';
                                const refreshInfo = token.wasRefreshed ? ' (已自动刷新)' : (token.refreshFailed ? ' (刷新失败)' : '');
                                tokenListHtml += '<div class="token-card" data-token-id="' + encodeURIComponent(token.id) + '">';
                                tokenListHtml += '<div class="token-header">';
                                tokenListHtml += '<div class="token-id">🔑 ' + token.id + '</div>';
                                tokenListHtml += '<div class="token-status ' + statusClass + '">' + status + '</div>';
                                tokenListHtml += '</div>';
                                tokenListHtml += '<div class="token-details">';
                                tokenListHtml += '<div><strong>过期时间:</strong> ' + expiresAt + '</div>';
                                tokenListHtml += '<div><strong>上传时间:</strong> ' + new Date(token.uploadedAt).toLocaleString() + '</div>';
                                if (refreshInfo) {
                                    tokenListHtml += '<div><strong>状态:</strong> ' + refreshInfo + '</div>';
                                }
                                tokenListHtml += '</div>';
                                tokenListHtml += '<div class="token-actions">';
                                tokenListHtml += '<button class="btn-refresh" data-token-id="' + encodeURIComponent(token.id) + '">刷新</button>';
                                tokenListHtml += '<button class="btn-delete" data-token-id="' + encodeURIComponent(token.id) + '">删除</button>';
                                tokenListHtml += '</div>';
                                tokenListHtml += '</div>';
                            });
                            tokenListHtml += '</div></div>';
                        }
                        
                        tokenStatus.innerHTML = '<div class="token-info"><strong>🔢 Token总数:</strong> ' + data.tokenCount + '<br><strong>📊 Token状态:</strong> 有效</div>' + tokenListHtml;
                        tokenStatus.style.display = 'block';
                        
                        // 显示按钮（当有token时）
                        const tokenStatusButtons = document.querySelector('.token-status-buttons');
                        if (tokenStatusButtons) {
                            tokenStatusButtons.style.display = 'flex';
                        }
                    } else {
                        tokenStatus.innerHTML = '<div class="error">尚未上传凭证文件或Token已失效</div>';
                        tokenStatus.style.display = 'block';
                        
                        // 隐藏按钮（当没有token时）
                        const tokenStatusButtons = document.querySelector('.token-status-buttons');
                        if (tokenStatusButtons) {
                            tokenStatusButtons.style.display = 'none';
                        }
                    }
                } catch (error) {
                    if (floatingStatus) {
                        showStatus(floatingStatus, '获取Token状态失败: ' + error.message, 'error');
                    }
                    tokenStatus.innerHTML = '<div class="error">获取Token状态失败: ' + error.message + '</div>';
                    tokenStatus.style.display = 'block';
                    
                    // 隐藏按钮（出错时）
                    const tokenStatusButtons = document.querySelector('.token-status-buttons');
                    if (tokenStatusButtons) {
                        tokenStatusButtons.style.display = 'none';
                    }
                }
            }
            
            // 刷新token
            if (refreshTokenBtn && refreshStatus && floatingStatus) {
                refreshTokenBtn.addEventListener('click', async function() {
                    showStatus(floatingStatus, '正在强制刷新所有Token...', 'info');
                    try {
                        const response = await fetch('/api/refresh-token', {
                            method: 'POST',
                            headers: {
                                'Authorization': 'Bearer ' + userPassword,
                            },
                        });
                        
                        const data = await response.json();
                        
                        if (response.ok) {
                            showStatus(floatingStatus, '强制刷新完成！成功: ' + data.refreshResults.filter(r => r.success).length + '，失败: ' + data.refreshResults.filter(r => !r.success).length, 'success');
                            checkTokenStatus();
                        } else {
                            showStatus(floatingStatus, data.error || '强制刷新失败', 'error');
                        }
                    } catch (error) {
                        showStatus(floatingStatus, '网络错误: ' + error.message, 'error');
                    }
                });
            }
            
            // 删除所有Token
            if (deleteAllTokensBtn) {
                deleteAllTokensBtn.addEventListener('click', async function() {
                    showConfirmDialog(
                        '确定要删除所有Token吗?这将清除内存和KV存储中的所有Token数据，此操作不可撤销。',
                        async function() {
                            if (floatingStatus) {
                                showStatus(floatingStatus, '正在删除所有Token...', 'info');
                            }
                            try {
                                const response = await fetch('/api/delete-all-tokens', {
                                    method: 'POST',
                                    headers: {
                                        'Authorization': 'Bearer ' + userPassword,
                                    },
                                });
                                
                                const data = await response.json();
                                
                                if (response.ok) {
                                    if (floatingStatus) {
                                        showStatus(floatingStatus, data.message || '删除成功', 'success');
                                    }
                                    checkTokenStatus(); // 刷新界面
                                } else {
                                    if (floatingStatus) {
                                        showStatus(floatingStatus, data.error || '删除失败', 'error');
                                    }
                                }
                            } catch (error) {
                                if (floatingStatus) {
                                    showStatus(floatingStatus, '网络错误: ' + error.message, 'error');
                                }
                            }
                        },
                        null,
                        "删除所有Token"
                    );
                });
            }
            
            // 发送API请求
            if (sendBtn && apiStatus && apiResponse && responseContent && messageInput && modelSelect) {
                sendBtn.addEventListener('click', async function() {
                    const message = messageInput.value.trim();
                    const model = modelSelect.value;
                    
                    if (!message) {
                        showStatus(apiStatus, '请输入消息', 'error');
                        return;
                    }
                    
                    showStatus(apiStatus, '正在发送请求...', 'info');
                    apiResponse.classList.add('hidden');
                    
                    try {
                        const response = await fetch('/api/chat', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': 'Bearer ' + userPassword,
                            },
                            body: JSON.stringify({
                                messages: [
                                    {
                                        role: "user",
                                        content: message
                                    }
                                ],
                                model
                            }),
                        });
                        
                        const data = await response.json();
                        
                        if (response.ok) {
                            showStatus(apiStatus, '请求成功', 'success');
                            responseContent.textContent = JSON.stringify(data, null, 2);
                            apiResponse.classList.remove('hidden');
                        } else {
                            showStatus(apiStatus, data.error || '请求失败', 'error');
                        }
                    } catch (error) {
                        showStatus(apiStatus, '网络错误: ' + error.message, 'error');
                    }
                });
            }
            
            // 刷新单个token
            async function refreshSingleToken(tokenId) {
                const card = document.querySelector('[data-token-id="' + encodeURIComponent(tokenId) + '"]');
                if (!card) return;
                
                const refreshBtn = card.querySelector('.btn-refresh');
                const deleteBtn = card.querySelector('.btn-delete');
                
                // 禁用按钮
                if (refreshBtn) {
                    refreshBtn.disabled = true;
                    refreshBtn.textContent = '刷新中...';
                }
                if (deleteBtn) {
                    deleteBtn.disabled = true;
                }
                
                try {
                    const response = await fetch('/api/refresh-single-token', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': 'Bearer ' + userPassword,
                        },
                        body: JSON.stringify({ tokenId }),
                    });
                    
                    const data = await response.json();
                    
                    if (response.ok && data.success) {
                        if (floatingStatus) {
                            showStatus(floatingStatus, 'Token ' + tokenId + ' 刷新成功', 'success');
                        }
                        checkTokenStatus(); 
                    } else {
                        if (floatingStatus) {
                            showStatus(floatingStatus, 'Token ' + tokenId + ' 刷新失败: ' + (data.error || '未知错误'), 'error');
                        }
                        checkTokenStatus(); 
                    }
                } catch (error) {
                    if (floatingStatus) {
                        showStatus(floatingStatus, 'Token ' + tokenId + ' 刷新失败: ' + error.message, 'error');
                    }
                    checkTokenStatus(); 
                } finally {
                    // 重新启用按钮（如果卡片还存在的话）
                    const updatedCard = document.querySelector('[data-token-id="' + encodeURIComponent(tokenId) + '"]');
                    if (updatedCard) {
                        const updatedRefreshBtn = updatedCard.querySelector('.btn-refresh');
                        const updatedDeleteBtn = updatedCard.querySelector('.btn-delete');
                        
                        if (updatedRefreshBtn) {
                            updatedRefreshBtn.disabled = false;
                            updatedRefreshBtn.textContent = '刷新';
                        }
                        if (updatedDeleteBtn) {
                            updatedDeleteBtn.disabled = false;
                        }
                    }
                }
            }
            
            // 删除单个token
            async function deleteSingleToken(tokenId) {
                const card = document.querySelector('[data-token-id="' + encodeURIComponent(tokenId) + '"]');
                if (!card) return;
                
                const refreshBtn = card.querySelector('.btn-refresh');
                const deleteBtn = card.querySelector('.btn-delete');
                
                // 禁用按钮
                if (refreshBtn) {
                    refreshBtn.disabled = true;
                }
                if (deleteBtn) {
                    deleteBtn.disabled = true;
                    deleteBtn.textContent = '删除中...';
                }
                
                try {
                    const response = await fetch('/api/delete-token', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': 'Bearer ' + userPassword,
                        },
                        body: JSON.stringify({ tokenId }),
                    });
                    
                    const data = await response.json();
                    
                    if (response.ok && data.success) {
                        if (floatingStatus) {
                            showStatus(floatingStatus, 'Token ' + tokenId + ' 删除成功', 'success');
                        }
                        checkTokenStatus(); // 刷新整个token列表
                    } else {
                        if (floatingStatus) {
                            showStatus(floatingStatus, 'Token ' + tokenId + ' 删除失败: ' + (data.error || '未知错误'), 'error');
                        }
                    }
                } catch (error) {
                    if (floatingStatus) {
                        showStatus(floatingStatus, 'Token ' + tokenId + ' 删除失败: ' + error.message, 'error');
                    }
                } finally {
                    // 重新启用按钮
                    if (refreshBtn) {
                        refreshBtn.disabled = false;
                    }
                    if (deleteBtn) {
                        deleteBtn.disabled = false;
                        deleteBtn.textContent = '删除';
                    }
                }
            }
            
            // 显示状态信息（居中显示在页面顶部，5秒后自动消失）
            function showStatus(element, message, type) {
                if (!element) return;
                
                // 对于token操作相关的状态消息，使用floating status元素
                if ((element.id === 'token-status' || element.id === 'refresh-status') && 
                    (message.includes('刷新') || message.includes('删除') || message.includes('成功') || message.includes('失败'))) {
                    if (!floatingStatus) return;
                    
                    // 清除之前的定时器
                    if (floatingStatus.hideTimeout) {
                        clearTimeout(floatingStatus.hideTimeout);
                    }
                    
                    floatingStatus.className = 'status floating ' + type;
                    floatingStatus.textContent = message;
                    floatingStatus.style.display = 'block';
                    
                    // 5秒后自动隐藏
                    floatingStatus.hideTimeout = setTimeout(() => {
                        floatingStatus.style.display = 'none';
                        floatingStatus.hideTimeout = null;
                    }, 5000);
                    return;
                }
                
                // 清除之前的定时器
                if (element.hideTimeout) {
                    clearTimeout(element.hideTimeout);
                }
                
                // 设置内容样式，如果是token-status或refresh-status元素则不添加floating类
                if (element.id === 'token-status' || element.id === 'refresh-status') {
                    element.className = 'status ' + type;
                } else {
                    element.className = 'status floating ' + type;
                }
                element.textContent = message;
                element.style.display = 'block';
                
                // 只有在非倒计时状态下才自动隐藏
                if (!message.includes('等待授权完成') && !message.includes('剩余时间')) {
                    // 5秒后自动隐藏
                    element.hideTimeout = setTimeout(() => {
                        element.style.display = 'none';
                        element.hideTimeout = null;
                    }, 5000);
                }
            }
            
            // 函数已通过事件委托处理，无需全局声明
            
             
        });
    </script>
</body>
</html>
`;

// 验证密码
function verifyPassword(request: Request): boolean {
  const url = new URL(request.url);
  const authHeader = request.headers.get("Authorization");
  
  // 检查Authorization头
  if (authHeader && authHeader === `Bearer ${API_PASSWORD}`) {
    return true;
  }
  
  // 检查URL参数中的密码
  const password = url.searchParams.get("password");
  if (password === API_PASSWORD) {
    return true;
  }
  
  return false;
}

// 获取refresh_token的前8位作为标识符
function getTokenId(refresh_token: string): string {
  return refresh_token.substring(0, 8);
}

// 处理登录请求
async function handleLogin(request: Request): Promise<Response> {
   
  try {
    const body = await request.json();
    const { password } = body;
     
     
    
    if (password === API_PASSWORD) {
       
      return new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    } else {
       
      return new Response(JSON.stringify({ error: "密码错误" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      });
    }
  } catch (error) {
    console.error("登录请求处理错误:", error); 
    return new Response(JSON.stringify({ error: "请求格式错误" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }
}

// 处理token上传
async function handleUploadToken(request: Request): Promise<Response> {
  if (!verifyPassword(request)) {
    return new Response(JSON.stringify({ error: "未授权" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }
  
  try {
    const body = await request.json();
    const { access_token, refresh_token } = body;
    
    if (!access_token || !refresh_token) {
      return new Response(JSON.stringify({ error: "缺少必要的token字段" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }
    
    // 使用refresh_token前8位作为标识符
    const tokenId = getTokenId(refresh_token);
    
    // 存储token数据，使用上传的 expires_at 或 expiry_date 如果有的话，否则默认1小时后过期
    const tokenData: TokenData = {
      access_token,
      refresh_token,
      expires_at: body.expires_at || body.expiry_date || Date.now() + 60 * 60 * 1000, // 优先使用expires_at，其次expiry_date，最后默认1小时后过期
      uploaded_at: Date.now()
    };
    
    tokenStore.set(tokenId, tokenData);
    
    // 同时保存到KV存储
    await saveTokenToKv(tokenId, tokenData);
    
    return new Response(JSON.stringify({ success: true }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: "请求格式错误" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }
}

// 处理token状态查询
async function handleTokenStatus(request: Request): Promise<Response> {
  if (!verifyPassword(request)) {
    return new Response(JSON.stringify({ error: "未授权" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  // 从 KV 存储加载最新的 token 数据
  await loadTokensFromKv();
  
  // 获取所有token的状态，并自动刷新过期的token
  const tokenList: any[] = [];
  for (const [id, token] of tokenStore.entries()) {
    const isExpired = token.expires_at ? Date.now() > token.expires_at : false;
    
    if (isExpired) {
      // 尝试刷新过期的token
      const refreshedToken = await validateAndRefreshToken(id, token);
      if (refreshedToken) {
        tokenList.push({
          id,
          expiresAt: refreshedToken.expires_at,
          isExpired: false,
          uploadedAt: refreshedToken.uploaded_at,
          wasRefreshed: true
        });
      } else {
        // 刷新失败，token仍然过期
        tokenList.push({
          id,
          expiresAt: token.expires_at,
          isExpired: true,
          uploadedAt: token.uploaded_at,
          refreshFailed: true
        });
      }
    } else {
      // Token未过期
      tokenList.push({
        id,
        expiresAt: token.expires_at,
        isExpired: false,
        uploadedAt: token.uploaded_at
      });
    }
  }
  
  return new Response(JSON.stringify({
    hasToken: tokenStore.size > 0,
    tokenCount: tokenStore.size,
    tokens: tokenList
  }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

// 强制刷新单个token（无论是否过期）
async function forceRefreshToken(id: string, token: TokenData): Promise<TokenData | null> {
  
  
  try {
    // 调用Qwen的token刷新API
    const response = await fetch("https://chat.qwen.ai/api/v1/oauth2/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: token.refresh_token,
        client_id: "f0304373b74a44d2b584a3fb70ca9e56",
      }),
    });

    if (!response.ok) {
      console.error(`Token ${id} 强制刷新失败`);
      return null;
    }

    const data = await response.json();
    
    // 创建更新后的token数据
    const updatedTokenData: TokenData = {
      access_token: data.access_token,
      refresh_token: data.refresh_token || token.refresh_token,
      expires_at: data.expires_in ? Date.now() + data.expires_in * 1000 : Date.now() + 60 * 60 * 1000,
      uploaded_at: token.uploaded_at
    };
    
    // 更新存储
    tokenStore.set(id, updatedTokenData);
    await saveTokenToKv(id, updatedTokenData);
    
    
    return updatedTokenData;
  } catch (error) {
    console.error(`Token ${id} 强制刷新时发生错误:`, error);
    return null;
  }
}

// 处理刷新单个token
async function handleRefreshSingleToken(request: Request): Promise<Response> {
  if (!verifyPassword(request)) {
    return new Response(JSON.stringify({ error: "未授权" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  try {
    const body = await request.json();
    const { tokenId } = body;
    
    if (!tokenId) {
      return new Response(JSON.stringify({ error: "缺少tokenId参数" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    // 从 KV 存储加载最新的 token 数据
    await loadTokensFromKv();
    
    const token = tokenStore.get(tokenId);
    if (!token) {
      return new Response(JSON.stringify({ error: "Token不存在" }), {
        status: 404,
        headers: { "Content-Type": "application/json" },
      });
    }
    
    // 强制刷新单个token
    const refreshedToken = await forceRefreshToken(tokenId, token);
    
    if (refreshedToken) {
      return new Response(JSON.stringify({
        success: true,
        tokenId,
        message: "Token刷新成功"
      }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    } else {
      // 刷新失败，移除token
      tokenStore.delete(tokenId);
      await deleteTokenFromKv(tokenId);
      
      return new Response(JSON.stringify({
        success: false,
        tokenId,
        error: "Token刷新失败，已删除"
      }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }
  } catch (error) {
    return new Response(JSON.stringify({ error: "请求格式错误" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }
}

// 处理删除单个token
async function handleDeleteToken(request: Request): Promise<Response> {
  if (!verifyPassword(request)) {
    return new Response(JSON.stringify({ error: "未授权" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  try {
    const body = await request.json();
    const { tokenId } = body;
    
    if (!tokenId) {
      return new Response(JSON.stringify({ error: "缺少tokenId参数" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    // 从 KV 存储加载最新的 token 数据
    await loadTokensFromKv();
    
    const token = tokenStore.get(tokenId);
    if (!token) {
      return new Response(JSON.stringify({ error: "Token不存在" }), {
        status: 404,
        headers: { "Content-Type": "application/json" },
      });
    }
    
    // 删除token
    tokenStore.delete(tokenId);
    await deleteTokenFromKv(tokenId);
    
    return new Response(JSON.stringify({
      success: true,
      tokenId,
      message: "Token删除成功"
    }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: "请求格式错误" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }
}

// 处理删除所有token
async function handleDeleteAllTokens(request: Request): Promise<Response> {
  if (!verifyPassword(request)) {
    return new Response(JSON.stringify({ error: "未授权" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  try {
    // 清空内存中的token存储
    const deletedCount = tokenStore.size;
    tokenStore.clear();
    
    // 清空KV存储中的所有token
    if (kv) {
      try {
        const entries = kv.list<string, TokenData>({ prefix: ["tokens"] });
        let deletedKvCount = 0;
        for await (const entry of entries) {
          await kv.delete(entry.key);
          deletedKvCount++;
        }
        
      } catch (error) {
        console.error("清空KV存储失败:", error);
      }
    }
    
    return new Response(JSON.stringify({
      success: true,
      deletedCount,
      message: `成功删除 ${deletedCount} 个Token`
    }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: "请求格式错误" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }
}

// 处理token刷新（强制刷新所有token）
async function handleRefreshToken(request: Request): Promise<Response> {
  if (!verifyPassword(request)) {
    return new Response(JSON.stringify({ error: "未授权" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  // 从 KV 存储加载最新的 token 数据
  await loadTokensFromKv();
  
  if (tokenStore.size === 0) {
    return new Response(JSON.stringify({ error: "没有可用的token" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }
  
  // 强制刷新所有token
  const refreshResults: any[] = [];
  const tokensToRemove: string[] = [];
  
  for (const [id, token] of tokenStore.entries()) {
    const refreshedToken = await forceRefreshToken(id, token);
    
    if (refreshedToken) {
      refreshResults.push({ id, success: true });
    } else {
      refreshResults.push({ id, success: false, error: "Token刷新失败" });
      tokensToRemove.push(id);
    }
  }
  
  // 移除刷新失败的token
  for (const id of tokensToRemove) {
    tokenStore.delete(id);
    await deleteTokenFromKv(id);
  }
  
  return new Response(JSON.stringify({
    success: true,
    refreshResults,
    remainingTokens: tokenStore.size,
    isForcedRefresh: true // 标识这是强制刷新
  }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

// 验证并刷新单个token（如果需要）
async function validateAndRefreshToken(id: string, token: TokenData): Promise<TokenData | null> {
  const isExpired = token.expires_at ? Date.now() > token.expires_at : false;
  
  if (!isExpired) {
    return token; // Token未过期，直接返回
  }
  
  
  
  try {
    // 调用Qwen的token刷新API
    const response = await fetch("https://chat.qwen.ai/api/v1/oauth2/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: token.refresh_token,
        client_id: "f0304373b74a44d2b584a3fb70ca9e56",
      }),
    });

    if (!response.ok) {
      console.error(`Token ${id} 刷新失败`);
      return null; // 刷新失败
    }

    const data = await response.json();
    
    // 创建更新后的token数据
    const updatedTokenData: TokenData = {
      access_token: data.access_token,
      refresh_token: data.refresh_token || token.refresh_token,
      expires_at: data.expires_in ? Date.now() + data.expires_in * 1000 : Date.now() + 60 * 60 * 1000,
      uploaded_at: token.uploaded_at
    };
    
    // 更新存储
    tokenStore.set(id, updatedTokenData);
    await saveTokenToKv(id, updatedTokenData);
    
    
    return updatedTokenData;
  } catch (error) {
    console.error(`Token ${id} 刷新时发生错误:`, error);
    return null; // 刷新失败
  }
}

// 获取有效的token（会自动刷新过期的token）
async function getValidToken(): Promise<{ id: string; token: TokenData } | null> {
  // 从 KV 存储加载最新的 token 数据
  await loadTokensFromKv();
  
  if (tokenStore.size === 0) {
    return null;
  }
  
  // 收集所有有效的token
  const validTokens: Array<{ id: string; token: TokenData }> = [];
  const tokenEntries = Array.from(tokenStore.entries());
  
  // 随机打乱token顺序，实现负载均衡
  for (let i = tokenEntries.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [tokenEntries[i], tokenEntries[j]] = [tokenEntries[j], tokenEntries[i]];
  }
  
  // 验证并收集有效token
  for (const [id, token] of tokenEntries) {
    const validToken = await validateAndRefreshToken(id, token);
    if (validToken) {
      validTokens.push({ id, token: validToken });
    }
  }
  
  // 如果有有效token，随机返回一个
  if (validTokens.length > 0) {
    const randomIndex = Math.floor(Math.random() * validTokens.length);
    return validTokens[randomIndex];
  }
  
  return null; // 所有token都无效
}

// 处理聊天API请求
async function handleChat(request: Request): Promise<Response> {
  // 验证密码
  if (!verifyPassword(request)) {
    return new Response(JSON.stringify({ error: "未授权" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  try {
    const body = await request.json();
    // 从请求体中解构出 stream 参数，默认为 false
    const { messages, model = "qwen3-coder-plus", stream = false } = body;

    // 验证messages数组格式
    if (!messages || !Array.isArray(messages) || messages.length === 0) {
      return new Response(JSON.stringify({ error: "缺少消息内容" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    // 获取有效token（会自动刷新过期token）
    const validTokenResult = await getValidToken();
    if (!validTokenResult) {
      return new Response(JSON.stringify({ error: "没有可用的token" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    const { id: tokenId, token: currentToken } = validTokenResult;
    

    // 构造请求体，动态设置 stream 参数
    const requestBody = {
      model,
      messages,
      temperature: 0,
      top_p: 1,
      stream, // 将客户端的stream设置透传给Qwen API
    };

    // 调用Qwen的聊天API
    const response = await fetch("https://portal.qwen.ai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${currentToken.access_token}`,
        "Content-Type": "application/json",
        "Accept": stream ? "text/event-stream" : "application/json", // 根据stream设置Accept头
      },
      body: JSON.stringify(requestBody),
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error(`使用Token ${tokenId} 调用API失败:`, errorText);
      return new Response(JSON.stringify({ error: `API调用失败: ${response.status} ${errorText}` }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }

    // 如果是流式请求，创建一个更健壮的管道来转发数据
    if (stream) {
      
      
      // 创建一个转换流，它可以更好地处理背压和连接生命周期
      const { readable, writable } = new TransformStream();
      
      // 将Qwen API的响应体（readable stream）通过管道连接到我们转换流的写入端
      // 这会持续地将数据从源头泵到我们的管道中
      response.body?.pipeTo(writable);
      
      // 创建新的响应头，并尽可能地复制原始响应头
      const headers = new Headers();
      for (const [key, value] of response.headers.entries()) {
        // 复制所有对客户端有用的头部信息
        if (key.toLowerCase() === 'content-type' || key.toLowerCase() === 'cache-control' || key.toLowerCase().startsWith('x-')) {
          headers.set(key, value);
        }
      }
      // 确保关键的流式响应头存在
      headers.set("Content-Type", "text/event-stream; charset=utf-8");
      headers.set("Cache-Control", "no-cache");
      headers.set("Connection", "keep-alive");

      // 将我们转换流的读取端作为新的响应体返回给客户端
      // 这样客户端就能接收到通过我们管道转发的数据了
      return new Response(readable, { status: 200, headers });
    }

    // 如果是非流式请求，返回完整的JSON响应
    
    const responseText = await response.text();
    const headers = new Headers({
      "Content-Type": "application/json; charset=utf-8",
    });
    // 复制原始响应的其他相关头部
    for (const [key, value] of response.headers.entries()) {
      if (key.toLowerCase().startsWith('x-') || key.toLowerCase() === 'ratelimit-limit' || key.toLowerCase() === 'ratelimit-remaining' || key.toLowerCase() === 'ratelimit-reset') {
        headers.set(key, value);
      }
    }
    return new Response(responseText, { status: 200, headers });

  } catch (error) {
    console.error("处理聊天请求时发生意外错误:", error);
    return new Response(JSON.stringify({ error: `服务器内部错误: ${error.message}` }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
}

// 处理模型列表请求
async function handleModels(request: Request): Promise<Response> {
  if (!verifyPassword(request)) {
    return new Response(JSON.stringify({ error: "未授权" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }
  
  // 返回支持的模型列表
  const models = {
    "object": "list",
    "data": [
      {
        "id": "qwen3-coder-plus",
        "object": "model",
        "created": Math.floor(Date.now() / 1000),
        "owned_by": "qwen"
      }
    ]
  };
  
  return new Response(JSON.stringify(models), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

// 处理OAuth设备授权初始化
async function handleOAuthInit(request: Request): Promise<Response> {
  if (!verifyPassword(request)) {
    return new Response(JSON.stringify({ error: "未授权" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  await acquireLock();
  try {
    // 生成PKCE对
    const pkcePair = await generatePKCEPair();
    
    // 请求设备授权
    const authState = await requestDeviceAuthorization(pkcePair.codeChallenge);
    authState.codeVerifier = pkcePair.codeVerifier;
    
    // 添加时间戳
    const now = Date.now();
    authState.createdAt = now;
    authState.lastUsedAt = now;
    
    // 生成状态ID并存储
    const stateId = generateStateId();
    oauthStates.set(stateId, authState);
    await saveOAuthStateToKv(stateId, authState);
    
    return new Response(JSON.stringify({
      success: true,
      stateId,
      userCode: authState.userCode,
      verificationUri: authState.verificationUri,
      verificationUriComplete: authState.verificationUriComplete,
      expiresAt: authState.expiresAt,
      expiresIn: Math.floor((authState.expiresAt - Date.now()) / 1000) // 返回剩余秒数
    }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch (error) {
    console.error('OAuth initialization failed:', error);
    return new Response(JSON.stringify({ 
      error: `OAuth初始化失败: ${error.message}` 
    }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  } finally {
    releaseLock();
  }
}

// 处理OAuth轮询状态
async function handleOAuthPoll(request: Request): Promise<Response> {
  if (!verifyPassword(request)) {
    return new Response(JSON.stringify({ error: "未授权" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  await acquireLock();
  try {
    const body = await request.json();
    const { stateId } = body;
    
    if (!stateId) {
      return new Response(JSON.stringify({ error: "缺少stateId参数" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    // 获取OAuth状态 - 先从内存找，再从KV找
    let state = oauthStates.get(stateId);
    if (!state) {
      state = await loadOAuthStateFromKv(stateId);
      if (state) {
        oauthStates.set(stateId, state);
      }
    }
    
    // 更新使用时间
    if (state) {
      await updateOAuthStateUsage(stateId);
    }
    
    if (!state) {
      return new Response(JSON.stringify({ error: "无效的stateId" }), {
        status: 404,
        headers: { "Content-Type": "application/json" },
      });
    }

    // 检查是否过期 - 使用更宽松的检查
    const now = Date.now();
    if (state.expiresAt && now > state.expiresAt + 60000) { // 60秒缓冲时间
      await safeDeleteOAuthState(stateId);
      return new Response(JSON.stringify({ 
        success: false, 
        error: "设备授权码已过期" 
      }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    // 如果接近过期，提醒用户
    if (state.expiresAt && now > state.expiresAt - 60000) { // 剩余1分钟时提醒
      return new Response(JSON.stringify({
        success: false,
        status: 'pending',
        warning: "设备授权码即将过期，请尽快完成授权"
      }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }

    // 尝试获取token - 只调用一次pollDeviceToken
    try {
      const tokenResponse = await pollDeviceToken(state.deviceCode, state.codeVerifier);
      
      // 检查是否成功获取令牌
      if (tokenResponse.access_token) {
        // 转换为 TokenData 格式
        const tokenData: TokenData = {
          access_token: tokenResponse.access_token,
          refresh_token: tokenResponse.refresh_token,
          expires_at: Date.now() + (tokenResponse.expires_in || 3600) * 1000,
          uploaded_at: Date.now()
        };
        
        // 存储token
        const tokenId = getTokenId(tokenData.refresh_token);
        tokenStore.set(tokenId, tokenData);
        await saveTokenToKv(tokenId, tokenData);
        
        // 清理OAuth状态
        await safeDeleteOAuthState(stateId);
        
        return new Response(JSON.stringify({
          success: true,
          tokenId,
          message: "认证成功"
        }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      
      // 检查是否为待处理状态
      if (tokenResponse.status === 'pending') {
        // 如果是slow_down状态，增加轮询间隔
        if (tokenResponse.slowDown) {
          state.pollInterval = Math.min((state.pollInterval || 2) * 1.5, 10);
        }
        
        return new Response(JSON.stringify({
          success: false,
          status: 'pending',
          remainingTime: state.expiresAt ? Math.max(0, Math.floor((state.expiresAt - now) / 1000)) : 0
        }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      
      // 其他错误情况
      await safeDeleteOAuthState(stateId);
      return new Response(JSON.stringify({
        success: false,
        error: "授权失败或被拒绝"
      }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
      
    } catch (error) {
      console.error('OAuth poll error:', error);
      
      // 检查是否是超时或设备码过期错误
      if (error.message.includes('timed out') || error.message.includes('expired') || error.message.includes('invalid') || error.message.includes('401')) {
        await safeDeleteOAuthState(stateId);
        return new Response(JSON.stringify({
          success: false,
          error: error.message
        }), {
          status: 400,
          headers: { "Content-Type": "application/json" },
        });
      }
      
      // 其他错误继续轮询
      return new Response(JSON.stringify({
        success: false,
        status: 'pending'
      }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
  } catch (error) {
    console.error('OAuth poll failed:', error);
    return new Response(JSON.stringify({ 
      error: `OAuth轮询失败: ${error.message}` 
    }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  } finally {
    releaseLock();
  }
}

// 取消OAuth认证
async function handleOAuthCancel(request: Request): Promise<Response> {
  if (!verifyPassword(request)) {
    return new Response(JSON.stringify({ error: "未授权" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  await acquireLock();
  try {
    const body = await request.json();
    const { stateId } = body;
    
    if (stateId) {
      await safeDeleteOAuthState(stateId);
    }
    
    return new Response(JSON.stringify({
      success: true,
      message: "OAuth认证已取消"
    }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch (error) {
    return new Response(JSON.stringify({ 
      error: "请求格式错误" 
    }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  } finally {
    releaseLock();
  }
}

// 添加CORS头到响应
function addCorsHeaders(response: Response): Response {
  const headers = new Headers(response.headers);
  headers.set("Access-Control-Allow-Origin", "*");
  headers.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
  
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

// 处理OPTIONS请求（CORS预检请求）
function handleOptionsRequest(): Response {
  return new Response(null, {
    status: 200,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    },
  });
}

// 请求路由处理
async function handleRequest(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;
  
   
  
  // 处理OPTIONS请求（CORS预检请求）
  if (method === "OPTIONS") {
     
    return handleOptionsRequest();
  }
  
  // 处理API路由
  if (path.startsWith("/api/")) {
     
    let response;
    switch (path) {
      case "/api/login":
         
        response = await handleLogin(request);
        break;
      case "/api/upload-token":
        response = await handleUploadToken(request);
        break;
      case "/api/token-status":
        response = await handleTokenStatus(request);
        break;
      case "/api/refresh-token":
        response = await handleRefreshToken(request);
        break;
      case "/api/refresh-single-token":
        response = await handleRefreshSingleToken(request);
        break;
      case "/api/delete-token":
        response = await handleDeleteToken(request);
        break;
      case "/api/delete-all-tokens":
        response = await handleDeleteAllTokens(request);
        break;
      case "/api/chat":
        response = await handleChat(request);
        break;
      case "/api/oauth-init":
        response = await handleOAuthInit(request);
        break;
      case "/api/oauth-poll":
        response = await handleOAuthPoll(request);
        break;
      case "/api/oauth-cancel":
        response = await handleOAuthCancel(request);
        break;
      default:
         
        response = new Response(JSON.stringify({ error: "API端点不存在" }), {
          status: 404,
          headers: { "Content-Type": "application/json" },
        });
    }
    return addCorsHeaders(response);
  }
  
  // 处理OpenAI兼容的API路由
  if (path.startsWith("/v1/")) {
    let response;
    switch (path) {
      case "/v1/chat/completions":
        response = await handleChat(request);
        break;
      case "/v1/models":
        response = await handleModels(request);
        break;
      default:
        response = new Response(JSON.stringify({ error: "API端点不存在" }), {
          status: 404,
          headers: { "Content-Type": "application/json" },
        });
    }
    return addCorsHeaders(response);
  }
  
  // 处理根路径，返回HTML页面
  if (path === "/") {
     
    const response = new Response(HTML_TEMPLATE, {
      status: 200,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
    return addCorsHeaders(response);
  }
  
  // 其他路径返回404
   
  const response = new Response("页面不存在", {
    status: 404,
    headers: { "Content-Type": "text/plain; charset=utf-8" },
  });
  return addCorsHeaders(response);
}

// 启动服务器

// 启动定期清理机制
startPeriodicCleanup();

// 启动HTTP服务器
serve(handleRequest, { port: PORT });

// 优雅退出处理
process.on('SIGINT', () => {
  console.log('收到SIGINT信号，正在优雅退出...');
  stopPeriodicCleanup();
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('收到SIGTERM信号，正在优雅退出...');
  stopPeriodicCleanup();
  process.exit(0);
});