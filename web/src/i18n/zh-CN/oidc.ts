/**
 * Copyright 2026 Sven Victor
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

export default {
  authorize: {
    title: "应用授权",
    description: "应用请求访问您的以下信息：",
    new: "新",
    approve: "授权",
    cancel: "取消",
    missingClientId: "缺少客户端ID",
    missingRedirectUri: "缺少重定向URI",
    missingResponseType: "缺少响应类型",
    missingState: "缺少状态参数",
    invalidResponseType: "无效的响应类型",
    missingParams: "缺少必要参数",
    failed: "授权失败",
    error: "授权错误: {{error}}"
  },
  test: {
    clientSecret: "客户端密钥",
    clientID: "客户端ID",
    redirectURI: "重定向URI",
    responseType: "响应类型",
    scope: "权限范围",
    state: "状态",
    nonce: "Nonce",
    failedVerifyIdToken: "验证ID Token失败",
    codeVerifier: "Code Verifier",
    codeChallenge: "Code Challenge",
    codeChallengeMethod: "Code Challenge Method",
    code: "授权码",
    token: "令牌",
    status: "状态",
    auth: "认证",
    userInfo: "用户信息",
    idToken: "ID Token",
    accessToken: "Access Token",
    title: "OIDC 测试页面",
    oidcConfig: {
      invalidURL: "无效的URL",
      authorizationEndpointRequired: "授权端点是必填的",
      tokenEndpointRequired: "令牌端点是必填的",
      userinfoEndpointRequired: "用户信息端点是必填的",
      title: "OIDC 配置信息",
      authorizationEndpoint: "授权端点",
      tokenEndpoint: "令牌端点",
      userinfoEndpoint: "用户信息端点",
      jwksEndpoint: "JWKS 端点",
      scope: "权限范围",
      issuer: "颁发者",
      scopeRequired: "权限范围是必填的",
    },
    oidcStatus: {
      code: {
        title: "获取授权码"
      },
      token: {
        idToken: "ID Token",
        accessToken: "Access Token",
        title: "获取Token"
      },
      userInfo: {
        title: "获取用户信息"
      },
      refreshToken: {
        title: "刷新令牌"
      },
      idToken: {
        title: "获取/校验ID Token"
      },
    },
  },
  callback: {
    processing: "正在处理认证...",
    success: "认证成功",
    failed: "认证失败",
    noCode: "未收到授权码",
    closeNow: "立即关闭",
    closeIn: "{{timerInterval}}秒后关闭页面",
    close: "立即关闭"
  }
};
