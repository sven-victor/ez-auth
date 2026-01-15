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

import React, { useEffect, useState } from 'react';
import { Button, Card, Descriptions, Form, Input, List, message, Select, Space, Switch, Tabs, Tag, Typography } from 'antd';
import { Link, useSearchParams } from 'react-router-dom';
import { getOIDCConfig, exchangeToken, getUserInfo, getJWKS } from '@/api/oidc';
import { useRequest } from 'ahooks';
import { useTranslation } from 'ez-console';
import _, { has, isString } from 'lodash';
import { CheckCircleTwoTone, CloseCircleTwoTone, ExclamationCircleOutlined, LoadingOutlined } from '@ant-design/icons';

import { createLocalJWKSet, jwtVerify } from 'jose'

const randomString = (length: number) => {
  const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
  let result = '';
  for (let i = 0; i < length; i++) {
    result += charset[_.random(0, charset.length - 1)];
  }
  return result;
}
const isWebCryptoSupported = () => {
  return window.crypto && window.crypto.subtle;
};


// Parse JWT token
const parseJWT = (token: string) => {
  try {
    const [_, payload, __] = token.split('.');
    const binaryPayload = Uint8Array.from(atob(payload.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    return new TextDecoder().decode(binaryPayload);
  } catch (error) {
    console.error(error)
    return null;
  }
}

const parseJWTPayload = (token: string): Record<string, any> => {
  try {
    return JSON.parse(parseJWT(token) ?? "{}");
  } catch (error) {
    console.error(error)
    return {};
  }
}


const OIDCConfig: React.FC<{
  setOidcConfig: (oidcConfig: API.OIDCConfig | undefined) => void;
  setJWKS: (jwks: ReturnType<typeof createLocalJWKSet>) => void;
}> = ({ setOidcConfig, setJWKS }) => {
  const [searchParams] = useSearchParams();
  const client_id = searchParams.get('client_id') ?? undefined;
  const { t } = useTranslation("oidc", { keyPrefix: "test" });
  const [oidcConfigURL, setOidcConfigURL] = useState<any>();
  // Get OIDC configuration information
  const { run: fetchOIDCConfig, data: oidcConfig, loading, error: oidcConfigError } = useRequest(async (url: string): Promise<API.OIDCConfig | undefined> => {
    if (!url && !client_id) {
      return undefined
    }
    const res = await getOIDCConfig({
      wellknow_endpoint: url,
      client_id: client_id,
    });
    if (has(res, 'jwks_uri') && isString(res.jwks_uri)) {
      try {
        const jwks = await getJWKS({
          jwks_endpoint: res.jwks_uri as string,
          client_id: client_id,
        });
        if (jwks?.keys && Array.isArray(jwks?.keys) && jwks.keys.length > 0) {
          const jwksSet = createLocalJWKSet(jwks as any);
          setJWKS(jwksSet);
        }
      } catch (error) {
        throw new Error(t('failedFetchJWKS', {
          error: error,
          defaultValue: "Failed to fetch JWKS: {{error}}",
        }));
      }
    }
    if (has(res, 'userinfo_endpoint')) {
      return res as any as API.OIDCConfig;
    }
    throw new Error(`${t('failedFetchOIDCConfig', {
      defaultValue: "Failed to fetch OIDC config",
    })}: ${JSON.stringify(res)}`);
  }, {
    manual: true,
    onSuccess: (data) => {
      setOidcConfig(data);
    },
    onError: (error) => {
      message.error(t('failedFetchOIDCConfig', {
        error: error,
        defaultValue: "Failed to fetch OIDC config",
      }));
    },
  });
  useEffect(() => {
    fetchOIDCConfig(oidcConfigURL);
  }, [oidcConfigURL]);

  useEffect(() => {
    if (oidcConfig?.jwks_uri) {

    }
  }, [oidcConfig?.jwks_uri])

  return (
    <Space direction="vertical" style={{ width: '100%' }}>
      <Space direction="vertical" style={{ width: '100%', display: client_id ? 'none' : 'block' }}>
        <Typography.Text>{t("oidcConfigURL", { defaultValue: "OIDC Config URL" })}</Typography.Text>
        <Input style={{ width: '100%' }} placeholder="client_id" onChange={(e) => setOidcConfigURL(e.target.value)} defaultValue={oidcConfigURL} />
      </Space>
      <Card variant='borderless' loading={loading}>
        {oidcConfigError ? (
          <>
            <CloseCircleTwoTone twoToneColor="#f5222d" />
            <Typography.Text style={{ marginLeft: '8px' }}>{oidcConfigError?.message}</Typography.Text>
          </>
        ) : (
          oidcConfig ? (
            <Descriptions title={t("oidcConfig.title", { defaultValue: "OIDC Config" })} bordered>
              <Descriptions.Item label={t("oidcConfig.issuer", { defaultValue: "Issuer" })} styles={{ label: { textAlign: 'right' } }} span={3}>
                {oidcConfig.issuer}
              </Descriptions.Item>
              <Descriptions.Item label={t("oidcConfig.authorizationEndpoint", { defaultValue: "Authorization Endpoint" })} styles={{ label: { textAlign: 'right' } }} span={3}>
                {oidcConfig.authorization_endpoint}
              </Descriptions.Item>
              <Descriptions.Item label={t("oidcConfig.tokenEndpoint", { defaultValue: "Token Endpoint" })} styles={{ label: { textAlign: 'right' } }} span={3}>
                {oidcConfig.token_endpoint}
              </Descriptions.Item>
              <Descriptions.Item label={t("oidcConfig.userinfoEndpoint", { defaultValue: "Userinfo Endpoint" })} styles={{ label: { textAlign: 'right' } }} span={3}>
                {oidcConfig.userinfo_endpoint}
              </Descriptions.Item>
              {oidcConfig.jwks_uri ? <Descriptions.Item label={t("oidcConfig.jwksEndpoint", { defaultValue: "JWKS Endpoint" })} styles={{ label: { textAlign: 'right' } }} span={3}>
                <Link to={oidcConfig.jwks_uri} target='_blank'>{oidcConfig.jwks_uri}</Link>
              </Descriptions.Item> : null}
              <Descriptions.Item label="Scope" styles={{ label: { textAlign: 'right' } }} span={3}>
                {oidcConfig.scopes_supported?.map((scope: string) => <Tag key={scope}>{scope}</Tag>)}
              </Descriptions.Item>
            </Descriptions>
          ) : (
            <Form labelCol={{ span: 4 }} onValuesChange={(_, allValues) => {
              setOidcConfig(allValues);
            }}>
              <Form.Item label={t("oidcConfig.authorizationEndpoint", { defaultValue: "Authorization Endpoint" })} name="authorization_endpoint" rules={[
                { required: true, message: t("oidcConfig.authorizationEndpointRequired", { defaultValue: "Required" }) },
                { type: 'url', message: t("oidcConfig.invalidURL", { defaultValue: "Invalid URL" }) },
              ]}>
                <Input />
              </Form.Item>
              <Form.Item label={t("oidcConfig.tokenEndpoint", { defaultValue: "Token Endpoint" })} name="token_endpoint" rules={[
                { required: true, message: t("oidcConfig.tokenEndpointRequired", { defaultValue: "Required" }) },
                { type: 'url', message: t("oidcConfig.invalidURL", { defaultValue: "Invalid URL" }) },
              ]}>
                <Input />
              </Form.Item>
              <Form.Item label={t("oidcConfig.userinfoEndpoint", { defaultValue: "Userinfo Endpoint" })} name="userinfo_endpoint" rules={[
                { required: true, message: t("oidcConfig.userinfoEndpointRequired", { defaultValue: "Required" }) },
                { type: 'url', message: t("oidcConfig.invalidURL", { defaultValue: "Invalid URL" }) },
              ]}>
                <Input />
              </Form.Item>
              <Form.Item label={t("oidcConfig.scope", { defaultValue: "Scope" })} name="scopes_supported" rules={[
                { required: true, message: t("oidcConfig.scopeRequired", { defaultValue: "Required" }) },
              ]}>
                <Select mode="tags" defaultValue={['openid', 'profile', 'email']} />
              </Form.Item>
            </Form>
          )
        )}
      </Card>
    </Space>
  )
}
interface OIDCStatusItem {
  status?: string;
  title: string;
  description?: React.ReactNode;
}
interface OIDCStatus {
  code: OIDCStatusItem;
  userInfo: OIDCStatusItem;
  token: OIDCStatusItem;
  refreshToken: OIDCStatusItem;
  idToken: OIDCStatusItem;
}

const OIDCTestPage: React.FC = () => {
  const { t } = useTranslation("oidc", { keyPrefix: "test" });
  const [searchParams] = useSearchParams();
  const client_id = searchParams.get('client_id') ?? undefined;

  const [form] = Form.useForm();

  const [jwks, setJWKS] = useState<ReturnType<typeof createLocalJWKSet> | null>(null);
  const [state, setState] = useState<string>();
  const [code, setCode] = useState<string>();
  const [nonce, setNonce] = useState<string>();
  const [codeVerifier, setCodeVerifier] = useState<string>();
  const [codeChallengeMethod, setCodeChallengeMethod] = useState<'S256' | 'plain' | 'none'>('S256');
  const [status, setStatus] = useState<OIDCStatus>({
    code: {
      title: t("oidcStatus.code.title", { defaultValue: "Get Code" }),
    },
    token: {
      title: t("oidcStatus.token.title", { defaultValue: "Get Token" }),
    },
    refreshToken: {
      title: t("oidcStatus.refreshToken.title", { defaultValue: "Refresh Token" }),
    },
    idToken: {
      title: t("oidcStatus.idToken.title", { defaultValue: "ID Token" }),
    },
    userInfo: {
      title: t("oidcStatus.userInfo.title", { defaultValue: "Get User Info" }),
    },
  });

  const setOIDCStatus = (name: keyof OIDCStatus, status: string, description?: React.ReactNode) => {
    setStatus(prev => ({
      ...prev,
      [name]: {
        ...prev[name],
        status,
        description,
      },
    }))
  }

  const [oidcConfig, setOidcConfig] = useState<API.OIDCConfig | undefined>();
  useEffect(() => {
    const index = randomString(16);
    const codeVerifier = randomString(16);
    const nonce = randomString(16);
    setCodeVerifier(codeVerifier)
    setNonce(nonce)
    form.setFieldsValue({
      nonce,
      code_verifier: codeVerifier,
    })

    const watchCode = (e: StorageEvent) => {

      if (e.key === `oidc_code_${index}`) {
        setCode(e.newValue ?? undefined)
        form.setFieldsValue({
          code: e.newValue,
        })
        setOIDCStatus('code', 'success')
      }
    }
    const state = randomString(16);
    setState(state)
    form.setFieldsValue({
      state,
      redirect_uri: `${window.location.origin}${window.location.pathname.replace(/\/oidc\/test$/, '/oidc/callback')}/${index}`,
    });
    window.addEventListener('storage', watchCode)
    return () => {
      window.removeEventListener('storage', watchCode)
    }
  }, []);

  useEffect(() => {
    if (client_id) {
      form.setFieldsValue({
        client_id,
      })
    }
  }, [client_id])
  const generateCodeChallenge = async (verifier?: string, method: 'S256' | 'plain' | 'none' = 'S256'): Promise<string | undefined> => {
    if (!verifier) {
      return undefined
    }
    switch (method) {
      case 'S256':
        break;
      case 'plain':
        return verifier
      case 'none':
        return undefined
      default:
        throw new Error(t('invalidCodeChallengeMethod', {
          defaultValue: 'Invalid code challenge method',
        }))
    }

    if (!isWebCryptoSupported()) {
      message.error(t('browserDoesNotSupportWebCryptoAPI', {
        defaultValue: 'The browser or site does not support Web Crypto API',
      }))
      return undefined
    }

    try {
      // Convert verifier to Uint8Array
      const encoder = new TextEncoder();
      const data = encoder.encode(verifier);

      // Use SHA-256 for hashing
      const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);

      // Convert hash result to base64url format
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const base64String = btoa(String.fromCharCode.apply(null, hashArray));
      return base64String
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
    } catch (error) {
      console.error('failed to generate code challenge:', error);
      throw error;
    }
  };
  const handleLogin = async (formValues: any) => {
    setOIDCStatus('code', '')
    setOIDCStatus('token', '')
    setOIDCStatus('refreshToken', '')
    setOIDCStatus('idToken', '')
    setOIDCStatus('userInfo', '')
    if (!oidcConfig?.authorization_endpoint) {
      message.error(t('pleaseConfigureAuthorizationEndpoint', {
        defaultValue: 'Please configure the authorization endpoint',
      }))
      return;
    }
    if (!oidcConfig?.token_endpoint) {
      message.error(t('pleaseConfigureTokenEndpoint', {
        defaultValue: 'Please configure the token endpoint',
      }))
      return
    }
    if (!oidcConfig?.userinfo_endpoint) {
      message.error(t('pleaseConfigureUserinfoEndpoint', {
        defaultValue: 'Please configure the userinfo endpoint',
      }))
      return
    }
    // if (!oidcConfig?.scopes_supported) {
    //   message.error(t('pleaseConfigureScope', {
    //     defaultValue: 'Please configure the scope',
    //   }))
    //   return
    // }
    if (!formValues.client_id) {
      message.error(t('pleaseConfigureClientID', {
        defaultValue: 'Please configure the client ID',
      }))
      return
    }
    setOIDCStatus('code', 'loading')
    const codeChallenge = await generateCodeChallenge(codeVerifier, codeChallengeMethod)
    const codeChallengeQuery = codeChallenge ? `&code_challenge=${codeChallenge}&code_challenge_method=${codeChallengeMethod}` : ''
    const nonceQuery = nonce ? `&nonce=${nonce}` : ''
    // Open a child window
    const subWindow = window.open('', '_blank', 'width=600,height=400');
    if (subWindow) {
      subWindow.location.href = `${oidcConfig?.authorization_endpoint}?` +
        `client_id=${formValues.client_id}&` +
        `redirect_uri=${encodeURIComponent(formValues.redirect_uri)}&` +
        `response_type=code&` +
        `scope=${encodeURIComponent(oidcConfig?.scopes_supported?.join(' ') ?? '')}&` +
        `state=${formValues.state}&` +
        codeChallengeQuery +
        nonceQuery;
      const checkInterval = setInterval(() => {
        if (subWindow?.closed) {
          setCode((code) => {
            if (!code) {
              setOIDCStatus('code', 'error', <Typography.Text>
                {t('failedGetCode', {
                  defaultValue: 'Failed to get code',
                })}
              </Typography.Text>)
            }
            return code
          })
          clearInterval(checkInterval);
        }
      }, 500); // Check every 500 milliseconds
      setTimeout(() => {
        setCode((code) => {
          if (!code) {
            setOIDCStatus('code', 'error', <Typography.Text>
              {t('failedGetCode', {
                defaultValue: 'Failed to get code',
              })}
            </Typography.Text>)
          }
          return code
        })
        clearInterval(checkInterval);
      }, 10000)
    }
  };
  const { run: fetchToken, loading: fetchTokenLoading, data: { access_token, refresh_token, id_token } = {} } = useRequest(async (params: API.ExchangeTokenParams) => {
    const ret = await exchangeToken(params);
    if (!ret.access_token) {
      throw new Error(`${t('failedFetchToken', {
        defaultValue: 'Failed to fetch token',
      })}: ${JSON.stringify(ret)}`)
    }
    return ret
  }, {
    onBefore: () => {
      setOIDCStatus('token', 'loading')
    },
    onError: (error) => {
      setOIDCStatus('token', 'error', <Typography.Text>
        {error.message}
      </Typography.Text>)
    },
    onSuccess: ({ id_token, access_token, refresh_token }) => {
      const children = []
      if (id_token) {
        setOIDCStatus('idToken', 'success')
        if (jwks) {
          jwtVerify(id_token, jwks, {
            algorithms: ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'], // Allowed algorithms
            issuer: oidcConfig?.issuer,
          }).then((verifyResult) => {
            if (nonce && verifyResult.payload.nonce !== nonce) {
              throw new Error('nonce mismatch')
            }
          }).catch((error) => {
            console.log(error)
            setOIDCStatus('idToken', 'error', <Typography.Text>
              {t('failedVerifyIdToken', {
                defaultValue: 'Failed to verify id token with jwks',
              })}: {`${error}`}
            </Typography.Text>)
          })
        } else {
          const { nonce: idTokenNonce } = parseJWTPayload(id_token)
          if (nonce && idTokenNonce !== nonce) {
            setOIDCStatus('idToken', 'error', <Typography.Text>
              {t('nonceMismatch', {
                defaultValue: 'Nonce mismatch',
              })}
            </Typography.Text>)
          }
        }
        children.push(<Tag>ID Token</Tag>)
      }
      if (access_token) {
        children.push(<Tag>Access Token</Tag>)
        if (jwks) {
          jwtVerify(access_token, jwks, {
            algorithms: ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'], // Allowed algorithms
            issuer: oidcConfig?.issuer,
          }).catch((error) => {
            console.log(error)
            setOIDCStatus('token', 'error', <Typography.Text>
              {t('failedVerifyAccessToken', {
                defaultValue: 'Failed to verify access token with jwks',
              })}: {`${error}`}
            </Typography.Text>)
          })
        }
      }
      if (refresh_token) {
        children.push(<Tag>Refresh Token</Tag>)
        if (jwks) {
          jwtVerify(refresh_token, jwks, {
            algorithms: ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'], // Allowed algorithms
            issuer: oidcConfig?.issuer,
          }).catch((error) => {
            console.log(error)
            setOIDCStatus('refreshToken', 'error', <Typography.Text>
              {t('failedVerifyRefreshToken', {
                defaultValue: 'Failed to verify refresh token with jwks',
              })}: {`${error}`}
            </Typography.Text>)
          })
        }
      }
      setOIDCStatus('token', 'success', <Space direction="horizontal">
        {children.map(child => child)}
      </Space>)
    },
    manual: true,
  });
  useEffect(() => {
    const { token_endpoint } = oidcConfig ?? {}
    // If code exists, get token
    if (code && token_endpoint) {
      fetchToken({
        client_id: form.getFieldValue('client_id'),
        client_secret: form.getFieldValue('client_secret'),
        code,
        token_endpoint,
        state: form.getFieldValue('state'),
        code_verifier: codeVerifier,
      })
    }
  }, [code])

  const { run: fetchUserInfo, loading: fetchUserInfoLoading, data: userInfo } = useRequest(async (
    userinfo_endpoint: string,
    access_token: string,
  ) => {
    return await getUserInfo({
      userinfo_endpoint,
      access_token,
    });
  }, {
    onBefore: () => {
      setOIDCStatus('userInfo', 'loading')
    },
    onError: (error) => {
      setOIDCStatus('userInfo', 'error', <Typography.Text>
        {error.message}
      </Typography.Text>)
    },
    onSuccess: ({ }) => {
      setOIDCStatus('userInfo', 'success')
    },
    manual: true,
  });

  useEffect(() => {
    if (codeChallengeMethod === 'S256') {
      if (!isWebCryptoSupported()) {
        message.error('The browser or site does not support Web Crypto API')
        form.setFieldsValue({
          code_challenge_method: 'plain',
        })
        setCodeChallengeMethod('plain')
      }
    } else if (codeChallengeMethod === 'none') {
      form.setFieldsValue({
        code_verifier: undefined,
      })
      setCodeVerifier(undefined)
    }
  }, [codeChallengeMethod])

  useEffect(() => {
    if (access_token && oidcConfig?.userinfo_endpoint) {
      fetchUserInfo(oidcConfig.userinfo_endpoint, access_token)
    }
  }, [access_token, oidcConfig?.userinfo_endpoint])
  const { run: refreshToken, loading: refreshTokenLoading } = useRequest(async (params: API.ExchangeTokenParams) => {
    const { access_token } = await exchangeToken(params);
    if (!access_token) {
      throw new Error(t('failedFetchToken', {
        defaultValue: 'Failed to fetch token',
      }))
    }
    if (oidcConfig?.userinfo_endpoint) {
      const userInfo = await getUserInfo({ userinfo_endpoint: oidcConfig.userinfo_endpoint, access_token })
      if (!userInfo) {
        throw new Error(t('failedGetUserInfo', {
          defaultValue: 'Failed to get user info',
        }))
      }
      return userInfo
    }
  }, {
    onBefore: () => {
      setOIDCStatus('refreshToken', 'loading')
    },
    onError: (error) => {
      setOIDCStatus('refreshToken', 'error', <Typography.Text>
        {error.message}
      </Typography.Text>)
    },
    onSuccess: ({ }) => {
      setOIDCStatus('refreshToken', 'success')
    },
    manual: true,
  });

  useEffect(() => {
    if (refresh_token && oidcConfig?.token_endpoint) {
      refreshToken({
        client_id: form.getFieldValue('client_id'),
        client_secret: form.getFieldValue('client_secret'),
        refresh_token,
        token_endpoint: oidcConfig.token_endpoint,
      })
    }
  }, [refresh_token, oidcConfig?.token_endpoint])

  const getStatusAvatar = (status: string) => {
    switch (status) {
      case 'success':
        return <CheckCircleTwoTone twoToneColor="#52c41a" />
      case 'error':
        return <CloseCircleTwoTone twoToneColor="#f5222d" />
      case 'loading':
        return <LoadingOutlined />
      default:
        return <ExclamationCircleOutlined />
    }
  }

  return (
    <div style={{ padding: '24px' }}>
      <Space direction="vertical" size="large" style={{ width: '100%' }}>
        <OIDCConfig setOidcConfig={setOidcConfig} setJWKS={(jwks) => {
          setJWKS(() => {
            return jwks
          })
        }} />
        <Card variant='borderless'>
          <Form labelCol={{ span: 4 }} form={form} onFinish={handleLogin}>
            {oidcConfig ? <>


            </> : null}
            <Form.Item label={t("clientID", { defaultValue: "Client ID" })} name="client_id">
              <Input />
            </Form.Item>
            <Form.Item label={t("clientSecret", { defaultValue: "Client Secret" })} name="client_secret">
              <Input />
            </Form.Item>
            <Form.Item label={t("state", { defaultValue: "State" })} name="state">
              <Input disabled value={state} />
            </Form.Item>
            <Form.Item label={t("redirectURI", { defaultValue: "Redirect URI" })} name="redirect_uri">
              <Input disabled />
            </Form.Item>
            <Form.Item label={t("code", { defaultValue: "Code" })} name="code">
              <Input disabled value={code} />
            </Form.Item>
            <Form.Item label={t("nonce", { defaultValue: "Nonce" })} name="nonce">
              <Input addonBefore={<Switch defaultChecked={true} onChange={(checked) => {
                if (checked) {
                  setNonce(randomString(16))
                  form.setFieldsValue({
                    nonce: randomString(16),
                  })
                } else {
                  setNonce(undefined)
                  form.setFieldsValue({
                    nonce: undefined,
                  })
                }
              }} />} disabled />
            </Form.Item>
            <Form.Item label={t("codeVerifier", { defaultValue: "Code Verifier" })} name="code_verifier">
              <Input addonBefore={<Select onChange={(value) => {
                setCodeChallengeMethod(value)
              }} value={codeChallengeMethod} options={[{
                label: 'S256',
                value: 'S256',
              }, {
                label: 'plain',
                value: 'plain',
              }, {
                label: 'none',
                value: 'none',
              }]} />} disabled />
            </Form.Item>
            <Form.Item style={{ textAlign: 'center' }}>
              <Button
                type="primary"
                htmlType="submit"
                loading={status.code.status === 'loading' || fetchTokenLoading || fetchUserInfoLoading || refreshTokenLoading}
              >
                {t("auth", { defaultValue: "Auth" })}
              </Button>
            </Form.Item>
          </Form>
        </Card>
        <Card title={t("status", { defaultValue: "Status" })}>
          {/*List with status icons*/}
          <List
            grid={{ gutter: 16, column: 3 }}
            dataSource={Object.values(status)}
            renderItem={(item) => (
              <List.Item>
                <List.Item.Meta
                  avatar={getStatusAvatar(item.status)}
                  title={item.title}
                  description={item.description}
                />
              </List.Item>
            )}
          />
        </Card>
        <Card loading={fetchUserInfoLoading && fetchTokenLoading && refreshTokenLoading} >
          <Tabs
            items={[{
              key: "userInfo",
              label: t("userInfo", { defaultValue: "User Info" }),
              children: userInfo && (
                <Descriptions bordered items={Object.entries(userInfo).map(([key, value]) => ({
                  label: key,
                  span: 3,
                  children: value,
                }))} />
              ),
              disabled: !userInfo || fetchUserInfoLoading,
            }, {
              key: "idToken",
              label: t("idToken", { defaultValue: "ID Token" }),
              children: id_token && (
                <Descriptions bordered items={Object.entries(parseJWTPayload(id_token)).map(([key, value]) => ({
                  label: key,
                  span: 3,
                  children: value,
                }))} />
              ),
              disabled: !id_token || fetchTokenLoading,
            }, {
              key: "accessToken",
              label: t("accessToken", { defaultValue: "Access Token" }),
              children: access_token && (
                <Descriptions bordered items={Object.entries(parseJWTPayload(access_token)).map(([key, value]) => ({
                  label: key,
                  span: 3,
                  children: value,
                }))} />
              ),
              disabled: !access_token || fetchTokenLoading,
            }]}
          />
        </Card>
      </Space>
    </div>
  );
};

export default OIDCTestPage; 