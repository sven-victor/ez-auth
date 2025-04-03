import React, { useEffect, useRef } from 'react';
import { Button, Card, message, Space, Typography, Tag } from 'antd';
import { useSearchParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { getApplicationByClientId, authorizeApplication } from '@/api/oidc';
import { useRequest } from 'ahooks';
import { SwapOutlined } from '@ant-design/icons';
import Avatar from '@/components/Avatar';
import { getApplicationDisplayName } from '@/utils';
const { Title } = Typography;

const OIDCAuthorize: React.FC = () => {
  const [searchParams] = useSearchParams();
  const { t, i18n } = useTranslation("oidc");


  const clientId = searchParams.get('client_id');
  const redirectUri = searchParams.get('redirect_uri');
  const responseType = searchParams.get('response_type');
  const scope = searchParams.get('scope');
  const state = searchParams.get('state');
  const autoAuthorize = useRef<boolean>(false);
  const nonce = searchParams.get('nonce');
  const codeChallenge = searchParams.get('code_challenge');
  const codeChallengeMethod = searchParams.get('code_challenge_method');

  const { data: { application = undefined, scopes = [] } = {}, loading } = useRequest(async () => {
    if (!clientId) {
      return {};
    }
    return await getApplicationByClientId(clientId);
  }, {
    ready: !!clientId,
  });

  useEffect(() => {
    // Validate necessary parameters
    if (!clientId) {
      message.error(t('authorize.missingClientId', { defaultValue: 'Missing Client ID' }));
      return;
    }
    if (!redirectUri) {
      message.error(t('authorize.missingRedirectUri', { defaultValue: 'Missing Redirect URI' }));
      return;
    }
    if (!responseType) {
      message.error(t('authorize.missingResponseType', { defaultValue: 'Missing Response Type' }));
      return;
    }
    if (!['code', 'token'].includes(responseType)) {
      message.error(t('authorize.invalidResponseType', { defaultValue: 'Invalid Response Type' }));
      return;
    }
    if (!state) {
      message.error(t('authorize.missingState', { defaultValue: 'Missing State' }));
      return;
    }
  }, [clientId, redirectUri, responseType, scope]);


  const { run: handleAuthorize, loading: authorizeLoading } = useRequest(async () => {
    if (!clientId || !redirectUri) {
      throw new Error(t('authorize.missingParams', { defaultValue: 'Missing Parameters' }));
    }
    return authorizeApplication({
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: scope ?? application?.scopes.join(' ') ?? '',
      response_type: responseType ?? 'code',
      state: state ?? '',
      nonce: nonce ?? undefined,
      code_challenge: codeChallenge ?? undefined,
      code_challenge_method: codeChallengeMethod ?? undefined
    })
  }, {
    onError: (error) => {
      message.error(t('authorize.error', { defaultValue: 'Authorization failed: {{error}}', error: error.message }));
    },
    onSuccess: ({ redirect_uri }) => {
      if (redirect_uri) {
        window.location.href = redirect_uri;
      }
    },
    manual: true,
    ready: !!application && !!clientId && !!redirectUri
  });

  useEffect(() => {
    if (scopes && application && scope && !autoAuthorize.current) {
      for (const s of scope?.split(' ') ?? application.scopes) {
        if (!scopes.includes(s)) {
          return
        }
      }
      handleAuthorize();
    }
  }, [scopes, application, scope]);



  return (
    <div style={{
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
      minHeight: '100vh',
      background: '#f0f2f5'
    }}>
      <Card style={{ width: 400, textAlign: 'center' }} loading={loading}>
        <Space direction="vertical" size="small" style={{ width: '100%' }}>
          <Title level={3}>{t('authorize.title', { defaultValue: 'Application Authorization' })}</Title>
          <Space size={"large"} style={{ textAlign: 'center' }}>
            <Avatar shape='square' src="/ui/logo.png" style={{ width: 40, height: 40 }} />
            <SwapOutlined />
            {
              application?.icon ?
                <Avatar shape='square' src={application?.icon} style={{ width: 40, height: 40 }} />
                :
                <div style={{ width: 40, height: 40, textAlign: 'center', alignContent: 'center' }} >{application ? getApplicationDisplayName(application, i18n.language) : ""}</div>
            }
          </Space>
          <div style={{ textAlign: 'left', marginBottom: 24 }}>
            <p>{t('authorize.description', {
              defaultValue: 'The application requests access to the following information about you:',
              clientId: clientId
            })}</p>

            {(scope?.split(' ') ?? application?.scopes ?? []).map((s) => {
              const isGranted = scopes?.includes(s);
              return <p style={{ marginBlockEnd: 0, marginBlockStart: 5 }} key={s}>• {s}{isGranted ? null : <Tag style={{ marginLeft: 8 }} color="green">{t('authorize.new', { defaultValue: 'New' })}</Tag>}</p>
            })}
          </div>

          <Space>
            <Button
              type="primary"
              onClick={handleAuthorize}
              loading={authorizeLoading}
            >
              {t('authorize.approve', { defaultValue: 'Approve' })}
            </Button>
            <Button
              onClick={() => window.close()}
            >
              {t('authorize.cancel', { defaultValue: 'Cancel' })}
            </Button>
          </Space>
        </Space>
      </Card>
    </div>
  );
};

export default OIDCAuthorize; 