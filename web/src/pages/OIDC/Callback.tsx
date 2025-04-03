import React, { useEffect, useRef, useState } from 'react';
import { useParams, useSearchParams } from 'react-router-dom';
import { Button, Space } from 'antd';
import { useTranslation } from 'react-i18next';
const OIDCCallback: React.FC = () => {
  const { t } = useTranslation("oidc");
  const [searchParams] = useSearchParams();
  const { codeIndex } = useParams();
  const [message, setMessage] = useState<string>();
  const [timerInterval, setTimerInterval] = useState<number>(0);
  const setTimer = () => {
    setTimerInterval((interval) => {
      console.log(interval)
      return interval - 1;
    });
  }
  const timerRef = useRef<NodeJS.Timeout>();
  useEffect(() => {
    const code = searchParams.get('code');
    const error = searchParams.get('error');
    const errorDescription = searchParams.get('error_description');

    if (error) {
      setMessage(t("callback.error", { defaultValue: "Authentication failed: {{errorDescription}}", errorDescription: errorDescription || error }));
      return;
    }

    if (!code) {
      setMessage(t("callback.noCode", { defaultValue: "No authorization code received" }));
      return;
    }

    try {
      // Store the code in localStorage
      localStorage.setItem(`oidc_code_${codeIndex}`, code);
      window.onclose = () => {
        localStorage.removeItem(`oidc_code_${codeIndex}`);
      }
      if (!timerRef.current) {
        timerRef.current = setInterval(setTimer, 1000);
        setTimerInterval(5);
        setTimeout(() => {
          clearInterval(timerRef.current);
          window.close();
        }, 5000);
      }
    } catch (error) {
      setMessage(t("callback.failed", { defaultValue: "Failed to record authorization code" }));
    }
  }, []);

  return (
    <div style={{
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
      height: '100vh'
    }}>
      <Space direction='vertical'>
        <div>{message ?? `${t("callback.closeIn", { defaultValue: "{{timerInterval}} seconds to close the page", timerInterval })}`}</div>
        <Button onClick={() => {
          window.close();
        }}>{t("callback.close", { defaultValue: "Close immediately" })}</Button>
      </Space>
    </div>
  );
};

export default OIDCCallback; 