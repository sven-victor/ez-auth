import { createApplicationKey } from "@/api/application";
import { useRequest } from "ahooks";
import { Modal, Input, DatePicker, Form, message, Typography, Alert } from "antd";
import dayjs from "dayjs";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router-dom";

export const CreateAccessKeyModel = ({
  onSuccess,
  id,
  visible,
  setVisible,
}: {
  onSuccess: () => void,
  id: string,
  visible: boolean,
  setVisible: (visible: boolean) => void,
}) => {
  const { t } = useTranslation("applications");
  const [form] = Form.useForm();

  const [newKey, setNewKey] = useState<API.ApplicationKey & { wellknow_endpoint: string } | null>(null);

  const { run: handleCreateKey, loading: createKeyLoading } = useRequest(async (values: any) => {
    return await createApplicationKey(id!, values);
  }, {
    manual: true,
    onSuccess: (data) => {
      message.success(t('keyCreateSuccess', { defaultValue: 'Key created successfully' }));
      form.resetFields();
      setNewKey(data);
    },
    onError: (error) => {
      message.error(t('keyCreateError', { defaultValue: 'Failed to create key: {{error}}', error: error.message }));
    },
  })


  return <Modal
    title={newKey ? t('createKeySuccess', { defaultValue: 'Key Created Successfully' }) : t('createKey', { defaultValue: 'Create Key' })}
    open={visible}
    cancelButtonProps={{ style: { display: newKey ? 'none' : 'unset' } }}
    onOk={() => {
      if (newKey) {
        setVisible(false)
        onSuccess()
        setNewKey(null)
      } else {
        form.submit()
      }
    }}
    onCancel={() => {
      setVisible(false)
      if (newKey) {
        onSuccess()
        setNewKey(null)
      }
    }}
    confirmLoading={createKeyLoading}
  >
    <div hidden={newKey === null}>
      <Alert
        message={t('newKeyDescription', { defaultValue: 'Please save the client ID and client secret. You will not be able to see the secret again.' })}
        type="success"
        showIcon
        style={{ marginBottom: 16 }}
      />
      <div>Client ID: <Typography.Text copyable>{newKey?.client_id}</Typography.Text></div>
      <div>Client Secret: <Typography.Text copyable>{newKey?.client_secret}</Typography.Text></div>
      <div>Well-known Endpoint: <Typography.Text style={{ maxWidth: 280 }} ellipsis={{ tooltip: newKey?.wellknow_endpoint }} copyable={{ text: newKey?.wellknow_endpoint }}>{newKey?.wellknow_endpoint}</Typography.Text></div>
      <div style={{ marginTop: 10 }}>
        <Link to={`/oidc/test?client_id=${newKey?.client_id}`} target="_blank" state={{
          client_id: newKey?.client_id,
          client_secret: newKey?.client_secret,
        }}>
          {t('gotoTest', { defaultValue: 'Go to test' },)}
        </Link>
      </div>
    </div>
    <Form
      form={form}
      onFinish={handleCreateKey}
      layout="vertical"
      disabled={createKeyLoading}
      hidden={newKey !== null}
    >
      <Form.Item
        name="name"
        label={t('keyName', { defaultValue: 'Key Name' })}
        rules={[{ required: true, message: t('keyNameRequired', { defaultValue: 'Key name is required' }) }]}
      >
        <Input placeholder={t('keyNamePlaceholder', { defaultValue: 'Enter key name' })} />
      </Form.Item>
      <Form.Item
        name="expiresAt"
        label={t('keyExpiresAt', { defaultValue: 'Expires At' })}
      >
        <DatePicker
          showTime
          format="YYYY-MM-DD HH:mm:ss"
          disabledDate={current => current && current < dayjs().endOf('day')}
        />
      </Form.Item>
    </Form>
  </Modal>
}

export default CreateAccessKeyModel;