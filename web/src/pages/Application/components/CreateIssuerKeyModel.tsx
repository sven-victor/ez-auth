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

import { createApplicationIssuerKey } from "@/api/application";
import { InfoCircleOutlined } from "@ant-design/icons";
import { useRequest } from "ahooks";
import { Modal, Input, Form, message, Typography, Select, Space, Popover } from "antd";
import { useState } from "react";
import { useTranslation } from "react-i18next";

export const CreateIssuerKeyModel = ({
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
  const [importKey, setImportKey] = useState<boolean>(false);

  const { run: handleCreateKey, loading: createKeyLoading } = useRequest(async (values: any) => {
    return await createApplicationIssuerKey(id!, values);
  }, {
    manual: true,
    onSuccess: (_) => {
      message.success(t('keyCreateSuccess', { defaultValue: 'Key created successfully' }));
      form.resetFields();
      onSuccess();
      setVisible(false);
    },
    onError: (error) => {
      message.error(t('keyCreateError', { defaultValue: 'Failed to create key: {{error}}', error: error.message }));
    },
  })
  const [keyAlgorithm, setKeyAlgorithm] = useState<string>("RS256");


  return <Modal
    title={t('createKey', { defaultValue: 'Create Issuer Key' })}
    open={visible}
    onOk={() => {
      form.submit()
    }}
    width={600}
    onCancel={() => {
      setVisible(false)
    }}
    confirmLoading={createKeyLoading}
  >
    <Form
      form={form}
      onFinish={handleCreateKey}
      layout="vertical"
      initialValues={{
        algorithm: 'RS256',
      }}
      disabled={createKeyLoading}
    >
      <Form.Item
        name="name"
        label={t('keyName', { defaultValue: 'Key Name' })}
        rules={[{ required: true, message: t('keyNameRequired', { defaultValue: 'Key name is required' }) }]}
      >
        <Input placeholder={t('keyNamePlaceholder', { defaultValue: 'Enter key name' })} />
      </Form.Item>
      <Form.Item
        name="algorithm"
        label={t('keyAlgorithm', { defaultValue: 'Algorithm' })}
        rules={[{ required: true, message: t('keyAlgorithmRequired', { defaultValue: 'Algorithm is required' }) }]}
      >
        <Select
          onChange={(value) => {
            form.setFieldsValue({
              private_key: null,
            });
            setKeyAlgorithm(value);
          }}
          value={keyAlgorithm}
          options={[
            {
              label: t('keyAlgorithmRSA', { defaultValue: 'RSA' }),
              options: [
                { label: t('keyAlgorithmRS256', { defaultValue: 'RS256' }), value: 'RS256' },
                { label: t('keyAlgorithmRS384', { defaultValue: 'RS384' }), value: 'RS384' },
                { label: t('keyAlgorithmRS512', { defaultValue: 'RS512' }), value: 'RS512' },
              ]
            },
            {
              label: t('keyAlgorithmECDSA', { defaultValue: 'ECDSA' }),
              options: [
                { label: t('keyAlgorithmES256', { defaultValue: 'ES256' }), value: 'ES256' },
                { label: t('keyAlgorithmES384', { defaultValue: 'ES384' }), value: 'ES384' },
                { label: t('keyAlgorithmES512', { defaultValue: 'ES512' }), value: 'ES512' },
              ]
            },
            {
              label: t('keyAlgorithmHMAC', { defaultValue: 'HMAC' }),
              options: [
                { label: t('keyAlgorithmHS256', { defaultValue: 'HS256' }), value: 'HS256' },
                { label: t('keyAlgorithmHS384', { defaultValue: 'HS384' }), value: 'HS384' },
                { label: t('keyAlgorithmHS512', { defaultValue: 'HS512' }), value: 'HS512' },
              ]
            },
          ]}
        />
      </Form.Item>
      <Form.Item label={t('keySource', { defaultValue: 'Key Source' })} >
        <Select
          options={[
            { label: t('keyPrivateKeyImport', { defaultValue: 'Import' }), value: 'import' },
            { label: t('keyPrivateKeyAutoGenerate', { defaultValue: 'Auto Generate' }), value: 'auto' }]
          }
          defaultValue={'auto'}
          style={{ marginBottom: 3 }}
          onChange={(value) => {
            if (value === 'import') {
              setImportKey(true);
            } else {
              form.setFieldsValue({
                private_key: null,
              });
              setImportKey(false);
            }
          }} />
      </Form.Item>
      <Form.Item
        name="private_key"
        label={<Space size="small">
          {t('keyPrivateKey', { defaultValue: 'Private Key' })}
          <Popover content={<div>
            <div>{t(`keyPrivateKeyTooltip.${keyAlgorithm}`)}</div>
            <Typography.Text copyable code>{t(`keyPrivateKeyTooltipCommand.${keyAlgorithm}`)}</Typography.Text>
          </div>}>
            <InfoCircleOutlined />
          </Popover>
        </Space>}
        hidden={!importKey}
        rules={[() => {
          if (importKey) {
            return {
              required: true,
              message: t('keyPrivateKeyRequired', { defaultValue: 'Private key is required' }),
            }
          }
          return {}
        }]}
      >
        <Input.TextArea rows={10} />
      </Form.Item>
    </Form>
  </Modal>
}

export default CreateIssuerKeyModel;