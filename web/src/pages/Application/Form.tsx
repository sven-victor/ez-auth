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

import React, { useState } from 'react';
import {
  Card,
  Form,
  Input,
  Button,
  Select,
  Space,
  message,
  Row,
  Col,
  Descriptions,
  Radio,
  Tag,
  Switch,
} from 'antd';
import { useNavigate, useParams } from 'react-router-dom';
import { getApplication, updateApplication, createApplication } from '@/api/application';
import { useRequest } from 'ahooks';
import { GrantTypes, Scopes } from '@/types/application';
import { UnorderedListOutlined, CodeOutlined } from '@ant-design/icons';
import { toLDAPAttrs } from '@/utils';
import { uniq } from 'lodash';
import { AvatarUpload, useTranslation, useSite, type SiteConfig } from 'ez-console';
import I18nFormItem from '@/components/I18nFormItem';
const { Option } = Select;
const { TextArea } = Input;

interface ApplicationFormValues {
  name: string;
  display_name: string;
  display_name_i18n?: Record<string, string>;
  description?: string;
  description_i18n?: Record<string, string>;
  status: 'active' | 'inactive';
  source?: 'ldap' | 'local';
  grant_types?: string[];
  redirect_uris?: string[];
  scopes?: string[];
  icon?: string;
  ldap_attrs?: string;
  uri?: string;
  force_independent_password?: boolean;
}

const ApplicationForm: React.FC = () => {
  const { id = "" } = useParams<{ id?: string }>();
  const { siteConfig } = useSite();
  const navigate = useNavigate();
  const { t } = useTranslation("applications");
  const { t: tCommon } = useTranslation("common");
  const [form] = Form.useForm();
  const [codeForm] = Form.useForm();
  const isEditMode = !!id;

  const [uri, setUri] = useState<string>('');
  const [ldapAttrs, setLDAPAttrs] = useState<API.LDAPAttrs[]>([]);
  const [source, setSource] = useState<'ldap' | 'local'>('local');
  const [viewMode, setViewMode] = useState<'normal' | 'code'>('normal');
  const [grantTypes, setGrantTypes] = useState<string[]>([]);

  // If it is edit mode, get application information
  const { loading: applicationLoading, data: application } = useRequest(async () => {
    if (!isEditMode || !form) {
      return;
    }

    return getApplication(id)
  }, {
    onSuccess: (data) => {
      if (data) {
        setGrantTypes(data.grant_types || []);
        setSource(data.source || 'local');
        form.setFieldsValue({
          name: data.name,
          display_name: data.display_name,
          display_name_i18n: data.display_name_i18n,
          description: data.description,
          description_i18n: data.description_i18n,
          status: data.status,
          source: data.source || 'local',
          grant_types: data.grant_types,
          redirect_uris: data.redirect_uris,
          scopes: data.scopes,
          uri: data.uri,
          icon: data.icon,
          force_independent_password: data.force_independent_password,
        });
        const ldap_attrs: string[] = data.ldap_attrs?.filter((attr: API.LDAPAttrs) => attr.user_attr).map((attr: API.LDAPAttrs) => {
          return `${attr.name}: ${attr.value}`
        }) ?? [];
        if (data.ldap_attrs) {
          setLDAPAttrs(data.ldap_attrs.filter((attr: API.LDAPAttrs) => attr.user_attr));
          codeForm.setFieldsValue({
            ldap_attrs: ldap_attrs.join('\n'),
          });
        }
      }
    }, onError: (error) => {
      message.error(t('loadError', { defaultValue: 'Failed to load application: {{error}}', error: `${error}` }));
    }, refreshDeps: [id, form]
  });

  // Submit form
  const { run: onSubmit, loading: submitLoading } = useRequest(async (data: API.ApplicationUpdateRequest | API.ApplicationCreateRequest) => {
    try {
      if (isEditMode) {
        // Update application
        await updateApplication(id, data);
        message.success(t('updateSuccess', { defaultValue: 'Application updated successfully' }));
        navigate(`/applications/${id}`);
      } else {
        // Create new application
        const newApplication = await createApplication(data);
        message.success(t('createSuccess', { defaultValue: 'Application created successfully' }));
        navigate(`/applications/${newApplication.id}`);
      }
    } catch (error) {
      message.error(isEditMode ? t('updateError', { defaultValue: 'Failed to update application: {{error}}', error: error as string }) : t('createError', { defaultValue: 'Failed to create application: {{error}}', error: error as string }));
    }
  }, { manual: true });

  // Submit normal mode form
  const onNormalSubmit = (values: ApplicationFormValues) => {
    onSubmit({
      name: values.name,
      display_name: values.display_name,
      display_name_i18n: values.display_name_i18n,
      description: values.description,
      description_i18n: values.description_i18n,
      status: values.status,
      source: values.source,
      grant_types: values.grant_types,
      uri: values.uri,
      redirect_uris: values.redirect_uris,
      scopes: values.scopes,
      icon: values.icon,
      force_independent_password: values.force_independent_password,
    })
  }

  const onCodeSubmit = ({ ldap_attrs, }: Required<Pick<ApplicationFormValues, 'ldap_attrs'>>) => {
    onSubmit({ ldap_attrs: toLDAPAttrs(ldap_attrs), source: 'ldap' })
  }

  return (
    <Card
      title={isEditMode ? t('editTitle', { defaultValue: 'Edit Application' }) : t('createTitle', { defaultValue: 'Create Application' })}
      loading={applicationLoading}
      extra={<Space>
        {((!isEditMode && source === 'ldap') || (isEditMode && source === 'ldap')) && (
          <Radio.Group value={viewMode} onChange={(e) => setViewMode(e.target.value)}>
            <Radio.Button value="normal"><UnorderedListOutlined /></Radio.Button>
            <Radio.Button value="code"><CodeOutlined /></Radio.Button>
          </Radio.Group>
        )}
      </Space>}
    >
      <Form<ApplicationFormValues>
        form={form}
        hidden={viewMode === 'code'}
        layout="horizontal"
        onFinish={onNormalSubmit}
        labelCol={{
          sm: { span: 24 },
          md: { span: 8 },
        }}
        wrapperCol={{
          sm: { span: 24 },
          md: { span: 16 },
        }}
        size='middle'
        style={{ maxWidth: '650px', margin: '0 auto' }}
        initialValues={{
          name: '',
          description: '',
          status: 'active',
          source: 'local',
          grant_types: [],
          redirect_uris: [],
          scopes: [],
        }}
      >
        <Form.Item
          name="icon"
          label={t('icon', { defaultValue: 'Icon' })}
        >
          <AvatarUpload />
        </Form.Item>
        {!isEditMode && (
          <Form.Item
            name="source"
            label={t('source', { defaultValue: 'Data Source' })}
            rules={[{ required: true, message: t('sourceRequired', { defaultValue: 'Data source is required' }) }]}
          >
            <Radio.Group onChange={(e) => setSource(e.target.value)}>
              <Radio value="local">{t('sourceLocal', { defaultValue: 'Local' })}</Radio>
              <Radio value="ldap" disabled={!((siteConfig as SiteConfig | undefined)?.attrs.application_ldap_enabled)}>{t('sourceLdap', { defaultValue: 'LDAP' })}</Radio>
            </Radio.Group>
          </Form.Item>
        )}
        {isEditMode && (
          <Form.Item
            label={t('source', { defaultValue: 'Data Source' })}
          >
            <span>{source === 'ldap' ? t('sourceLdap', { defaultValue: 'LDAP' }) : t('sourceLocal', { defaultValue: 'Local' })}</span>
          </Form.Item>
        )}
        <Form.Item
          name="name"
          label={t('name', { defaultValue: 'Name' })}
          rules={[
            { required: true, message: t('nameRequired', { defaultValue: 'Name is required' }) },
            { pattern: /^[a-zA-Z0-9_-]+$/, message: t('nameInvalid', { defaultValue: 'Name can only contain letters, numbers, hyphens, and underscores' }) }
          ]}
        >
          <Input placeholder={t('namePlaceholder', { defaultValue: 'Enter application name' })} />
        </Form.Item>

        <Form.Item
          label={t('displayName', { defaultValue: "Display Name" })}
        >
          <I18nFormItem
            t={(key, options) => {
              return tCommon(`languageName.${key}`, options);
            }}
            name="display_name"
          />
        </Form.Item>
        <Form.Item
          label={t('description', { defaultValue: "Description" })}
        >
          <I18nFormItem
            t={(key, options) => {
              return tCommon(`languageName.${key}`, options);
            }}
            name="description" childRender={() => {
              return <TextArea rows={4} />
            }}
          />
        </Form.Item>

        <Form.Item
          name="status"
          label={t('status', { defaultValue: 'Status' })}
          rules={[{ required: true, message: t('statusRequired', { defaultValue: 'Status is required' }) }]}
        >
          <Select>
            <Option value="active">{t('statusEnum.active', { defaultValue: 'Active' })}</Option>
            <Option value="inactive">{t('statusEnum.inactive', { defaultValue: 'Inactive' })}</Option>
          </Select>
        </Form.Item>

        <Form.Item
          name="grant_types"
          label={t('grantTypes', { defaultValue: 'Grant Types' })}
          rules={[{ required: true, message: t('grantTypesRequired', { defaultValue: 'Grant types are required' }) }]}
          initialValue={['auto']}
        >
          <Select<string> mode="multiple" placeholder={t('grantTypesPlaceholder', { defaultValue: 'Select grant types' })} onSelect={(value) => {
            const conflictGrantTypes = ['authorization_code', 'hybrid', 'implicit', 'password', 'auto']
            const grantTypes: string[] = uniq<string>([...(form.getFieldValue("grant_types") ?? []), value]);
            if (conflictGrantTypes.includes(value)) {
              if (grantTypes.filter((item) => conflictGrantTypes.includes(item)).length >= 2) {
                const newGrantTypes = [value, ...grantTypes.filter((item) => !conflictGrantTypes.includes(item))];
                form.setFieldsValue({ grant_types: newGrantTypes });
                setGrantTypes(newGrantTypes);
                return;
              }
            }
            setGrantTypes([value, ...grantTypes]);
          }}>

            {Object.keys(GrantTypes).map((grantType: string) => {
              return <Option key={grantType} value={grantType}>{t(`grantType.${grantType}`, { defaultValue: GrantTypes[grantType as keyof typeof GrantTypes] })}</Option>
            })}
          </Select>
        </Form.Item>

        <Form.Item
          name="force_independent_password"
          label={t('forceIndependentPassword', { defaultValue: 'Force Independent Password' })}
          dependencies={['grant_types']}
          tooltip={t('forceIndependentPasswordTooltip', { defaultValue: "If enabled, users need to be forced to use the app's unique password when authenticating, and the unique password needs to be set by the user before use." })}
          hidden={!grantTypes.includes('password')}
        >
          <Switch />
        </Form.Item>

        <Form.Item
          name="uri"
          label={t('uri', { defaultValue: 'Homepage URI' })}
          rules={[{
            pattern: /^https?:\/\/[^\s]+$/,
            message: t('uriInvalid', { defaultValue: 'Invalid URI format' }),
          }]}
        >
          <Input placeholder={t('uriPlaceholder', { defaultValue: 'Enter homepage URI' })} onBlur={(e) => {
            const uri = e.target.value;
            if (uri) {
              setUri(uri);
            }
          }} />
        </Form.Item>

        <Form.Item
          name="redirect_uris"
          label={t('redirectUris', { defaultValue: 'Redirect URIs' })}
          rules={[(form) => {
            const grantTypes: string[] = form.getFieldValue('grant_types') ?? [];
            if (grantTypes.includes('authorization_code') || grantTypes.includes('hybrid')) {
              return {
                required: true,
                message: t('redirectUrisRequired', { defaultValue: 'Redirect URIs are required' }),
              }
            }
            return {
              required: false,
            }
          }, {
            validator(_, value, callback) {
              value?.forEach((uri: string) => {
                if (!/^https?:\/\/[^\s]+$/.test(uri)) {
                  callback(t('uriInvalid', { defaultValue: 'Invalid Redirect URI: {{value}}', value: uri }));
                  return
                }
              });
              callback()
            },
          }]}
        >
          <Select mode="tags" placeholder={t('redirectUrisPlaceholder', { defaultValue: 'Enter redirect URIs' })} options={uri ? [{ label: uri, value: uri }] : []} />
        </Form.Item>
        <Form.Item
          name="scopes"
          label={t('scopes', { defaultValue: 'Scopes' })}
        >
          <Select mode="tags" placeholder={t('scopesPlaceholder', { defaultValue: 'Enter or select scopes' })} options={Scopes.map((scope) => ({ label: scope, value: scope }))} />
        </Form.Item>

        <Form.Item wrapperCol={{ offset: 6, span: 18 }}>
          <Space>
            <Button type="primary" htmlType="submit" loading={submitLoading}>
              {isEditMode ? tCommon('update', { defaultValue: 'Update' }) : tCommon('create', { defaultValue: 'Create' })}
            </Button>
            <Button onClick={() => navigate('/applications')}>
              {tCommon('cancel', { defaultValue: 'Cancel' })}
            </Button>
          </Space>
        </Form.Item>
      </Form>
      <Card hidden={viewMode === 'normal' || source === 'local'} variant='borderless'>
        <Row >
          <Col sm={{ span: 24 }} md={{ span: 24 }} lg={{ span: 24 }} xl={{ span: 11 }}>
            <Form
              form={codeForm}
              layout="vertical"
              initialValues={{
                ldap_attrs: '',
              }}
              onFinish={onCodeSubmit}
            >
              <Form.Item
                name="ldap_attrs"
              >
                <Input.TextArea
                  onChange={(e) => {
                    setLDAPAttrs(toLDAPAttrs(e.target.value));
                  }}
                  rows={21}
                  size='large'
                />
              </Form.Item>

              {/* Submit button, centered */}
              <Form.Item wrapperCol={{ offset: 9 }}>
                <Space>
                  <Button
                    type="primary"
                    htmlType="submit"
                    loading={submitLoading}
                  >
                    {isEditMode ? tCommon('update') : tCommon('create')}
                  </Button>
                  <Button
                    onClick={() => isEditMode ? navigate(`/applications/${id}`) : navigate('/applications')}
                  >
                    {tCommon('cancel')}
                  </Button>
                </Space>
              </Form.Item>
            </Form>
          </Col>
          <Col md={{ span: 0 }} lg={{ span: 1 }}></Col>
          <Col sm={{ span: 24 }} md={{ span: 24 }} lg={{ span: 24 }} xl={{ span: 11 }} hidden={viewMode === 'normal'}>
            <Descriptions size='middle' column={1} bordered items={[...ldapAttrs.map((attr) => ({
              key: attr.name,
              label: attr.name,
              children: <span>{attr.value}</span>,
            })), ...(application?.ldap_attrs?.filter((attr) => !attr.user_attr).map((attr) => ({
              key: attr.name,
              label: <Space><span>{attr.name}</span><Tag color="blue">{t('systemAttr', { defaultValue: "system" })}</Tag></Space>,
              children: <span>{attr.value}</span>,
            })) ?? []),
            ]}
              style={{
                maxHeight: 650,
                overflow: 'auto',
              }}
            />
          </Col>
        </Row>
      </Card>
    </Card>
  );
};

export default ApplicationForm; 