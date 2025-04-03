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
} from 'antd';
import { useNavigate, useParams } from 'react-router-dom';
import { getApplication, updateApplication, createApplication } from '@/api/application';
import { useTranslation } from 'react-i18next';
import { useRequest } from 'ahooks';
import { GrantTypes, Scopes } from '@/types/application';
import { UnorderedListOutlined, CodeOutlined } from '@ant-design/icons';
import { toLDAPAttrs } from '@/utils';
import { uniq } from 'lodash';
import { AvatarUpload } from '@/components/Avatar';
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
  grant_types?: string[];
  redirect_uris?: string[];
  scopes?: string[];
  icon?: string;
  ldap_attrs?: string;
  uri?: string;
}

const ApplicationForm: React.FC = () => {
  const { id = "" } = useParams<{ id?: string }>();
  const navigate = useNavigate();
  const { t } = useTranslation("applications");
  const { t: tCommon } = useTranslation("common");
  const [form] = Form.useForm();
  const [codeForm] = Form.useForm();
  const isEditMode = !!id;

  const [uri, setUri] = useState<string>('');
  const [ldapAttrs, setLDAPAttrs] = useState<API.LDAPAttrs[]>([]);

  const [viewMode, setViewMode] = useState<'normal' | 'code'>('normal');

  // If it is edit mode, get application information
  const { loading: applicationLoading, data: application } = useRequest(async () => {
    if (!isEditMode || !form) {
      return;
    }

    return getApplication(id)
  }, {
    onSuccess: (data) => {
      if (data) {
        form.setFieldsValue({
          name: data.name,
          display_name: data.display_name,
          display_name_i18n: data.display_name_i18n,
          description: data.description,
          description_i18n: data.description_i18n,
          status: data.status,
          grant_types: data.grant_types,
          redirect_uris: data.redirect_uris,
          scopes: data.scopes,
          uri: data.uri,
          icon: data.icon,
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
      grant_types: values.grant_types,
      uri: values.uri,
      redirect_uris: values.redirect_uris,
      scopes: values.scopes,
      icon: values.icon,
    })
  }

  const onCodeSubmit = ({ ldap_attrs, }: Required<Pick<ApplicationFormValues, 'ldap_attrs'>>) => {
    onSubmit({ ldap_attrs: toLDAPAttrs(ldap_attrs) })
  }

  return (
    <Card
      title={isEditMode ? t('editTitle', { defaultValue: 'Edit Application' }) : t('createTitle', { defaultValue: 'Create Application' })}
      loading={applicationLoading}
      extra={<Space>
        <Radio.Group value={viewMode} onChange={(e) => setViewMode(e.target.value)}>
          <Radio.Button value="normal"><UnorderedListOutlined /></Radio.Button>
          <Radio.Button value="code"><CodeOutlined /></Radio.Button>
        </Radio.Group>
      </Space>}
    >
      <Form<ApplicationFormValues>
        form={form}
        hidden={viewMode === 'code'}
        layout="horizontal"
        onFinish={onNormalSubmit}
        labelCol={{
          sm: { span: 24 },
          md: { span: 6 },
        }}
        wrapperCol={{
          sm: { span: 24 },
          md: { span: 18 },
        }}
        size='middle'
        style={{ maxWidth: '500px', margin: '0 auto' }}
        initialValues={{
          name: '',
          description: '',
          status: 'active',
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
                return;
              }
            }
          }}>

            {Object.keys(GrantTypes).map((grantType: string) => {
              return <Option value={grantType}>{t(`grantType.${grantType}`, { defaultValue: GrantTypes[grantType as keyof typeof GrantTypes] })}</Option>
            })}
          </Select>
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
      <Card hidden={viewMode === 'normal'} variant='borderless'>
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