import React, { useState } from 'react';
import {
  Card,
  Form,
  Input,
  Button,
  Select,
  Space,
  message,
  Switch,
  Radio,
  Col,
  Row,
  Descriptions,
  Tag,
} from 'antd';
import { useNavigate, useParams } from 'react-router-dom';
import { getUser, updateUser, createUser, getRoles } from '@/api/user';
import { useTranslation } from 'react-i18next';
import { useRequest } from 'ahooks';
import { CodeOutlined, UnorderedListOutlined } from '@ant-design/icons';
import { toLDAPAttrs } from '@/utils';
import { AvatarUpload } from '@/components/Avatar';

const { Option } = Select;

interface UserFormValues {
  username: string;
  email: string;
  full_name: string;
  status: 'active' | 'inactive';
  mfa_enforced: boolean;
  ldap_attrs: string;
  source: string;
  role_ids: string[];
  phone?: string;
  avatar?: string;
  password?: string;
}

const UserForm: React.FC = () => {
  const { id = "" } = useParams<{ id?: string }>();
  const navigate = useNavigate();
  const { t } = useTranslation("users");
  const { t: tCommon } = useTranslation("common");
  const [form] = Form.useForm();
  const [codeForm] = Form.useForm();
  const isEditMode = !!id;

  const [ldapAttrs, setLDAPAttrs] = useState<API.LDAPAttrs[]>([]);


  // Get role list
  const { data: rolesData, loading: rolesLoading } = useRequest(async () => {
    const { data } = await getRoles();
    return data.map((role: API.Role) => ({
      ...role,
      label: role.name,
      value: role.id,
    }));
  });

  // If it is edit mode, get user information
  const { loading: userLoading, run: fetchUser, data: user } = useRequest(async () => {
    if (!isEditMode || !form) {
      return;
    }

    return getUser(id)
  }, {
    onSuccess: (data) => {
      if (data) {
        form.setFieldsValue({
          username: data.username,
          email: data.email,
          full_name: data.full_name,
          status: data.status,
          mfa_enforced: data.mfa_enforced,
          role_ids: data.roles ? data.roles.map(role => role.id) : [],
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
      message.error(t('loadError', { defaultValue: 'Failed to load user: {{error}}', error: `${error}` }));
    }, refreshDeps: [id, form]
  });


  // Submit form
  const { run: onSubmit, loading: submitLoading } = useRequest(async (values: UserFormValues) => {
    try {
      if (isEditMode) {
        // Update user basic information
        await updateUser(id, values.ldap_attrs ? {
          ldap_attrs: toLDAPAttrs(values.ldap_attrs)
        } : {
          email: values.email,
          full_name: values.full_name,
          status: values.status,
          mfa_enforced: values.mfa_enforced,
          source: user?.source || 'local',
          role_ids: values.role_ids,
          avatar: values.avatar,
        });

        message.success(t('updateSuccess', { defaultValue: 'User updated successfully' }));
        fetchUser()
      } else {
        // Create new user
        const newUser = await createUser(values.ldap_attrs ? {
          ldap_attrs: toLDAPAttrs(values.ldap_attrs)
        } : {
          username: values.username!,
          email: values.email,
          full_name: values.full_name,
          mfa_enforced: values.mfa_enforced,
          source: user?.source || 'local',
          role_ids: values.role_ids,
          avatar: values.avatar,
          password: values.password,
        });
        message.success(t('createSuccess', { defaultValue: 'User created successfully' }));
        navigate(`/users/${newUser.id}`);
      }
    } catch (error) {
      message.error(isEditMode ? t('updateError', { defaultValue: 'Failed to update user: {{error}}', error: error as string }) : t('createError', { defaultValue: 'Failed to create user: {{error}}', error: error as string }));
    }
  }, { manual: true });

  // Form validation rules
  const validatePassword = (_: any, value: string) => {
    const minLength = 8;
    if (isEditMode) return Promise.resolve();
    if (!value) return Promise.reject(new Error(t('passwordRequired', { defaultValue: 'Password is required' })));
    if (value.length < minLength) return Promise.reject(new Error(t('passwordTooShort', { defaultValue: 'Password must be at least {{minLength}} characters', minLength })));
    return Promise.resolve();
  };

  const validateConfirmPassword = (_: any, value: string) => {
    if (isEditMode) return Promise.resolve();
    if (!value) return Promise.reject(new Error(t('confirmPasswordRequired', { defaultValue: 'Please confirm your password' })));
    if (value !== form.getFieldValue('password')) {
      return Promise.reject(new Error(t('passwordMismatch', { defaultValue: 'The two passwords do not match' })));
    }
    return Promise.resolve();
  };

  const [viewMode, setViewMode] = useState<'normal' | 'code'>('normal');

  return (
    <Card
      title={isEditMode ? t('editTitle', { defaultValue: 'Edit User' }) : t('createTitle', { defaultValue: 'Create User' })}
      loading={userLoading}
      extra={<Space>
        <Radio.Group value={viewMode} onChange={(e) => setViewMode(e.target.value)}>
          <Radio.Button value="normal"><UnorderedListOutlined /></Radio.Button>
          <Radio.Button value="code"><CodeOutlined /></Radio.Button>
        </Radio.Group>
      </Space>}
    >
      <Form<UserFormValues>
        hidden={viewMode === 'code'}
        form={form}
        layout="horizontal"
        onFinish={onSubmit}
        labelCol={{
          xs: { span: 24 },
          sm: { span: 24 },
          md: { span: 8 },
        }}
        wrapperCol={{
          xs: { span: 24 },
          sm: { span: 24 },
          md: { span: 16 },
        }}
        size='middle'
        style={{ margin: '0 auto', maxWidth: 600 }}
        initialValues={{
          username: '',
          email: '',
          full_name: '',
          status: 'active',
          mfa_enforced: false,
        }}
      >
        <Form.Item
          name="avatar"
          label={t('user.avatar', { defaultValue: 'Avatar' })}
        >
          <AvatarUpload />
        </Form.Item>
        <Form.Item
          name="username"
          label={t('username', { defaultValue: 'Username' })}
          rules={[
            { required: !isEditMode, message: t('usernameRequired', { defaultValue: 'Username is required' }) },
          ]}
        >
          <Input disabled={isEditMode} placeholder={t('usernamePlaceholder', { defaultValue: 'Enter username' })} />
        </Form.Item>
        <Form.Item
          name="email"
          label={t('email', { defaultValue: 'Email' })}
          rules={[
            { required: true, message: t('emailRequired', { defaultValue: 'Email is required' }) },
            { type: 'email', message: t('emailInvalid', { defaultValue: 'Please enter a valid email' }) },
          ]}
        >
          <Input placeholder={t('emailPlaceholder', { defaultValue: 'Enter email' })} />
        </Form.Item>
        <Form.Item
          name="full_name"
          label={t('fullName', { defaultValue: 'Full Name' })}
          rules={[{ required: true, message: t('fullNameRequired', { defaultValue: 'Full name is required' }) }]}
        >
          <Input placeholder={t('fullNamePlaceholder', { defaultValue: 'Enter full name' })} />
        </Form.Item>
        {isEditMode && (
          <Form.Item
            name="status"
            label={t('status', { defaultValue: 'Status' })}
            rules={[{ required: true, message: t('statusRequired', { defaultValue: 'Status is required' }) }]}
          >
            <Select placeholder={t('statusPlaceholder', { defaultValue: 'Select status' })}>
              <Option value="active">{t('statusEnum.active', { defaultValue: 'Active' })}</Option>
              <Option value="disabled">{t('statusEnum.disabled', { defaultValue: 'Disabled' })}</Option>
            </Select>
          </Form.Item>)}
        <Form.Item
          name="mfa_enforced"
          label={t('mfaEnforced', { defaultValue: 'MFA Enforced' })}
        >
          <Switch />
        </Form.Item>

        {!isEditMode && (
          <>
            <Form.Item
              name="password"
              label={t('password', { defaultValue: 'Password' })}
              rules={[{ validator: validatePassword }]}
            >
              <Input.Password visibilityToggle={false} placeholder={t('passwordPlaceholder', { defaultValue: 'Enter password' })} />
            </Form.Item>
            <Form.Item
              name="confirm_password"
              label={t('confirmPassword', { defaultValue: 'Confirm Password' })}
              rules={[{ validator: validateConfirmPassword }]}
              dependencies={['password']}
            >
              <Input.Password placeholder={t('confirmPasswordPlaceholder', { defaultValue: 'Confirm password' })} />
            </Form.Item>
          </>
        )}
        <Form.Item
          name="role_ids"
          label={t('user.roles', { defaultValue: 'Roles' })}
        >
          <Select
            mode="multiple"
            placeholder={t('user.selectRoles', { defaultValue: 'Select roles' })}
            options={rolesData}
            optionFilterProp="label"
            loading={rolesLoading}
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
              {isEditMode ? tCommon('update', { defaultValue: 'Update' }) : tCommon('create', { defaultValue: 'Create' })}
            </Button>
            <Button
              onClick={() => isEditMode ? navigate(`/users/${id}`) : navigate('/users')}
            >
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
              onFinish={onSubmit}
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
                    onClick={() => isEditMode ? navigate(`/users/${id}`) : navigate('/users')}
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
            })), ...(user?.ldap_attrs?.filter((attr) => !attr.user_attr).map((attr) => ({
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

export default UserForm; 