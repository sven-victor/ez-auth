import React, { useRef, useState } from 'react';
import {
  Card,
  Descriptions,
  Button,
  Tag,
  Space,
  Typography,
  Spin,
  message,
  Badge,
  TableColumnType,
  Divider,
  Modal,
} from 'antd';
import {
  UserOutlined,
  EditOutlined,
  ArrowLeftOutlined,
  AppstoreOutlined,
  ReloadOutlined,
  UserAddOutlined,
} from '@ant-design/icons';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { getUser, getUserApplications, resetUserPassword } from '@/api/user';
import { formatDate, getApplicationDescription, getApplicationDisplayName } from '@/utils';
import { useTranslation } from 'react-i18next';
import { useRequest } from 'ahooks';
import i18n from '@/i18n';
import AssignUserModel from './components/AssignUserModel';
import { Table, TableRef } from '@/components/Table';
import Avatar from '@/components/Avatar';
import NotFound from '../NotFound';
import { PermissionGuard } from '@/components/PermissionGuard';

const { Title } = Typography;

const UserDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { t } = useTranslation("users");
  const { t: tApplications } = useTranslation("applications");
  const { t: tCommon } = useTranslation("common");
  const [assignUserVisible, setAssignUserVisible] = useState(false);

  if (!id) {
    return <NotFound />
  }

  const { data: user, loading: loading, run: runGetUser } = useRequest(async () => {
    if (!id) {
      return null
    }
    return getUser(id)
  }, {
    onError: (error) => {
      message.error(t('detailLoadError', { error, defaultValue: "Failed to load user details: {{error}}" }));
    }
  });

  const appListActionRef = useRef<TableRef<API.Application>>(null);

  if (loading) {
    return (
      <div style={{ textAlign: 'center', padding: '50px' }}>
        <Spin size="large" />
      </div>
    );
  }

  if (!user) {
    return (
      <div style={{ textAlign: 'center', padding: '50px' }}>
        <Title level={4}>{t('notFound', { defaultValue: 'User not found' })}</Title>
        <Button type="primary" onClick={() => navigate('/users')}>
          {t('backToList', { defaultValue: 'Back to List' })}
        </Button>
      </div>
    );
  }

  const getMfaStatus = () => {
    if (user.mfa_enabled) {
      return <Badge status="success" text={t('mfaEnabled', { defaultValue: 'MFA Enabled' })} />
    }
    if (user.mfa_enforced) {
      return <Badge status="warning" text={t('mfaEnforced', { defaultValue: 'MFA Enforced' })} />
    }
    return <Badge status="default" text={t('mfaDisabled', { defaultValue: 'MFA Disabled' })} />
  }

  const renderStatus = (status: string) => {
    switch (status) {
      case 'disabled':
        return <Badge status="default" text={t('statusEnum.disabled', { defaultValue: 'Disabled' })} />;
      case 'password_expired':
        return <Badge status="warning" text={t('statusEnum.password_expired', { defaultValue: 'Password Expired' })} />;
      case 'active':
        return <Badge status="success" text={t('statusEnum.active', { defaultValue: 'Active' })} />;
      case 'locked':
        return <Badge status="error" text={t('statusEnum.locked', { defaultValue: 'Locked' })} />;
      case 'deleted':
        return <Badge status="error" text={t('statusEnum.deleted', { defaultValue: 'Deleted' })} />;
      case 'invalid_ldap_binding':
        return <Badge status="error" text={t('statusEnum.invalid_ldap_binding', { defaultValue: 'Invalid LDAP Binding' })} />;
      default:
        return <Badge status="default" text={t(`statusEnum.${status}`, { defaultValue: status.charAt(0).toUpperCase() + status.slice(1) })} />;
    }
  }


  // Reset user password
  const handleResetPassword = (id: string, username: string, email: string) => {
    Modal.confirm({
      title: t('resetPasswordTitle', { defaultValue: 'Reset Password' }),
      content: t('resetPasswordConfirm', { defaultValue: `Are you sure you want to reset the password for ${username}?`, username }),
      okText: tCommon('confirm', { defaultValue: 'Confirm' }),
      cancelText: tCommon('cancel', { defaultValue: 'Cancel' }),
      onOk: async () => {
        try {
          const res = await resetUserPassword(id);  // Pass an empty password, the backend will generate a random password
          message.success(t('resetPasswordSuccess', { defaultValue: 'Password reset successfully' }));
          if (res.new_password) {
            Modal.info({
              title: t('resetPasswordSuccess', { defaultValue: 'Password Reset Successfully' }),
              content: <Typography.Text copyable={{ text: res.new_password }}>{t('resetPasswordSuccessContent', { defaultValue: `New password: ${res.new_password}`, password: res.new_password })}</Typography.Text>,
            });
          } else {
            Modal.info({
              title: t('resetPasswordSuccess', { defaultValue: 'Password Reset Successfully' }),
              content: t('resetPasswordSuccessSendByEmail', { defaultValue: 'The new password has been sent to the user email: {{email}}', email }),
            });
          }
        } catch (error) {
          console.error('Reset password error:', error);
          message.error(t('resetPasswordError', { defaultValue: 'Failed to reset password' }));
        }
      },
    });
  };

  const appColumns: TableColumnType<API.Application>[] = [
    {
      title: tApplications('name', { defaultValue: 'Name' }),
      key: 'name',
      width: 200,
      render: (_: any, record: API.Application) => (
        <div style={{ display: 'flex', alignItems: 'center', minWidth: 200 }}>
          <Avatar
            size="small"
            icon={<AppstoreOutlined />}
            src={record.icon || undefined}
            style={{ marginRight: 8 }}
          />
          <Link to={`/applications/${record.id}`}>{getApplicationDisplayName(record, i18n.language) || record.name}</Link>
        </div>
      ),
    },
    {
      title: tApplications('description', { defaultValue: 'Description' }),
      dataIndex: 'description',
      key: 'description',
      ellipsis: true,
      responsive: ['sm'],
      render: (_: any, record: API.Application,) => {
        return getApplicationDescription(record, i18n.language) || record.description;
      }
    },
    {
      title: tApplications('uri', { defaultValue: 'URI' }),
      dataIndex: 'uri',
      // width: 300,
      key: 'uri',
      ellipsis: true,
      responsive: ['lg'],
      render: (_: any, record: API.Application) => {
        return <Link to={record.uri} target="_blank">{record.uri}</Link>;
      }
    },
    {
      title: tApplications('status', { defaultValue: 'Status' }),
      dataIndex: 'status',
      width: 120,
      responsive: ['md'],
      key: 'status',
      render: (status: string) => {
        switch (status) {
          case 'active':
            return <Tag color="success">{tApplications('statusEnum.active', { defaultValue: 'Active' })}</Tag>;
          case 'inactive':
            return <Tag color="error">{tApplications('statusEnum.inactive', { defaultValue: 'Inactive' })}</Tag>;
          default:
            return <Tag>{tApplications(`statusEnum.${status}`, { defaultValue: status })}</Tag>;
        }
      },
    },
    {
      title: tApplications('role', { defaultValue: 'Role' }),
      dataIndex: 'role',
      key: 'role',
      render: (role: string) => {
        if (role) {
          return <Tag color="blue" key={role}>{role}</Tag>;
        }
        return <Tag>{t('noRole', { defaultValue: 'No Role' })}</Tag>;
      }
    }
  ];

  return (
    <Card
      title={
        <div style={{ display: 'flex', alignItems: 'center' }}>
          <div><Avatar
            size={48}
            icon={<UserOutlined />}
            src={user.avatar}
            style={{ marginRight: 16 }}
          /></div>
          <div>
            <div style={{ fontSize: 20, fontWeight: 'bold' }}>{user.username}</div>
            <div style={{ color: '#888' }}>{user.email}</div>
          </div>
        </div>
      }
      extra={
        <Space>
          <Button
            icon={<ArrowLeftOutlined />}
            onClick={() => navigate('/users')}
          >
            {tCommon('back', { defaultValue: 'Back' })}
          </Button>
          <PermissionGuard permission="authorization:user:update">
            <Button
              type="primary"
              icon={<EditOutlined />}
              onClick={() => navigate(`/users/${id}/edit`)}
            >
              {tCommon('edit', { defaultValue: 'Edit' })}
            </Button>
          </PermissionGuard>

          <Button
            type="primary"
            icon={<ReloadOutlined />}
            onClick={() => {
              runGetUser()
            }}
          >
            {tCommon('refresh', { defaultValue: 'Refresh' })}
          </Button>
          <PermissionGuard permission="authorization:user:reset-password">
            <Button
              type="primary"
              icon={<UserAddOutlined />}
              onClick={() => {
                handleResetPassword(id, user.username, user.email)
              }}
            >
              {t('resetPassword', { defaultValue: 'Reset Password' })}
            </Button>
          </PermissionGuard>
          <PermissionGuard permission="applications:users:assign">
            <Button
              type="primary"
              icon={<UserAddOutlined />}
              onClick={() => setAssignUserVisible(true)}
            >
              {t('assignApplication', { defaultValue: 'Assign Application' })}
            </Button>
          </PermissionGuard>
        </Space >
      }
    >
      <Space direction="vertical" size="middle" style={{ width: '100%' }}>
        <Descriptions bordered column={{ xs: 1, sm: 1, md: 1, lg: 2, xl: 2, xxl: 2 }} style={{ marginTop: 16 }} labelStyle={{ width: '20%', minWidth: 150 }}>
          <Descriptions.Item label={t('username', { defaultValue: 'Username' })}>{user.username}</Descriptions.Item>
          <Descriptions.Item label={t('fullName', { defaultValue: 'Full Name' })}>{user.full_name}</Descriptions.Item>
          <Descriptions.Item label={t('email', { defaultValue: 'Email' })}>{user.email}</Descriptions.Item>
          <Descriptions.Item label={t('status', { defaultValue: 'Status' })}>
            {renderStatus(user.status)}
          </Descriptions.Item>
          <Descriptions.Item label={t('roles', { defaultValue: 'Roles' })} span={2}>
            {user.roles && user.roles.length > 0 ? (
              user.roles.map(role => (
                <Tag color="blue" key={role.id}>
                  {role.name}
                </Tag>
              ))
            ) : (
              <Tag>{t('noRole', { defaultValue: 'No Role' })}</Tag>
            )}
          </Descriptions.Item>
          <Descriptions.Item label={t('mfa', { defaultValue: 'MFA' })}>
            {getMfaStatus()}
          </Descriptions.Item>
          <Descriptions.Item label={t('createdAt', { defaultValue: 'Created At' })}>{formatDate(user.created_at)}</Descriptions.Item>
          <Descriptions.Item label={t('updatedAt', { defaultValue: 'Updated At' })}>{formatDate(user.updated_at)}</Descriptions.Item>
          <Descriptions.Item label={t('lastLogin', { defaultValue: 'Last Login' })}>
            {user.last_login ? formatDate(user.last_login) : t('neverLogin', { defaultValue: 'Never' })}
          </Descriptions.Item>
        </Descriptions>
        <Divider >{t('assignedApplications', { defaultValue: 'Assigned Applications' })}</Divider>
        <Table<API.Application>
          rowKey="id"
          size="small"
          request={async ({ current, page_size }) => {
            return getUserApplications(id, current, page_size)
          }}
          columns={appColumns}
          actionRef={appListActionRef}
        />
      </Space>
      <AssignUserModel
        id={id || ''}
        visible={assignUserVisible}
        setVisible={setAssignUserVisible}
        onSuccess={() => {
          appListActionRef.current?.reload()
        }}
      />
    </Card >
  );
};

export default UserDetail; 