import React, { useRef, useState } from 'react';
import {
  Card,
  Button,
  Tag,
  Space,
  Input,
  Row,
  Col,
  Form,
  Select,
  Tooltip,
  message,
  Badge,
  Typography,
  Modal,
  TableColumnType,
} from 'antd';
import {
  SearchOutlined,
  ReloadOutlined,
  UserAddOutlined,
  EditOutlined,
  DeleteOutlined,
  UserOutlined,
  EyeOutlined,
  KeyOutlined,
  ToolOutlined,
  UndoOutlined,
  UnlockOutlined,
} from '@ant-design/icons';
import { Link, useNavigate } from 'react-router-dom';
import { PermissionGuard } from '@/components/PermissionGuard';
import { getUsers, deleteUser, resetUserPassword, restoreUser, unlockUser } from '@/api/user';
import { formatDate } from '@/utils';
import { useTranslation } from 'react-i18next';
import { useRequest } from 'ahooks';
import Avatar from '@/components/Avatar';
import Actions from '@/components/Actions';
import Table, { TableRef } from '@/components/Table';
import { createStyles } from 'antd-style';
import FixUserModal from './components/FixUserModal';
const { Option } = Select;

const useStyles = createStyles(({ token, css }) => ({
  nameColumn: css`
      @media (min-width: ${token.screenLG}px) {
        display: none;
      }
      padding: 8px 16px!important;
      display: table-cell;
  `,
  mfaColumn: css`
    @media (min-width: 1366px) {
      display: table-cell;
    }
    display: none;
  `,
}));

// User list page
const UserList: React.FC = () => {
  const navigate = useNavigate();
  const { t } = useTranslation("users");
  const { t: tCommon } = useTranslation("common");
  const [searchForm] = Form.useForm();
  const { styles } = useStyles();
  // Data state
  const tableRef = useRef<TableRef<API.User>>(null);

  const [fixUser, setFixUser] = useState<API.User | null>(null);
  // Query parameters
  const queryParams = useRef({
    keywords: undefined,
    status: undefined,
    source: 'ldap',
  });


  // Search form submission
  const handleSearch = (values: any) => {
    queryParams.current = {
      keywords: values.keywords,
      status: values.status,
      source: values.source,
    };
    tableRef.current?.setPagination((prev) => {
      return {
        ...prev,
        current: 1,
      }
    });

  };

  // Reset search form
  const handleReset = () => {
    queryParams.current = {
      keywords: undefined,
      status: undefined,
      source: 'ldap',
    };
    searchForm.resetFields();
    tableRef.current?.reset()
  };


  // Restore user
  const { run: handleRestore } = useRequest(restoreUser, {
    onSuccess: () => {
      message.success(t('restoreSuccess', { defaultValue: 'User restored successfully' }));
      tableRef.current?.reload()
    },
    onError: (error) => {
      message.error(t('restoreError', { defaultValue: 'Failed to restore user', error: error.message }));
    },
    manual: true,
  });

  // Delete user
  const { run: handleDelete } = useRequest(deleteUser, {
    onSuccess: () => {
      message.success(t('deleteSuccess', { defaultValue: 'User deleted successfully' }));
      tableRef.current?.reload()
    },
    onError: (error) => {
      message.error(t('deleteError', { defaultValue: 'Failed to delete user', error: error.message }));
    },
    manual: true,
  });

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

  // Unlock user
  const handleUnlock = (id: string) => {
    Modal.confirm({
      title: t('user.unlockTitle', { defaultValue: 'Unlock User' }),
      content: t('user.unlockConfirm', { defaultValue: 'Are you sure you want to unlock this user?' }),
      okText: tCommon('confirm', { defaultValue: 'Confirm' }),
      cancelText: tCommon('cancel', { defaultValue: 'Cancel' }),
      onOk: async () => {
        try {
          await unlockUser(id);
          message.success(t('user.unlockSuccess', { defaultValue: 'User unlocked successfully' }));
          tableRef.current?.reload()
        } catch (error) {
          message.error(t('user.unlockError', { defaultValue: 'Failed to unlock user: {{error}}', error: (error as any).message ?? String(error) }));
        }
      },
    });
  };


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
  // Build table columns
  const columns: TableColumnType<API.User>[] = [
    {
      title: t('username', { defaultValue: 'Username' }),
      key: 'username',
      render: (_: any, record: API.User) => (
        <div style={{ display: 'flex', alignItems: 'center' }}>
          <Avatar
            size="small"
            icon={<UserOutlined />}
            src={record.avatar}
            style={{ marginRight: 8 }}
          />
          <Link to={`/users/${record.id}`}>{record.username}</Link>
        </div>
      ),
      responsive: ['lg'],
    },
    {
      title: t('fullName', { defaultValue: 'Full Name' }),
      dataIndex: 'full_name',
      key: 'full_name',
      responsive: ['lg'],
    },
    {
      title: t('username', { defaultValue: 'Username' }),
      dataIndex: 'username',
      key: 'name',
      className: styles.nameColumn,
      render: (_: any, record: API.User) => {
        return (<div style={{ display: 'block', alignItems: 'center' }}>
          <Link to={`/users/${record.id}`}>{record.username}</Link>
          <div style={{ color: 'rgba(0,0,0,0.65)' }}>{record.full_name}</div>
        </div>)
      }
    },
    {
      title: t('email', { defaultValue: 'Email' }),
      dataIndex: 'email',
      key: 'email',
    },
    {
      title: t('source', { defaultValue: 'Source' }),
      dataIndex: 'source',
      key: 'source',
      responsive: ['xl'],
      render: (source: string, record: API.User) => {
        if (record.status === 'invalid_ldap_binding') {
          return <Tooltip title={t('invalidLdapBindingRelationship', { defaultValue: 'Invalid LDAP binding relationship: {{ldap_dn}}', ldap_dn: record.ldap_dn })}>
            <Tag color="red">{t('sourceLdap', { defaultValue: 'LDAP' })}</Tag>
          </Tooltip>;
        }
        switch (source) {
          case 'ldap':
            if (!record.ldap_dn) {
              return <Tooltip title={t('ldapUserDNNotSet', { defaultValue: 'LDAP User DN is not set, please fix it.' })}>
                <Tag color="red">{t('sourceLdap', { defaultValue: 'LDAP' })}</Tag>
              </Tooltip>;
            }
            return <Tag color="blue">{t('sourceLdap', { defaultValue: 'LDAP' })}</Tag>;
          case 'oauth2':
            return <Tag color="green">{t('sourceOauth2', { defaultValue: 'OAuth2' })}</Tag>;
          case 'local':
            return <Tag color="default">{t('sourceLocal', { defaultValue: 'Local' })}</Tag>;
          default:
            return <Tooltip title={t('sourceUnknown', { defaultValue: 'Source is unknown, please fix it.' })}>
              <Tag color="red">{source}</Tag>
            </Tooltip>;
        }
      },
    },
    {
      title: t('status', { defaultValue: 'Status' }),
      dataIndex: 'status',
      key: 'status',
      responsive: ['lg'],
      render: renderStatus,
    },
    {
      title: t('roles', { defaultValue: 'Roles' }),
      dataIndex: 'roles',
      key: 'roles',
      responsive: ['xxl'],
      render: (roles: any[]) => (
        <span>
          {roles && roles.length > 0 ? (
            roles.map(role => (
              <Tag color="blue" key={role.id}>
                {role.name}
              </Tag>
            ))
          ) : (
            <Tag>{t('noRole', { defaultValue: 'No Role' })}</Tag>
          )}
        </span>
      ),
    },
    {
      title: t('mfa', { defaultValue: 'MFA' }),
      dataIndex: 'mfa_enabled',
      key: 'mfa_enabled',
      className: styles.mfaColumn,
      render: (mfa_enabled: boolean) => {
        return mfa_enabled ? (
          <Badge status="success" text={t('mfaEnabled', { defaultValue: 'Enabled' })} />
        ) : (
          <Badge status="default" text={t('mfaDisabled', { defaultValue: 'Disabled' })} />
        );
      },
    },
    {
      title: t('lastLogin', { defaultValue: 'Last Login' }),
      dataIndex: 'last_login',
      key: 'last_login',
      responsive: ['xxl'],
      render: (last_login: string) => (
        last_login ? formatDate(last_login) : t('neverLogin', { defaultValue: 'Never' })
      ),
    },
    {
      title: tCommon('actions', { defaultValue: 'Actions' }),
      key: 'action',
      render: (_: any, record: API.User) => {
        const actions = [{
          key: "view",
          permission: "authorization:user:view",
          icon: <EyeOutlined />,
          tooltip: t('viewDetail', { defaultValue: 'View Detail' }),
          onClick: () => navigate(`/users/${record.id}`),
        }, {
          key: "edit",
          permission: "authorization:user:update",
          icon: <EditOutlined />,
          tooltip: t('edit', { defaultValue: 'Edit' }),
          hidden: record.status === 'locked' || record.status === 'deleted',
          onClick: () => navigate(`/users/${record.id}/edit`),
        }, {
          key: "unlock",
          permission: "authorization:user:update",
          icon: <UnlockOutlined />,
          tooltip: t('unlock', { defaultValue: 'Unlock' }),
          hidden: record.status !== 'locked',
          onClick: () => handleUnlock(record.id),
        }, {
          key: "resetPassword",
          permission: "authorization:user:resetPassword",
          icon: <KeyOutlined />,
          tooltip: t('resetPassword', { defaultValue: 'Reset Password' }),
          hidden: (!(record.source === 'local' || (record.source === 'ldap' && record.ldap_dn)) || record.status === 'invalid_ldap_binding') || record.status === 'deleted',
          onClick: () => handleResetPassword(record.id, record.username, record.email),
        }, {
          key: "fixUser",
          permission: "authorization:user:update",
          icon: <ToolOutlined />,
          tooltip: t('fixUser', { defaultValue: 'Fix User' }),
          hidden: !(((record.source === 'ldap' && !record.ldap_dn) || (record.status === 'invalid_ldap_binding'))),
          onClick: () => setFixUser(record),
        }, {
          key: "restore",
          permission: "authorization:user:update",
          icon: <UndoOutlined />,
          tooltip: t('restore', { defaultValue: 'Restore' }),
          hidden: record.status !== 'deleted',
          confirm: {
            title: t('restoreConfirm', { defaultValue: 'Are you sure you want to restore this user?' }),
            onConfirm: () => handleRestore(record.id),
          }
        }, {
          key: "delete",
          permission: "authorization:user:delete",
          icon: <DeleteOutlined />,
          tooltip: t('delete', { defaultValue: 'Delete' }),
          danger: true,
          confirm: {
            title: t('deleteConfirm', { defaultValue: 'Are you sure you want to delete this user?', username: record.username }),
            onConfirm: () => handleDelete(record.id),
            okText: tCommon('confirm', { defaultValue: 'Confirm' }),
            cancelText: tCommon('cancel', { defaultValue: 'Cancel' }),
          }

        }]
        return <div style={{ minWidth: 120 }}>
          <Actions actions={actions} />
        </div>
      },
    },
  ];

  return (
    <div>
      <Card style={{ marginBottom: 16 }}>
        <Form
          form={searchForm}
          layout="inline"
          onFinish={handleSearch}
          style={{ marginBottom: 16 }}
        >
          <Row gutter={[16, 16]} style={{ width: '100%' }}>
            <Col xs={{ span: 24 }} sm={{ span: 24 }} md={{ span: 10 }} lg={{ span: 6 }}>
              <Form.Item name="keywords">
                <Input
                  prefix={<SearchOutlined />}
                  placeholder={t('keywords', { defaultValue: 'Search by username, full name, or email' })}
                  allowClear
                />
              </Form.Item>
            </Col>
            <Col xs={{ span: 24 }} sm={{ span: 12 }} md={{ span: 7 }} lg={{ span: 6 }}>
              <Form.Item name="status">
                <Select
                  placeholder={t('status', { defaultValue: 'Status' })}
                  allowClear
                  style={{ width: '100%' }}
                >
                  <Option value="active">{t('statusEnum.active')}</Option>
                  <Option value="disabled">{t('statusEnum.disabled')}</Option>
                  <Option value="deleted">{t('statusEnum.deleted')}</Option>
                  <Option value="locked">{t('statusEnum.locked')}</Option>
                  <Option value="password_expired">{t('statusEnum.password_expired')}</Option>
                </Select>
              </Form.Item>
            </Col>
            <Col xs={{ span: 24 }} sm={{ span: 12 }} md={{ span: 7 }} lg={{ span: 6 }}>
              <Form.Item name="source">
                <Select defaultValue={"ldap"}>
                  <Option value="ldap">{t('sourceLdap', { defaultValue: 'LDAP' })}</Option>
                  <Option value="all">{t('sourceALL', { defaultValue: 'ALL' })}</Option>
                </Select>
              </Form.Item>
            </Col>
            <Col xs={{ span: 24 }} sm={{ span: 24 }} md={{ span: 24 }} lg={{ span: 6 }} style={{ textAlign: 'right' }}>
              <Space>
                <Button
                  type="primary"
                  icon={<SearchOutlined />}
                  htmlType="submit"
                >
                  {tCommon('search', { defaultValue: 'Search' })}
                </Button>
                <Button
                  icon={<ReloadOutlined />}
                  onClick={handleReset}
                >
                  {tCommon('reset', { defaultValue: 'Reset' })}
                </Button>
              </Space>
            </Col>
          </Row>
        </Form>
      </Card>
      <Card>
        <Row justify="space-between" align="middle" gutter={[0, 16]}>
          <Col>
            <Button type='primary' icon={<ReloadOutlined />} onClick={() => tableRef.current?.reload()}>{tCommon('refresh', { defaultValue: 'Refresh' })}</Button>
          </Col>
          <Col>
            <PermissionGuard permission="authorization:user:create">
              <Button
                type="primary"
                icon={<UserAddOutlined />}
                style={{ marginBottom: 16 }}
                onClick={() => navigate('/users/create')}
              >
                {t('create', { defaultValue: 'Create User' })}
              </Button>
            </PermissionGuard>
          </Col>
        </Row>

        <Table<API.User>
          columns={columns}
          request={async ({ current, page_size }) => {
            try {
              return await getUsers(queryParams.current.keywords, queryParams.current.status, current, page_size)
            } catch (error) {
              message.error(t('loadError', { defaultValue: 'Failed to load users', error: error }));
              return Promise.reject(error);
            }
          }}
          actionRef={tableRef}
        />
      </Card>
      <FixUserModal user={fixUser} onClose={() => setFixUser(null)} onSuccess={() => {
        setFixUser(null)
        tableRef.current?.reload()
      }} />
    </div>
  );
};

export default UserList;