import React, { useEffect, useState } from 'react';
import { Button, Card, message, Space, Tag, Tabs, Table, Descriptions, Typography, Badge, Empty, Popconfirm, Tooltip } from 'antd';
import { useLocation, useNavigate, useParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { TeamOutlined, EditOutlined, ArrowLeftOutlined, KeyOutlined, DeleteOutlined, PlusOutlined, ReloadOutlined } from '@ant-design/icons';
import { getApplication, deleteApplicationKey, removeUserFromApplication, deleteApplicationRole, getApplicationKeys, getApplicationIssuerKeys, deleteApplicationIssuerKey } from '@/api/application';
import { PermissionGuard } from '@/components/PermissionGuard';
import { usePermission } from '@/hooks/usePermission';
import { formatDate, getApplicationDisplayName, getApplicationDescription } from '@/utils';
import { useRequest } from 'ahooks';
import CreateAccessKeyModel from './components/CreateAccessKeyModel';
import AssignUserModel from './components/AssignUserModel';
import RoleFormModel from './components/RoleFormModel';
import CreateIssuerKeyModel from './components/CreateIssuerKeyModel';

const { TabPane } = Tabs;

const ApplicationDetail: React.FC = () => {
  const { hasPermission } = usePermission();
  const { t, i18n } = useTranslation("applications");
  const { t: tUser } = useTranslation("users");
  const { t: tCommon } = useTranslation("common");
  console.log(i18n.language)
  const navigate = useNavigate();
  const { id } = useParams<{ id: string }>();
  const location = useLocation();
  const hash = location.hash;
  const tab = hash.replace('#', '');
  const defaultActiveKey = tab || 'basic';

  const [createKeyModalVisible, setCreateKeyModalVisible] = useState(false);
  const [keys, setKeys] = useState<API.ApplicationKey[]>([]);
  const [createIssuerKeyModalVisible, setCreateIssuerKeyModalVisible] = useState(false);
  const [issuerKeys, setIssuerKeys] = useState<API.ApplicationIssuerKey[]>([]);

  const [users, setUsers] = useState<API.ApplicationUser[]>([]);
  const [assignUserModalVisible, setAssignUserModalVisible] = useState(false);

  const [roles, setRoles] = useState<API.ApplicationRole[]>([]);
  const [roleModalVisible, setRoleModalVisible] = useState(false);
  const [currentRole, setCurrentRole] = useState<API.ApplicationRole | null>(null);


  const { run: fetchApplication, data: application, loading } = useRequest(async () => {
    return await getApplication(id!);
  }, {
    onSuccess: (data) => {
      setUsers(data.users || []);
      setRoles(data.roles || []);
    },
    onError: (error) => {
      message.error(t('detail.fetch_error', { defaultValue: 'Failed to fetch application details: {{error}}', error }));
    }
  })


  const { run: fetchApplicationKeys } = useRequest(async () => {
    if (!hasPermission('applications:keys:view')) {
      return [];
    }
    return await getApplicationKeys(id!);
  }, {
    onSuccess: (data) => {
      setKeys(data);
    },
    onError: (error) => {
      message.error(t('detail.fetch_error', { defaultValue: 'Failed to fetch application keys: {{error}}', error }));
    },
  });

  const { run: fetchIssuerKeys } = useRequest(async () => {
    if (!hasPermission('applications:issuer-keys:view')) {
      return [];
    }
    return await getApplicationIssuerKeys(id!);
  }, {
    onSuccess: (data) => {
      setIssuerKeys(data);
    },
    onError: (error) => {
      message.error(t('detail.fetch_error', { defaultValue: 'Failed to fetch issuer keys: {{error}}', error }));
    },
  });

  const { run: handleDeleteRole } = useRequest(async (roleId: string) => {
    return await deleteApplicationRole(id!, roleId);
  }, {
    onSuccess: () => {
      message.success(t('deleteRoleSuccess', { defaultValue: 'Role deleted successfully' }));
      fetchApplication();
    },
    onError: (error) => {
      message.error(t('deleteRoleError', { defaultValue: 'Failed to delete role: {{error}}', error }));
    },
    manual: true
  });


  // Delete key
  const { run: handleDeleteKey } = useRequest(async (keyId: string) => {
    return await deleteApplicationKey(id!, keyId);
  }, {
    onSuccess: () => {
      message.success(t('deleteKeySuccess', { defaultValue: 'Key deleted successfully' }));
      fetchApplicationKeys();
    },
    onError: (error) => {
      message.error(t('deleteKeyError', { defaultValue: 'Failed to delete key: {{error}}', error }));
    },
    manual: true
  });

  const { run: handleDeleteIssuerKey } = useRequest(async (keyId: string) => {
    return await deleteApplicationIssuerKey(id!, keyId);
  }, {
    onSuccess: () => {
      message.success(t('deleteIssuerKeySuccess', { defaultValue: 'Issuer key deleted successfully' }));
      fetchIssuerKeys();
    },
    onError: (error) => {
      message.error(t('deleteIssuerKeyError', { defaultValue: 'Failed to delete issuer key: {{error}}', error }));
    },
    manual: true
  });


  // Open edit role modal
  const handleEditRole = (role: API.ApplicationRole) => {
    setCurrentRole(role);
    setRoleModalVisible(true);
  };

  // Remove user
  const handleRemoveUser = async (userId: string) => {
    try {
      await removeUserFromApplication(id!, userId);
      message.success(t('userRemoveSuccess', { defaultValue: 'User removed successfully' }));
      setUsers(prev => prev.filter(user => user.id !== userId));
    } catch (error) {
      message.error(t('userRemoveError', { defaultValue: 'Failed to remove user: {{error}}', error }));
    }
  };



  // Role list column definition
  const roleColumns = [
    {
      title: t('roleName', { defaultValue: 'Role Name' }),
      dataIndex: 'name',
      key: 'name',
    },
    {
      title: t('roleDescription', { defaultValue: 'Description' }),
      dataIndex: 'description',
      key: 'description',
    },
    {
      title: t('roleCreatedAt', { defaultValue: 'Created At' }),
      dataIndex: 'created_at',
      key: 'created_at',
      render: (date: string) => formatDate(date),
    },
    {
      title: tCommon('actions', { defaultValue: 'Actions' }),
      key: 'action',
      render: (_: any, record: API.ApplicationRole) => (
        <Space>
          <PermissionGuard permission="applications:role:update">
            <Button
              type="text"
              icon={<EditOutlined />}
              onClick={() => handleEditRole(record)}
            />
          </PermissionGuard>
          <PermissionGuard permission="applications:role:delete">
            <Popconfirm
              title={t('deleteRoleConfirm', { defaultValue: 'Are you sure to delete role {{role}}?', role: record.name })}
              onConfirm={() => handleDeleteRole(record.id)}
              okText={tCommon('confirm', { defaultValue: 'Confirm' })}
              cancelText={tCommon('cancel', { defaultValue: 'Cancel' })}
            >
              <Button
                type="text"
                danger
                icon={<DeleteOutlined />}
              />
            </Popconfirm>
          </PermissionGuard>
        </Space>
      ),
    },
  ];

  const issuerKeysColumns = [
    {
      title: t('keyName', { defaultValue: 'Key Name' }),
      dataIndex: 'name',
      key: 'name',
    },
    {
      title: t('keyAlgorithm', { defaultValue: 'Algorithm' }),
      dataIndex: 'algorithm',
      key: 'algorithm',
    },
    {
      title: t('keyCreatedAt', { defaultValue: 'Created At' }),
      dataIndex: 'created_at',
      key: 'created_at',
      render: (date: string) => formatDate(date),
    },
    {
      title: tCommon('actions', { defaultValue: 'Actions' }),
      key: 'action',
      render: (_: any, record: API.ApplicationIssuerKey) => (
        <Space>
          <PermissionGuard permission="applications:issuer-keys:delete">
            <Popconfirm
              title={t('deleteKeyConfirm', { defaultValue: 'Are you sure to delete key {{name}}?', name: record.name ? record.name : record.id })}
              onConfirm={() => handleDeleteIssuerKey(record.id)}
              okText={tCommon('confirm', { defaultValue: 'Confirm' })}
              cancelText={tCommon('cancel', { defaultValue: 'Cancel' })}
            >
              <Button
                type="text"
                danger
                icon={<DeleteOutlined />}
              />
            </Popconfirm>
          </PermissionGuard>
        </Space>
      ),
    },
  ]

  // Access key list column definition
  const accessKeysColumns = [
    {
      title: t('keyName', { defaultValue: 'Key Name' }),
      dataIndex: 'name',
      key: 'name',
    },
    {
      title: t('clientId', { defaultValue: 'Client ID' }),
      dataIndex: 'client_id',
      key: 'client_id',
      render: (key: string) => (
        <Typography.Text copyable>{key}</Typography.Text>
      ),
    },
    {
      title: t('keyExpiresAt', { defaultValue: 'Expires At' }),
      dataIndex: 'expires_at',
      key: 'expires_at',
      render: (date: string) => {
        if (date) {
          return formatDate(date)
        }
        return <Tag color="blue">{t('keyNeverExpires', { defaultValue: 'Never' })}</Tag>;
      },
    },
    {
      title: t('keyCreatedAt', { defaultValue: 'Created At' }),
      dataIndex: 'created_at',
      key: 'created_at',
      render: (date: string) => formatDate(date),
    },
    {
      title: tCommon('actions', { defaultValue: 'Actions' }),
      key: 'action',
      render: (_: any, record: API.ApplicationKey) => (
        <Space>
          <PermissionGuard permission="applications:keys:delete">
            <Popconfirm
              title={t('deleteKeyConfirm', { defaultValue: 'Are you sure to delete key {{name}}?', name: record.name ? record.name : record.client_id })}
              onConfirm={() => handleDeleteKey(record.id)}
              okText={tCommon('confirm')}
              cancelText={tCommon('cancel')}
            >
              <Button
                type="text"
                danger
                icon={<DeleteOutlined />}
              />
            </Popconfirm>
          </PermissionGuard>
        </Space>
      ),
    },
  ];

  // User list column definition
  const userColumns = [
    {
      title: tUser('username', { defaultValue: 'Username' }),
      dataIndex: 'username',
      key: 'username',
      render: (username: string, item: API.ApplicationUser) => {
        const name = item.full_name ? `${item.full_name} (${username})` : username
        if (item.source === "ldap") {
          if (item.id) {
            return <Space>
              {name}
              <Tag color="blue">{tUser('sourceLdap', { defaultValue: 'LDAP' })}</Tag>
            </Space>
          } else {
            return <Space>
              {name}
              <Tooltip title={tUser('ldapUserNotBound', { defaultValue: 'LDAP User is not bound to any local user, please bind it.', })}>
                <Tag color="red">{tUser('sourceLdap', { defaultValue: 'LDAP' })}</Tag>
              </Tooltip>
            </Space>
          }
        }
        return name
      },
    },
    {
      title: tUser('email', { defaultValue: 'Email' }),
      dataIndex: 'email',
      key: 'email',
    },
    {
      title: tUser('status', { defaultValue: 'Status' }),
      dataIndex: 'status',
      key: 'status',
      render: (status: string) => {
        switch (status) {
          case 'disabled':
            return <Badge status="default" text={tUser('statusEnum.disabled', { defaultValue: 'Disabled' })} />;
          case 'password_expired':
            return <Badge status="warning" text={tUser('statusEnum.password_expired', { defaultValue: 'Password Expired' })} />;
          case 'active':
            return <Badge status="success" text={tUser('statusEnum.active', { defaultValue: 'Active' })} />;
          case 'locked':
            return <Badge status="warning" text={tUser('statusEnum.locked', { defaultValue: 'Locked' })} />;
          case 'deleted':
            return <Badge status="error" text={tUser('statusEnum.deleted', { defaultValue: 'Deleted' })} />;
          default:
            return <Badge status="default" text={tUser(`statusEnum.${status}`, { defaultValue: status.charAt(0).toUpperCase() + status.slice(1) })} />;
        }
      },
    },
    {
      title: t('userRoles'),
      dataIndex: 'role',
      key: 'role',
      render: (role: string, item: API.ApplicationUser) => {
        if (role) {
          return <Tag color="green" key={item.role_id}>{role}</Tag>
        }
        return <Tag key={item.role_id}>{t('noRole')}</Tag>
      },
    },
    {
      title: tCommon('actions', { defaultValue: 'Actions' }),
      key: 'action',
      render: (_: any, record: API.ApplicationUser) => (
        <Space>
          <PermissionGuard permission="applications:users:unassign">
            <Popconfirm
              title={t('userRemoveConfirm', { defaultValue: 'Are you sure to remove user {{user}} from this application?', user: record.username })}
              onConfirm={() => handleRemoveUser(record.id)}
              okText={tCommon('confirm', { defaultValue: 'Confirm' })}
              cancelText={tCommon('cancel', { defaultValue: 'Cancel' })}
            >
              <Button
                type="text"
                danger
                icon={<DeleteOutlined />}
              />
            </Popconfirm>
          </PermissionGuard>
        </Space>
      ),
    },
  ];

  const [currentTab, setCurrentTab] = useState<'roles' | 'accessKeys' | 'users' | 'issuerKeys'>(defaultActiveKey as 'roles' | 'accessKeys' | 'users' | 'issuerKeys');
  const [tabExtraContent, setTabExtraContent] = useState<React.ReactNode>(null);


  useEffect(() => {
    switch (currentTab) {
      case 'roles':
        setTabExtraContent(<PermissionGuard permission="applications:role:create" key="create-role">
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => setRoleModalVisible(true)}
          >
            {t('createRole')}
          </Button>
        </PermissionGuard>)
        break;
      case 'accessKeys':
        setTabExtraContent(<Space>
          <PermissionGuard key="create-key" permission="applications:keys:create">
            <Button
              type="primary"
              icon={<KeyOutlined />}
              onClick={() => setCreateKeyModalVisible(true)}
              disabled={keys.length >= 10}
              title={keys.length >= 10 ? t('keyCountLimitReached', { defaultValue: "key count limit reached" }) : undefined}
            >
              {t('createKey')}
            </Button>
          </PermissionGuard>
          <Button
            type="primary"
            icon={<ReloadOutlined />}
            onClick={() => fetchApplicationKeys()}
          >
            {t('refresh')}
          </Button>
        </Space>)
        break;
      case 'users':
        setTabExtraContent(
          <PermissionGuard permission="applications:users:assign">
            <Button
              type="primary"
              icon={<TeamOutlined />}
              onClick={() => setAssignUserModalVisible(true)}
            >
              {t('assignUser')}
            </Button>
          </PermissionGuard>)
        break
      case 'issuerKeys':
        setTabExtraContent(
          <Space>
            <PermissionGuard permission="applications:issuer-keys:create">
              <Button
                type="primary"
                icon={<KeyOutlined />}
                onClick={() => setCreateIssuerKeyModalVisible(true)}
                disabled={issuerKeys.length >= 10}
                title={issuerKeys.length >= 10 ? t('keyCountLimitReached', { defaultValue: "key count limit reached" }) : undefined}
              >
                {t('createIssuerKey')}
              </Button>
            </PermissionGuard>
            <Button
              type="primary"
              icon={<ReloadOutlined />}
              onClick={() => fetchIssuerKeys()}
            >
              {t('refresh')}
            </Button>
          </Space>
        )
        break
      default:
        setTabExtraContent(null)
    }
  }, [currentTab])


  return (
    <div>
      {(!loading && !application) ? <Empty /> : <Card
        loading={loading}
        title={
          <div style={{ display: 'flex', alignItems: 'center', marginBottom: 16 }}>
            <div>
              <div style={{ fontSize: 20, fontWeight: 'bold' }}>{application?.name}</div>
              <div style={{ color: '#888', fontWeight: 'normal' }}>{<Typography.Text
                style={{ width: '50vw' }}
                ellipsis={{
                  tooltip: true,
                }}
              >
                {getApplicationDescription(application, i18n.language)}
              </Typography.Text>}
              </div>
            </div>
          </div>
        }
        extra={
          <Space>
            <Button
              icon={<ArrowLeftOutlined />}
              onClick={() => navigate('/applications')}
            >
              {tCommon('back', { defaultValue: 'Back' })}
            </Button>
            <Button
              type="primary"
              icon={<EditOutlined />}
              onClick={() => navigate(`/applications/${id}/edit`)}
            >
              {tCommon('edit', { defaultValue: 'Edit' })}
            </Button>
            <Button
              type="primary"
              icon={<ReloadOutlined />}
              onClick={() => {
                fetchApplication()
              }}
            >
              {tCommon('refresh', { defaultValue: 'Refresh' })}
            </Button>
          </Space>
        }
      >

        <Tabs
          defaultActiveKey={defaultActiveKey}
          onChange={(key) => {
            setCurrentTab(key as 'roles' | 'accessKeys' | 'users' | 'issuerKeys');
            navigate(`/applications/${id}#${key}`);
          }}
          tabBarExtraContent={tabExtraContent}
        >
          <TabPane tab={t('basicInfo', { defaultValue: 'Basic Info' })} key="basic">
            <Descriptions bordered column={{ xs: 1, sm: 1, md: 1, lg: 2, xl: 2, xxl: 2 }} style={{ marginTop: 16 }} labelStyle={{ width: '20%', minWidth: 150 }}>
              <Descriptions.Item label={t('name', { defaultValue: 'Name' })}>{getApplicationDisplayName(application, i18n.language)}</Descriptions.Item>
              <Descriptions.Item label={t('status', { defaultValue: 'Status' })}>
                {application?.status === 'active' ? (
                  <Badge status="success" text={t('statusEnum.active', { defaultValue: 'Active' })} />
                ) : (
                  <Badge status="error" text={t(`statusEnum.${application?.status}`, { defaultValue: `${application?.status?.charAt(0)?.toUpperCase()}${application?.status?.slice(1)}` })} />
                )}
              </Descriptions.Item>
              <Descriptions.Item label={t('description', { defaultValue: 'Description' })} span={2}>
                {getApplicationDescription(application, i18n.language)}
              </Descriptions.Item>
              <Descriptions.Item label={t('grantTypes', { defaultValue: 'Grant Types' })} span={2}>
                <Space>
                  {application?.grant_types?.map((type: string) => (
                    <Tag color="blue" key={type}>
                      {type}
                    </Tag>
                  ))}
                </Space>
              </Descriptions.Item>
              <Descriptions.Item label={t('uri', { defaultValue: 'URI' })} span={2}>
                <Typography.Text copyable={application?.uri ? true : false}>{application?.uri}</Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label={t('redirectUris', { defaultValue: 'Redirect URIs' })} span={2}>
                <Space direction="vertical" style={{ width: '100%' }}>
                  {application?.redirect_uris?.map((uri: string) => (
                    <Typography.Text key={uri} copyable>{uri}</Typography.Text>
                  ))}
                </Space>
              </Descriptions.Item>
              <Descriptions.Item label={t('scopes', { defaultValue: 'Scopes' })} span={2}>
                <Space>
                  {application?.scopes?.map(scope => (
                    <Tag color="green" key={scope}>
                      {scope}
                    </Tag>
                  ))}
                </Space>
              </Descriptions.Item>
              <Descriptions.Item label={t('createdAt', { defaultValue: 'Created At' })}>
                {formatDate(application?.created_at)}
              </Descriptions.Item>
              <Descriptions.Item label={t('updatedAt', { defaultValue: 'Updated At' })}>
                {formatDate(application?.updated_at)}
              </Descriptions.Item>
            </Descriptions>
          </TabPane>

          <TabPane tab={t('roles', { defaultValue: 'Roles' })} key="roles">
            <Table
              columns={roleColumns}
              dataSource={roles}
              rowKey="id"
            />
          </TabPane>

          <TabPane tab={t('accessKeys', { defaultValue: 'Access Keys' })} disabled={!hasPermission('applications:keys:view')} key="accessKeys">
            <Table
              columns={accessKeysColumns}
              dataSource={keys}
              rowKey="id"
            />
          </TabPane>

          <TabPane tab={t('issuerKeys', { defaultValue: 'Issuer Keys' })} disabled={!hasPermission('applications:issuer-keys:view')} key="issuerKeys">
            <Table
              columns={issuerKeysColumns}
              dataSource={issuerKeys}
              rowKey="id"
            />
          </TabPane>
          <TabPane tab={t('users', { defaultValue: 'Users' })} key="users">
            <Table
              columns={userColumns}
              dataSource={users}
              rowKey="id"
            />
          </TabPane>
        </Tabs>
      </Card>}
      {/* Create access key modal */}
      <CreateAccessKeyModel
        visible={createKeyModalVisible}
        setVisible={setCreateKeyModalVisible}
        id={id!}
        onSuccess={() => fetchApplicationKeys()}
      />

      {/* Edit/create role modal */}
      <RoleFormModel
        visible={roleModalVisible}
        setVisible={(visible) => {
          setRoleModalVisible(visible)
          if (!visible) {
            setCurrentRole(null)
          }
        }}
        id={id!}
        currentRole={currentRole}
        onSuccess={fetchApplication}
      />

      {/* Assign user modal */}
      <AssignUserModel
        visible={assignUserModalVisible}
        setVisible={setAssignUserModalVisible}
        id={id!}
        currentUser={users}
        roles={roles}
        onSuccess={fetchApplication}
      />

      {/* Create issuer key modal */}
      <CreateIssuerKeyModel
        visible={createIssuerKeyModalVisible}
        setVisible={setCreateIssuerKeyModalVisible}
        id={id!}
        onSuccess={() => fetchIssuerKeys()}
      />
    </div>
  );
};

export default ApplicationDetail; 