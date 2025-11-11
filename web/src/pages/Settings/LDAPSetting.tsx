import React, { useEffect, useState } from 'react';
import { Form, Input, Switch, Button, message, Modal, Spin, Steps, Skeleton, Descriptions, Divider, Tag, Table, Select } from 'antd';
import { useTranslation } from 'react-i18next';
import { getLDAPSettings, updateLDAPSettings, testLDAPConnection, importLDAPUsers, importLDAPApplications } from '@/api/system';
import { useRequest } from 'ahooks';
import { PermissionGuard } from '@/components/PermissionGuard';
import { CheckCircleTwoTone, LoadingOutlined } from '@ant-design/icons';
import { ColumnType } from 'antd/es/table';


interface ImportColumnType<T extends { imported: boolean, ldap_dn: string }> extends Omit<ColumnType<T>, 'render'> {
  render?: (value: any, record: T, index: number, loading: boolean) => React.ReactNode;
}

const ImportLDAPEntryModal = <T extends { imported: boolean, ldap_dn: string }>({ fetchItems, importItems, columns, ...props }: {
  visible: boolean,
  onCancel: () => void,
  fetchItems: () => Promise<T[]>,
  importItems: (dn: string[]) => Promise<T[]>,
  columns: ImportColumnType<T>[],
}) => {
  const { t } = useTranslation('system');
  const [items, setItems] = useState<T[]>([]);

  const [checkedList, setCheckedList] = useState<string[]>([]);


  const { run: loadItems, loading: loadItemsLoading } = useRequest(fetchItems, {
    onError: (error) => {
      message.error(t('settings.ldap.importError', { defaultValue: 'Import failed: {{error}}', error: `${error.message}` }));
    },
    onSuccess: (data) => {
      setItems(data);
    },
    manual: true,
  });


  const { run: handleImport, loading: importLoading } = useRequest(async () => {
    for (const item of checkedList.filter((item) => {
      const importItem = items.find((u) => u.ldap_dn === item)
      if (!importItem || importItem.imported) {
        return false;
      }
      return true;
    })) {
      const data = await importItems([item]);
      setItems((prev) => {
        const newItems = [...prev];
        return newItems.map((item) => {
          for (const newItem of data) {
            if (item.ldap_dn === newItem.ldap_dn) {
              return { ...newItem, imported: true };
            }
          }
          return item;
        });
      });
    }
  }, {
    manual: true,
  });

  useEffect(() => {
    if (props.visible) {
      setItems([]);
      loadItems()
      setCheckedList([]);
    }
  }, [props.visible])

  return <Modal
    title={t('settings.ldap.importTitle', { defaultValue: 'Import from LDAP' })}
    {...props}
    onOk={() => {
      handleImport()
    }}
    width={900}
    confirmLoading={importLoading}
    loading={loadItemsLoading}
  >
    <Table<T>
      rowKey="ldap_dn"
      rowSelection={{
        onChange: (selectedRowKeys) => {
          setCheckedList(selectedRowKeys as string[]);
        },
        getCheckboxProps: (record) => ({
          disabled: record.imported,
        }),
      }}
      columns={columns.map(({ render, ...column }): ColumnType<T> => {
        if (render) {
          return {
            ...column,
            render: (value: any, record: T, index: number) => {
              const loading = checkedList.includes(record.ldap_dn) && importLoading && !record.imported;
              return render(value, record, index, loading)
            }
          }
        }
        return column
      })}
      dataSource={items}
      pagination={false}
      scroll={{ y: 400, x: "max-content" }}
    />
    {/* <div
      id="scrollableDiv"
      style={{
        height: 400,
        overflow: 'auto',
        padding: '0 16px',
        border: '1px solid rgba(140, 140, 140, 0.35)',
      }}
    >
      <Checkbox style={{ position: 'absolute', float: 'right', right: 40 }} indeterminate={indeterminate} onChange={onCheckAllChange} checked={checkAll}>
        {t('settings.ldap.import.checkAll', { defaultValue: 'Check all' })}
      </Checkbox>
      <Checkbox.Group onChange={onChange} value={checkedList}>
        <List
          dataSource={items ?? []}
          renderItem={(item) => {
            const loading = checkedList.includes(item.ldap_dn) && importLoading && !item.imported;
            return <List.Item title={item.ldap_dn}>
              <Space>
                <Checkbox disabled={item.imported} style={{ fontWeight: 'bold' }} value={item.ldap_dn} />{renderItem(item, loading)}
              </Space>
            </List.Item>
          }}
        />
      </Checkbox.Group>
    </div> */}
  </Modal>
}


const LDAPSettingsForm: React.FC = () => {
  const { t } = useTranslation('system');
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);
  const [testResult, setTestResult] = useState<API.LDAPTestResponse | null>(null);
  const [testModalVisible, setTestModalVisible] = useState(false);
  const [testForm] = Form.useForm();
  const [importUserModalVisible, setImportUserModalVisible] = useState(false);

  const [importApplicationModalVisible, setImportApplicationModalVisible] = useState(false);

  const [isEnabled, setIsEnabled] = useState(false);

  useRequest(getLDAPSettings, {
    onSuccess: (data) => {
      form.setFieldsValue(data);
      setIsEnabled(data.enabled);
    },
    onError: (error) => {
      message.error(t('settings.ldap.loadError', { defaultValue: 'Failed to load LDAP settings: {{error}}', error: `${error.message}` }));
    }
  });


  useEffect(() => {
    setTestResult(null);
  }, [testModalVisible]);

  const handleSubmit = async (values: API.LDAPSettings) => {
    setLoading(true);
    try {
      await updateLDAPSettings(values);
      message.success(t('settings.ldap.saveSuccess', { defaultValue: 'LDAP settings saved successfully' }));
    } catch (error) {
      message.error(t('settings.ldap.saveError', { defaultValue: 'Failed to save LDAP settings: {{error}}', error: `${error}` }));
    } finally {
      setLoading(false);
    }
  };

  const { run: handleTest, loading: testLoading } = useRequest(async (values: API.LDAPTestRequest) => {
    const ldapSettings = await form.validateFields();
    return await testLDAPConnection({
      ...values,
      ...ldapSettings,
    });
  }, {
    onSuccess: (data) => {
      setTestResult(data);
    },
    onError: (error) => {
      message.error(t('settings.ldap.testError', { defaultValue: 'LDAP connection test failed: {{error}}', error: `${error.message}` }));
    },
    manual: true,
  });



  return (
    <>
      <Form
        form={form}
        layout="vertical"
        onFinish={handleSubmit}
        initialValues={{
          user_attr: 'uid',
          email_attr: 'mail',
          display_name_attr: 'displayName',
          default_role: 'user',
        }}
      >
        <Form.Item
          label={t('settings.ldap.enabled', { defaultValue: 'Enable LDAP' })}
          name="enabled"
          valuePropName="checked"
        >
          <Switch onChange={(checked) => setIsEnabled(checked)} />
        </Form.Item>

        <Form.Item
          label={t('settings.ldap.serverUrl', { defaultValue: 'Server URL' })}
          name="server_url"
          rules={[{ required: isEnabled, message: t('settings.ldap.serverUrlRequired', { defaultValue: 'Server URL is required' }) }]}
        >
          <Input disabled={!isEnabled} placeholder="ldap://ldap.example.com:389" />
        </Form.Item>


        <Form.Item
          label={t('settings.ldap.bindDn', { defaultValue: 'Bind DN' })}
          name="bind_dn"
          rules={[{ required: isEnabled, message: t('settings.ldap.bindDnRequired', { defaultValue: 'Bind DN is required' }) }]}
        >
          <Input disabled={!isEnabled} placeholder="cn=admin,dc=example,dc=com" />
        </Form.Item>

        <Form.Item
          label={t('settings.ldap.bindPassword', { defaultValue: 'Bind Password' })}
          name="bind_password"
          rules={[{ required: isEnabled, message: t('settings.ldap.bindPasswordRequired', { defaultValue: 'Bind password is required' }) }]}
        >
          <Input.Password hidden autoComplete='new-password' />
        </Form.Item>

        <Form.Item
          label={t('settings.ldap.baseDn', { defaultValue: 'Base DN' })}
          name="base_dn"
          rules={[{ required: isEnabled, message: t('settings.ldap.baseDnRequired', { defaultValue: 'Base DN is required' }) }]}
        >
          <Input disabled={!isEnabled} placeholder="dc=example,dc=com" />
        </Form.Item>

        <Form.Item
          label={t('settings.ldap.userFilter')}
          name="user_filter"
          help={t('settings.ldap.userFilterHelp', { defaultValue: 'Filter to apply to users, example: (objectClass=person)' })}
        >
          <Input disabled={!isEnabled} hidden autoComplete='off' placeholder="(objectClass=person)" />
        </Form.Item>

        <Form.Item
          label={t('settings.ldap.userAttr')}
          name="user_attr"
          rules={[{ required: isEnabled, message: t('settings.ldap.userAttrRequired') }]}
        >
          <Input disabled={!isEnabled} />
        </Form.Item>

        <Form.Item
          label={t('settings.ldap.emailAttr')}
          name="email_attr"
          rules={[{ required: isEnabled, message: t('settings.ldap.emailAttrRequired') }]}
        >
          <Input disabled={!isEnabled} />
        </Form.Item>

        <Form.Item
          label={t('settings.ldap.displayNameAttr')}
          name="display_name_attr"
          rules={[{ required: isEnabled, message: t('settings.ldap.displayNameAttrRequired') }]}
        >
          <Input disabled={!isEnabled} />
        </Form.Item>

        <Form.Item
          label={t('settings.ldap.defaultRole')}
          name="default_role"
          rules={[{ required: isEnabled, message: t('settings.ldap.defaultRoleRequired') }]}
        >
          <Input disabled={!isEnabled} />
        </Form.Item>
        <Divider>{t('settings.ldap.applicationDivider', { defaultValue: 'Application LDAP Configuration' })}</Divider>

        <Form.Item
          label={t('settings.ldap.applicationLdapEnabled', { defaultValue: 'Enable Application LDAP' })}
          name="application_ldap_enabled"
          valuePropName="checked"
          tooltip={t('settings.ldap.applicationLdapEnabledTooltip', { defaultValue: 'Enable LDAP-based application management. When enabled, applications can be stored in LDAP directory.' })}
        >
          <Switch disabled={!isEnabled} />
        </Form.Item>

        <Form.Item dependencies={['application_ldap_enabled']}>
          {({ getFieldValue }) => {
            if (!getFieldValue('application_ldap_enabled')) {
              return null
            }
            return <React.Fragment>
              <Form.Item
                label={t('settings.ldap.applicationBaseDn', { defaultValue: 'Application Base DN' })}
                name="application_base_dn"
                dependencies={['application_ldap_enabled']}
                rules={[
                  ({ getFieldValue }) => ({
                    required: isEnabled && getFieldValue('application_ldap_enabled'),
                    message: t('settings.ldap.applicationBaseDnRequired', { defaultValue: 'Application Base DN is required' })
                  })
                ]}
              >
                <Input disabled={!isEnabled} hidden autoComplete='off' placeholder="ou=applications,dc=example,dc=com" />
              </Form.Item>

              <Form.Item
                label={t('settings.ldap.applicationObjectClass', { defaultValue: 'Application Object Class' })}
                name="application_object_class"
              >
                <Select disabled={!isEnabled} defaultValue="groupOfNames" options={[{
                  label: 'groupOfNames',
                  value: 'groupOfNames',
                }, {
                  label: 'groupOfUniqueNames',
                  value: 'groupOfUniqueNames',
                }]} />
              </Form.Item>
              <Form.Item
                label={t('settings.ldap.applicationFilter')}
                name="application_filter"
                help={t('settings.ldap.applicationFilterHelp', { defaultValue: 'Filter to apply to applications, example: (|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames))' })}
              >
                <Input disabled={!isEnabled} defaultValue="(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames))" hidden autoComplete='off' placeholder="(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames))" />
              </Form.Item>
            </React.Fragment>
          }}
        </Form.Item>


        <Divider>{t('settings.ldap.tlsDivider')}</Divider>

        <Form.Item
          label={t('settings.ldap.startTls')}
          name="start_tls"
          valuePropName="checked"
        >
          <Switch disabled={!isEnabled} />
        </Form.Item>

        <Form.Item
          label={t('settings.ldap.insecure')}
          name="insecure"
          valuePropName="checked"
        >
          <Switch disabled={!isEnabled} />
        </Form.Item>

        <Form.Item
          label={t('settings.ldap.caCert')}
          name="ca_cert"
        >
          <Input.TextArea placeholder={t('settings.ldap.caCertPlaceholder')} disabled={!isEnabled} />
        </Form.Item>

        <Form.Item
          label={t('settings.ldap.clientCert')}
          name="client_cert"
        >
          <Input.TextArea placeholder={t('settings.ldap.clientCertPlaceholder')} disabled={!isEnabled} />
        </Form.Item>

        <Form.Item
          label={t('settings.ldap.clientKey')}
          name="client_key"
        >
          <Input.TextArea placeholder={t('settings.ldap.clientKeyPlaceholder')} disabled={!isEnabled} />
        </Form.Item>
        <Form.Item>
          <PermissionGuard permissions={['system:settings:update']}>
            <Button type="primary" htmlType="submit" loading={loading}>
              {t('settings.ldap.save')}
            </Button>
          </PermissionGuard>
          <PermissionGuard permissions={['system:settings:update']}>
            <Button
              disabled={!isEnabled}
              style={{ marginLeft: 8 }}
              onClick={() => setTestModalVisible(true)}
            >
              {t('settings.ldap.testConnection')}
            </Button>
          </PermissionGuard>

          <PermissionGuard permissions={['authorization:user:create']}>
            <Button
              disabled={!isEnabled}
              style={{ marginLeft: 8 }}
              onClick={() => {
                setImportUserModalVisible(true)
              }}
            >
              {t('settings.ldap.importUser')}
            </Button>
          </PermissionGuard>
          <PermissionGuard permissions={['application:create']}>
            <Button
              disabled={!isEnabled}
              style={{ marginLeft: 8 }}
              onClick={() => {
                setImportApplicationModalVisible(true)
              }}
            >
              {t('settings.ldap.importApplication')}
            </Button>
          </PermissionGuard>
        </Form.Item>
      </Form >

      <Modal
        title={t('settings.ldap.test.title')}
        open={testModalVisible}
        onCancel={() => setTestModalVisible(false)}
        footer={null}
      >
        <Form
          form={testForm}
          layout="vertical"
          onFinish={handleTest}
        >
          <Form.Item
            label={t('settings.ldap.test.username')}
            name="username"
            rules={[{ required: true, message: t('settings.ldap.test.usernameRequired') }]}
          >
            <Input disabled={!isEnabled} />
          </Form.Item>

          <Form.Item
            label={t('settings.ldap.test.password')}
            name="password"
            rules={[{ required: true, message: t('settings.ldap.test.passwordRequired') }]}
          >
            <Input.Password disabled={!isEnabled} />
          </Form.Item>

          <Form.Item>
            <PermissionGuard permissions={['system:settings:update']}>
              <Button disabled={!isEnabled} type="primary" htmlType="submit">
                {t('settings.ldap.test.test')}
              </Button>
            </PermissionGuard>
            <Button
              style={{ marginLeft: 8 }}
              onClick={() => setTestModalVisible(false)}
            >
              {t('settings.ldap.test.cancel')}
            </Button>
          </Form.Item>
        </Form>
        <Spin spinning={testLoading}>
          <Skeleton active={testLoading} loading={testLoading}>
            {testResult && (testResult.user ? <Descriptions bordered>
              <Descriptions.Item label="Username" span={3}>{testResult.user.username}</Descriptions.Item>
              <Descriptions.Item label="Email" span={3}>{testResult.user.email}</Descriptions.Item>
              <Descriptions.Item label="FullName" span={3}>{testResult.user.full_name}</Descriptions.Item>
              <Descriptions.Item label="CreatedAt" span={3}>{testResult.user.created_at}</Descriptions.Item>
              <Descriptions.Item label="UpdatedAt" span={3}>{testResult.user.updated_at}</Descriptions.Item>
            </Descriptions> : <Steps
              direction="vertical"
              current={testResult.message?.findIndex((msg) => !msg.success)}
              status={testResult.message?.find((msg) => !msg.success) ? 'error' : 'finish'}
              items={testResult.message?.map((msg) => ({
                status: msg.success ? 'finish' : 'error',
                title: msg.message,
              }))} />)
            }
          </Skeleton>
        </Spin>
      </Modal>
      <ImportLDAPEntryModal<API.ImportLDAPUsersResponse>
        visible={importUserModalVisible}
        onCancel={() => setImportUserModalVisible(false)}
        fetchItems={() => importLDAPUsers({})}
        importItems={(dn: string[]) => importLDAPUsers({ user_dn: dn })}
        columns={[{
          title: t('settings.ldap.username', { defaultValue: 'Username' }),
          dataIndex: 'username',
        }, {
          title: t('settings.ldap.email', { defaultValue: 'Email' }),
          dataIndex: 'email',
        }, {
          title: t('settings.ldap.fullName', { defaultValue: 'Full Name' }),
          dataIndex: 'full_name',
        }, {
          title: t('settings.ldap.importStatus', { defaultValue: 'Import Status' }),
          dataIndex: 'imported',
          fixed: 'right',
          render: (imported, record, _, loading) => {
            if (loading) {
              return <Spin indicator={<LoadingOutlined spin />} />
            }
            if (imported) {
              return <CheckCircleTwoTone twoToneColor="#52c41a" />
            }
            if (record.id) {
              return <Tag color="blue">{t('settings.ldap.importTypeBound', { defaultValue: 'Bound' })}</Tag>
            }
            return <Tag color="green">{t('settings.ldap.importTypeNew', { defaultValue: 'New' })}</Tag>
          }
        }]}
      />
      <ImportLDAPEntryModal<API.ImportLDAPApplicationsResponse>
        visible={importApplicationModalVisible}
        onCancel={() => setImportApplicationModalVisible(false)}
        fetchItems={() => importLDAPApplications({})}
        importItems={(dn: string[]) => importLDAPApplications({ application_dn: dn })}
        columns={[{
          title: 'Name',
          dataIndex: 'name',
        }, {
          title: 'LDAP DN',
          dataIndex: 'ldap_dn',
        }, {
          title: t('settings.ldap.importStatus', { defaultValue: 'Import Status' }),
          dataIndex: 'imported',
          fixed: 'right',
          render: (imported, record, _, loading) => {
            if (loading) {
              return <Spin indicator={<LoadingOutlined spin />} />
            }
            if (imported) {
              return <CheckCircleTwoTone twoToneColor="#52c41a" />
            }
            if (record.id) {
              return <Tag color="blue">{t('settings.ldap.importTypeBound', { defaultValue: 'Bound' })}</Tag>
            }
            return <Tag color="green">{t('settings.ldap.importTypeNew', { defaultValue: 'New' })}</Tag>
          }
        }]}
      />
    </>
  );
};

export default LDAPSettingsForm; 