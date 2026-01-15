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

import { assignUserToApplication } from "@/api/application";
import { getApplicationRoles } from "@/api/application";
import { Avatar } from "ez-console";
import { AppstoreOutlined, CheckCircleFilled, CloseCircleFilled, CloseOutlined, LoadingOutlined } from "@ant-design/icons";
import { useRequest } from "ahooks";
import { Modal, Form, message, Select, Spin, List, Button, Popover } from "antd";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { createStyles } from "antd-style";
import { getUserAssignableApplications } from "@/api/user";

const useStyles = createStyles(({ css }) => ({
  assignList: css`
    .ant-list-item-meta-content{
      display: flex;
      align-items: center;
      justify-content: space-between;
      .ant-list-item-meta-description{
        margin-right: 120px;
      }
    }
  `,
}));

interface AssignApplicationStatus {
  applicationId: string,
  applicationName?: string,
  applicationIcon?: string,
  roleId?: string,
  roles?: API.ApplicationRole[],
  status: 'success' | 'error' | 'loading' | 'pending',
  errorMessage?: string,
}

export const AssignUserModel = ({
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
  const { styles } = useStyles();
  const { t } = useTranslation("applications");
  const { t: tUsers } = useTranslation("users");
  const { t: tCommon } = useTranslation("common");
  const [form] = Form.useForm();
  const [selectedApplications, setSelectedApplications] = useState<AssignApplicationStatus[]>([]);
  // Assign user to application
  const { run: handleAssignUser, loading: assignUserLoading } = useRequest(async () => {
    for (const application of selectedApplications) {
      try {
        setSelectedApplications((oriValues) => {
          return oriValues.map(item => item.applicationId === application.applicationId ? { ...item, status: 'loading' } : item)
        })
        await assignUserToApplication(application.applicationId, id!, application.roleId)
        setSelectedApplications((oriValues) => {
          return oriValues.map(item => item.applicationId === application.applicationId ? { ...item, status: 'success' } : item)
        })
      } catch (error) {
        setSelectedApplications((oriValues) => {
          return oriValues.map(item => item.applicationId === application.applicationId ? { ...item, status: 'error', errorMessage: `${error}` } : item)
        })
        throw error
      }
    }


  }, {
    manual: true,
    onSuccess: () => {
      message.success(t('userAssignSuccess'));
      setVisible(false);
      form.resetFields();
      onSuccess()
    },
    onError: (error) => {
      message.error(t('userAssignError', { error }));
    },
  });

  const { run: handleApplicationSearch, data: availableApplications = [], loading: applicationSearchLoading } = useRequest(async (value?: string) => {
    const { data } = await getUserAssignableApplications(id, value)
    return data
  }, {
    manual: true,
  });

  useEffect(() => {
    if (!visible) {
      form.resetFields();
      setSelectedApplications([]);
    } else {
      handleApplicationSearch()
    }
  }, [visible]);

  return <Modal
    title={tUsers('assignApplication')}
    open={visible}
    onCancel={() => setVisible(false)}
    onOk={() => {
      form.submit()
    }}
    cancelText={tCommon('cancel', { defaultValue: 'Cancel' })}
    okText={tCommon('assign', { defaultValue: 'Assign' })}
    confirmLoading={assignUserLoading || applicationSearchLoading}
  >
    <Form
      form={form}
      onFinish={handleAssignUser}
      layout="vertical"
    >
      <Form.Item
        name="applicationId"
        label={tUsers('selectApplication')}
        rules={[{ required: true, message: tUsers('applicationRequired') }]}
      >
        <Select
          placeholder={tUsers('selectApplicationPlaceholder')}
          showSearch
          value={selectedApplications.map(item => item.applicationId)}
          loading={applicationSearchLoading}
          onSearch={handleApplicationSearch}
          onChange={async (values: string[]) => {
            setSelectedApplications((oriValues) => {
              return values.map((value) => {
                return oriValues.find(item => item.applicationId === value) || {
                  applicationId: value,
                  applicationName: availableApplications.find(item => item.id === value)?.name,
                  applicationIcon: availableApplications.find(item => item.id === value)?.icon,
                  status: 'pending',
                }
              })
            })
          }}
          filterOption={false}
          notFoundContent={applicationSearchLoading ? <Spin size="small" /> : null}
          mode="multiple"
        >
          {availableApplications.map(application => (
            <Select.Option key={application.id} value={application.id}>
              {application.name}
            </Select.Option>
          ))}
        </Select>
      </Form.Item>
    </Form>
    <List<AssignApplicationStatus>
      style={{ minHeight: 250 }}
      dataSource={selectedApplications}
      className={styles.assignList}
      renderItem={(item) => <AssignUserItem
        item={item}
        onRoleChange={(roleId) => {
          setSelectedApplications((oriValues) => {
            return oriValues.map(value => value.applicationId === item.applicationId ? { ...value, roleId: roleId } : value)
          })
        }}
        onRemove={() => {
          setSelectedApplications((oriValues) => { return oriValues.filter(value => value.applicationId !== item.applicationId) })
        }}
      />
      }
    />
  </Modal>
}

interface AssignUserItemProps {
  item: AssignApplicationStatus,
  onRoleChange: (roleId: string) => void,
  onRemove: () => void,
}

const AssignUserItem = ({ item, onRoleChange, onRemove }: AssignUserItemProps) => {
  const { t } = useTranslation("applications");
  const { loading, data: roles = [] } = useRequest(async () => {
    return await getApplicationRoles(item.applicationId)
  }, { refreshDeps: [item.applicationId] })
  const renderApplicationStatus = (item: AssignApplicationStatus) => {
    switch (item.status) {
      case 'success':
        return <CheckCircleFilled style={{ color: '#52c41a' }} />
      case 'error':
        return <Popover content={item.errorMessage}><CloseCircleFilled style={{ color: '#f5222d' }} /></Popover>
      case 'loading':
      case 'pending':
        return <></>
    }
  }
  const renderApplicationAction = (item: AssignApplicationStatus) => {
    switch (item.status) {
      case 'loading':
        return <Spin size="small" style={{ padding: '0 15px' }} />
      case 'error':
      case 'pending':
        return <Button
          type="link"
          onClick={() => onRemove()}
        >
          <CloseOutlined />
        </Button>
    }
  }

  const renderRoleSelect = (item: AssignApplicationStatus) => {
    if (loading) {
      return <Spin size="small" indicator={<LoadingOutlined spin />} />
    }
    if (roles.length === 0) {
      return <></>
    }
    return <Select
      allowClear
      placeholder={t('selectRoles')}
      value={item.roleId}
      loading={loading}
      style={{ minWidth: 150 }}
      onChange={(value) => onRoleChange(value)}
      options={roles.map(role => ({ label: role.name, value: role.id }))}
    />
  }
  return <List.Item
    extra={renderApplicationAction(item)}
  >
    <List.Item.Meta
      avatar={<Avatar src={item.applicationIcon} icon={<AppstoreOutlined />} />}
      title={<div>{item.applicationName} {renderApplicationStatus(item)}</div>}
      description={renderRoleSelect(item)}
    />
  </List.Item>
}

export default AssignUserModel;