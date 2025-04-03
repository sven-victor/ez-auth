import { assignUserToApplication } from "@/api/application";
import { getUsers } from "@/api/user";
import { useRequest } from "ahooks";
import { Modal, Form, message, Select, Spin } from "antd";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

export const AssignUserModel = ({
  onSuccess,
  id,
  visible,
  setVisible,
  currentUser,
  roles,
}: {
  onSuccess: () => void,
  id: string,
  visible: boolean,
  setVisible: (visible: boolean) => void,
  currentUser: API.User[],
  roles: API.ApplicationRole[],
}) => {
  const { t } = useTranslation("applications");
  const { t: tCommon } = useTranslation("common");
  const [form] = Form.useForm();
  const [availableUsers, setAvailableUsers] = useState<API.User[]>([]);

  // Assign user to application
  const { run: handleAssignUser, loading: assignUserLoading } = useRequest(async (values: any) => {
    return await assignUserToApplication(id!, values.userId, values.roleId)
  }, {
    manual: true,
    onSuccess: () => {
      message.success(t('userAssignSuccess', { defaultValue: 'User assigned successfully' }));
      setVisible(false);
      form.resetFields();
      onSuccess()
    },
    onError: (error) => {
      message.error(t('userAssignError', { defaultValue: 'Failed to assign user: {{error}}', error }));
    },
  });

  const { run: handleUserSearch, loading: userSearchLoading } = useRequest(async (value?: string) => {
    return await getUsers(value)
  }, {
    onSuccess: (data) => {
      const filteredUsers = data.data.filter(user =>
        !currentUser?.some(assignedUser => assignedUser.id === user.id)
      );
      setAvailableUsers(filteredUsers);
    },
    manual: true,
  });

  useEffect(() => {
    if (!visible) {
      form.resetFields();
    } else {
      handleUserSearch()
    }
  }, [visible]);

  return <Modal
    title={t('assignUser', { defaultValue: 'Assign User' })}
    open={visible}
    onCancel={() => setVisible(false)}
    onOk={() => {
      form.submit()
    }}
    okText={tCommon('assign', { defaultValue: 'Assign' })}
    confirmLoading={assignUserLoading}
  >
    <Form
      form={form}
      onFinish={handleAssignUser}
      layout="vertical"
    >
      <Form.Item
        name="userId"
        label={t('selectUser', { defaultValue: 'Select User' })}
        rules={[{ required: true, message: t('userRequired', { defaultValue: 'User is required' }) }]}
      >
        <Select
          placeholder={t('selectUserPlaceholder', { defaultValue: 'Select a user' })}
          showSearch
          loading={userSearchLoading}
          onSearch={handleUserSearch}
          filterOption={false}
          notFoundContent={userSearchLoading ? <Spin size="small" /> : null}
        >
          {availableUsers.map(user => (
            <Select.Option key={user.id} value={user.id}>
              {user.full_name} ({user.email})
            </Select.Option>
          ))}
        </Select>
      </Form.Item>
      <Form.Item
        name="roleId"
        label={t('selectRoles', { defaultValue: 'Select Role' })}
      >
        <Select
          placeholder={t('selectRolesPlaceholder', { defaultValue: 'Select a role' })}
        >
          {roles.map(role => (
            <Select.Option key={role.id} value={role.id}>
              {role.name}
            </Select.Option>
          ))}
        </Select>
      </Form.Item>
    </Form>
  </Modal>
}

export default AssignUserModel;