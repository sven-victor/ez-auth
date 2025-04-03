import { createApplicationRole, updateApplicationRole } from "@/api/application";
import { useRequest } from "ahooks";
import { Modal, Input, Form, message } from "antd";
import { useEffect } from "react";
import { useTranslation } from "react-i18next";
const RoleFormModel = ({
  onSuccess,
  id,
  visible,
  setVisible,
  currentRole,
}: {
  onSuccess: () => void,
  id: string,
  visible: boolean,
  setVisible: (visible: boolean) => void,
  currentRole?: API.ApplicationRole | null,
}) => {
  const { t } = useTranslation("applications");
  const { t: tCommon } = useTranslation("common");
  const [form] = Form.useForm();

  const { run: handleCreateRole, loading: createRoleLoading } = useRequest(async (values: any) => {
    return await createApplicationRole(id!, values);
  }, {
    onSuccess: () => {
      message.success(t('roleCreateSuccess', { defaultValue: 'Role created successfully' }));
      onSuccess();
      setVisible(false);
      form.resetFields();
    },
    onError: (error) => {
      message.error(t('roleCreateError', { defaultValue: 'Failed to create role: {{error}}', error }));
    },
    manual: true,
  });

  useEffect(() => {
    if (!visible) {
      form.resetFields();
    } else {
      form.setFieldsValue({
        name: currentRole?.name,
        description: currentRole?.description,
      });
    }
  }, [visible]);

  const { run: handleUpdateRole, loading: updateRoleLoading } = useRequest(async (values: any) => {
    if (!currentRole) {
      throw new Error('currentRole is required');
    }
    return await updateApplicationRole(id!, currentRole.id, values);
  }, {
    onSuccess: () => {
      message.success(t('roleUpdateSuccess', { defaultValue: 'Role updated successfully' }));
      onSuccess();
      setVisible(false);
      form.resetFields();
    },
    onError: (error) => {
      message.error(t('roleUpdateError', { defaultValue: 'Failed to update role: {{error}}', error }));
    },
    manual: true,
  });

  return <Modal
    title={currentRole ? t('editRole', { defaultValue: 'Edit Role' }) : t('createRole', { defaultValue: 'Create Role' })}
    open={visible}
    onCancel={() => setVisible(false)}
    onOk={() => {
      form.submit()
    }}
    okText={currentRole ? tCommon('update', { defaultValue: 'Update' }) : tCommon('create', { defaultValue: 'Create' })}
    confirmLoading={updateRoleLoading || createRoleLoading}
  >
    <Form
      form={form}
      onFinish={currentRole ? handleUpdateRole : handleCreateRole}
      layout="vertical"
      disabled={updateRoleLoading || createRoleLoading}
    >
      <Form.Item
        name="name"
        label={t('roleName', { defaultValue: 'Role Name' })}
        rules={[{ required: true, message: t('roleNameRequired', { defaultValue: 'Role name is required' }) }]}
      >
        <Input placeholder={t('roleNamePlaceholder', { defaultValue: 'Enter role name' })} />
      </Form.Item>
      <Form.Item
        name="description"
        label={t('roleDescription', { defaultValue: 'Description' })}
      >
        <Input.TextArea rows={4} placeholder={t('roleDescriptionPlaceholder', { defaultValue: 'Enter description' })} />
      </Form.Item>
    </Form>
  </Modal>;
};

export default RoleFormModel;
