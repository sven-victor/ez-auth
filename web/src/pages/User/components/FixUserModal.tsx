import { updateUser, getLdapUsers } from "@/api/user";
import { useRequest } from "ahooks";
import { message, Modal, Space, Button, Select, Tag } from "antd";
import { useState, useEffect } from "react";
import { useTranslation } from "react-i18next";

const FixUserModal = ({ user, onClose, onSuccess }: { user: API.User | null, onClose: () => void, onSuccess: () => void }) => {
  const { t } = useTranslation("users");
  const { t: tCommon } = useTranslation("common");
  const [fixMethod, setFixMethod] = useState<'local' | 'bind' | null>(null);
  const [ldapUserDN, setLdapUserDN] = useState<string | null>(null);


  const { run: handleUpdateUser, loading: updateUserLoading } = useRequest(updateUser, {
    onSuccess: () => {
      message.success(t('updateUserSuccess', { defaultValue: 'User updated successfully' }));
      onSuccess();
    },
    onError: (error) => {
      message.error(t('updateUserError', { defaultValue: 'Failed to update user', error: error.message }));
    },
    manual: true,
  });

  const { data: ldapUsers, loading: ldapUsersLoading } = useRequest(async () => {
    if (fixMethod === 'bind' && user) {
      return getLdapUsers(true).then((users) => {
        const recommend = []
        const other = []
        for (const ldapUser of users) {
          if (ldapUser.username === user?.username ||
            ldapUser.email === user?.email ||
            ldapUser.full_name === user?.full_name
          ) {
            recommend.push({ recommend: true, ...ldapUser })
          } else {
            other.push({ recommend: false, ...ldapUser })
          }
        }
        return [...recommend, ...other]
      });
    }
    return Promise.resolve([]);
  }, {
    refreshDeps: [user?.id, fixMethod],
  });

  useEffect(() => {
    if (user) {
      setFixMethod(null)
      setLdapUserDN(null)
    }
  }, [user])


  return <Modal
    open={user !== null}
    onCancel={onClose}
    okText={tCommon('confirm', { defaultValue: 'Confirm' })}
    cancelText={tCommon('cancel', { defaultValue: 'Cancel' })}
    onOk={() => {
      if (user) {
        if (fixMethod === 'local') {
          return handleUpdateUser(user.id, {
            email: user.email,
            full_name: user.full_name,
            status: user.status as 'active' | 'inactive',
            mfa_enforced: user.mfa_enforced,
            source: 'local',
          });
        } else if (fixMethod === 'bind') {
          if (!ldapUserDN) {
            message.error(t('ldapUserDNRequired', { defaultValue: 'LDAP User DN is required' }));
            return;
          }
          return handleUpdateUser(user.id, {
            email: user.email,
            full_name: user.full_name,
            status: user.status as 'active' | 'inactive',
            mfa_enforced: user.mfa_enforced,
            source: 'ldap',
            ldap_dn: ldapUserDN
          });
        } else {
          message.error(t('unknownFixMethod', { defaultValue: 'Unknown fix method' }));
          return;
        }
      }
      message.error(t('unknownUserId', { defaultValue: 'Unknown user id' }));
      return;
    }}
    title={t('fixUserTitle', { defaultValue: 'Fix User' })}>
    <Space direction="vertical" style={{ width: '100%' }}>
      <Button loading={updateUserLoading} style={{ width: '100%', height: 40 }} type={'default'} variant='outlined' color={fixMethod === 'local' ? 'primary' : 'default'} onClick={() => setFixMethod('local')}>{t('fixUserConvertToLocal', { defaultValue: 'Convert to Local' })}</Button>
      <Button loading={updateUserLoading} style={{ width: '100%', height: 40 }} type={'default'} variant='outlined' color={fixMethod === 'bind' ? 'primary' : 'default'} onClick={() => setFixMethod('bind')}>{t('fixUserBindLDAPUser', { defaultValue: 'Bind LDAP User' })}</Button>
      <Select
        loading={ldapUsersLoading}
        style={{ display: fixMethod === 'bind' ? 'block' : 'none' }}
        onSelect={(value) => setLdapUserDN(value)}
        value={ldapUserDN}
        options={ldapUsers?.map((user) => ({ label: <div><Tag color={user.recommend ? 'blue' : 'default'}>{user.full_name}</Tag> {user.username} - {user.email} - {user.ldap_dn}</div>, value: user.ldap_dn }))}
        showSearch={true}
      />
    </Space>
  </Modal >
}

export default FixUserModal;