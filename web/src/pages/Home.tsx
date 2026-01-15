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

import React, { useEffect, useState } from 'react';
import { Button, Card, Form, Input, Layout, List, message, Modal, Pagination, Radio, Space, Tag, Tooltip, Typography } from 'antd';
import { useAuth, Avatar, HeaderDropdown, LanguageSwitch, Loading, PermissionGuard, Actions, useSite, type SiteConfig } from 'ez-console';
import { useTranslation } from 'ez-console';
import { useRequest } from 'ahooks';
import { getMySelfApplications } from '@/api/user';
import { updateApplicationPassword } from '@/api/application';
import { getApplicationDescription, getApplicationDisplayName } from '@/utils';
import { AppstoreOutlined, KeyOutlined, MoonOutlined, ProductOutlined, ReloadOutlined, SearchOutlined, SunOutlined, SwapOutlined, UnorderedListOutlined, UserOutlined } from '@ant-design/icons';
import { Content, Header } from 'antd/es/layout/layout';
import { Link } from 'react-router-dom';
import classNames from 'classnames';
import { createStyles, useThemeMode } from 'antd-style';

const useStyles = createStyles(({ css, token }) => {
  return {
    header: css`
      padding: 0;
      display: flex;
      justify-content: space-between;
      background-color: ${token.colorBgContainer};
      border-block-end: 1px solid ${token.colorBorderSecondary};
    `,
    iconStyle: {
      cursor: "pointer",
      padding: "12px",
      display: "inline-flex",
      alignItems: "center",
      justifyContent: "center",
      fontSize: 18,
      textDecoration: "none",
      verticalAlign: "middle",
      color: token.colorText,
      '&:hover': {
        color: token.colorPrimaryTextHover
      },
    },
  };
});
const { Paragraph, Text, Title } = Typography;



const Home: React.FC = () => {
  const { siteConfig } = useSite();
  const { styles } = useStyles();
  const { t, i18n } = useTranslation();
  const { t: tCommon } = useTranslation('common');
  const { t: tApplications } = useTranslation('applications');
  const { logout, user, loading: userLoading } = useAuth();
  const { themeMode, setThemeMode } = useThemeMode();

  const [navigation, setNavigation] = useState<API.Navigation[]>([]);

  const [search, setSearch] = useState<string>('');
  const [listType, setListType] = useState<'card' | 'list'>('card');

  if (user) {
    if (user.mfa_enforced && !user.mfa_enabled) {
      window.location.href = '/profile#mfa';
      return
    } else if (user.status === "password_expired") {
      window.location.href = '/profile#password';
      return
    }
  } else if (!userLoading) {
    window.location.href = '/login?redirect=' + encodeURIComponent(window.location.href);
    return
  }
  useEffect(() => {
    if (siteConfig) {
      const navigation = (siteConfig as SiteConfig).navigation.filter(item => item.path !== siteConfig.home_page)
      if (navigation.length > 1) {
        setNavigation(navigation.filter(item => item.path !== window.location.pathname))
      } else {
        setNavigation([])
      }
      document.getElementById('site-icon')?.setAttribute('href', siteConfig.logo || '/logo.png')
    }
  }, [siteConfig])
  useEffect(() => {
    if (i18n.language) {
      window.document.title = (siteConfig?.name_i18n[i18n.language] || siteConfig?.name || "")
    }
  }, [siteConfig, i18n.language])

  const handleLogout = () => {
    logout();
    window.location.href = '/login?redirect=' + encodeURIComponent(window.location.href);
  };

  const userMenu = [
    {
      key: 'profile',
      label: <a href="/profile">{tCommon('profile', { defaultValue: 'Profile' })}</a>,
    },
    {
      key: 'logout',
      label: tCommon('logout', { defaultValue: 'Logout' }),
      onClick: handleLogout,
    },
  ];

  const { runAsync: changePassword, loading: changePasswordLoading } = useRequest(updateApplicationPassword, {
    manual: true,
    onError: (error: any) => {
      if (error.code === 'E40050') {
        if (error.message.match(/password length must be at least \d+ characters/)) {
          const minLength = error.message.match(/password length must be at least (\d+) characters/)?.[1]
          message.error(tApplications('setApplicationPasswordError.E40050', { defaultValue: 'Set application password failed: {{error}}', error: error.message, minLength }))
          return
        }
        message.error(`Set application password failed: ${error.message}`)
        return
      }
      message.error(tApplications(`setApplicationPasswordError.${error.code}`, { defaultValue: 'Set application password failed: {{error}}', error: error.message }))
    }
  });

  const { data, loading, run: runGetApplications } = useRequest(getMySelfApplications, {
    defaultParams: [search, 1, 30]
  });
  if (userLoading) {
    return <Loading />
  }

  const handleChangePassword = (item: API.Application) => {
    const modal = Modal.confirm({
      title: tApplications('setApplicationPasswordTitle', { defaultValue: 'Set application independent password' }),
      content: <div>
        <div>{tApplications('setApplicationPasswordDescription', { defaultValue: 'Set an application independent password for the current user.' })}</div>
        <Form style={{ marginTop: 10, marginBottom: 10 }} onFinish={async (values) => {
          await changePassword(item.id, { password: values.password })
          modal.destroy()
          Modal.success({
            title: tApplications('setApplicationPasswordSuccess', { defaultValue: 'Set application password successfully.' }),
          })
        }}>
          <div>
            <Form.Item name="password" >
              <Input.Password autoComplete='new-password' />
            </Form.Item>
          </div>
          <Space style={{ float: 'right' }}>
            <Button onClick={() => modal.destroy()} loading={changePasswordLoading}>
              {tCommon('cancel', { defaultValue: 'Cancel' })}
            </Button>
            <Button type="primary" htmlType="submit" loading={changePasswordLoading}>
              {tCommon('ok', { defaultValue: 'OK' })}
            </Button>
          </Space>
        </Form>
      </div>,
      okCancel: false,
      footer: null,
    })
  }

  const renderListItem = (item: API.Application) => {
    const description = getApplicationDescription(item, i18n.language);
    const title = getApplicationDisplayName(item, i18n.language) || item.name;
    const grantTypes = item.grant_types || [];
    const isPasswordGrant = grantTypes.includes('password');
    switch (listType) {
      case 'list':
        return (
          <List.Item
            extra={siteConfig?.enable_multi_org && <Tag color="blue">{item.organization_name}</Tag>}
            actions={[<Actions key="actions" actions={[{
              key: 'changePassword',
              icon: <KeyOutlined />,
              hidden: !isPasswordGrant,
              type: 'link',
              onClick: async () => {
                return await handleChangePassword(item)
              }
            }]} />]}>
            <List.Item.Meta
              avatar={<Avatar src={item.icon} fallback={<AppstoreOutlined />} />}
              title={<Text style={{ fontSize: 16 }} >{title}</Text>}
              description={description || item.uri}
            />
            {item.force_independent_password && <div>{item.has_password ? <Tag color="green">{tApplications('passwordHasBeenSet', { defaultValue: 'Password Set' })}</Tag> : <Tooltip title={tApplications('passwordNotSetDescription', { defaultValue: 'The application requires a password to be set for the current user.' })}><Tag color="red">{tApplications('passwordNotSet', { defaultValue: 'Not Set' })}</Tag></Tooltip>}</div>}
          </List.Item>
        )
      default:
        return (
          <List.Item >
            <Card
              hoverable={!!item.uri}
              onClick={() => {
                if (item.uri) {
                  window.open(item.uri, '_blank');
                }
              }}
            >
              <Card.Meta
                avatar={<Avatar src={item.icon} fallback={<AppstoreOutlined />} />}
                title={<div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Text style={{ fontSize: 16 }} ellipsis={{ tooltip: true }}>{title}</Text>
                  {siteConfig?.enable_multi_org && <Tag color="blue">{item.organization_name}</Tag>}
                </div>}
                description={<Paragraph
                  style={{ height: 44 }}
                  ellipsis={{ rows: 2, tooltip: true }}
                >{description || item.uri}</Paragraph>}
              />
            </Card>
          </List.Item>
        )
    }
  }

  return <Layout style={{ minHeight: '100vh' }} className="site-layout">
    <Header className={classNames("site-header", styles.header)} style={{ padding: 0, display: 'flex', justifyContent: 'space-between' }}>
      <div style={{ display: 'flex', alignItems: 'center', marginLeft: '20px' }} >
        <Avatar src={siteConfig?.logo || '/logo.png'} />
        <div style={{ marginLeft: '10px' }}>
          <Title style={{ fontSize: 16 }}>{siteConfig?.name}</Title>
        </div>
      </div>
      <div style={{ marginRight: '20px' }}>
        <PermissionGuard permission="applications:list">
          <Link to="/applications" className={styles.iconStyle}  >
            <ProductOutlined />
          </Link>
        </PermissionGuard>
        <HeaderDropdown
          hidden={!user?.roles || navigation.length === 0}
          menu={{
            items: navigation.map(item => ({
              key: item.path,
              style: { paddingRight: '20px' },
              label: <a href={item.path}>{t(`menu.${item.name}`, { defaultValue: item.name })}</a>,
            }))
          }}
        >
          <SwapOutlined />
        </HeaderDropdown>
        <HeaderDropdown menu={{ items: userMenu }}>
          {user?.avatar ? <Avatar src={user.avatar} /> : <Avatar icon={<UserOutlined />} />}
          <span style={{ height: '1em', lineHeight: '1em' }}>{user?.full_name || user?.username}</span>
        </HeaderDropdown>
        <LanguageSwitch />,
        <HeaderDropdown
          key="theme-switch"
          menu={{
            items: [
              { key: 'light', label: <span><SunOutlined /> {tCommon('light', { defaultValue: 'Light Mode' })}</span> },
              { key: 'dark', label: <span><MoonOutlined /> {tCommon('dark', { defaultValue: 'Dark Mode' })}</span> }
            ],
            onClick: ({ key }) => {
              setThemeMode(key as 'light' | 'dark')
            },
            selectedKeys: [themeMode],
          }}
        >
          {themeMode === 'light' ? <SunOutlined /> : <MoonOutlined />}
        </HeaderDropdown>
      </div>
    </Header>
    <Content style={{ margin: '16px' }}>
      <Card >
        <div style={{ width: '100%', padding: 0, display: 'flex', justifyContent: 'space-between', paddingBottom: 10 }}>
          <Input placeholder={tCommon('search', { defaultValue: 'Search' })} style={{ width: 200, }} onChange={(e) => {
            setSearch(e.target.value)
          }} onPressEnter={() => {
            runGetApplications(search, 1, data?.page_size || 30)
          }} suffix={<SearchOutlined />} />
          <Space>
            <Button type="text" icon={<ReloadOutlined />} onClick={() => {
              runGetApplications(search, data?.current || 1, data?.page_size || 30)
            }} />
            <Radio.Group value={listType} onChange={(e) => setListType(e.target.value)}>
              <Radio.Button value="card"><AppstoreOutlined /></Radio.Button>
              <Radio.Button value="list"><UnorderedListOutlined /></Radio.Button>
            </Radio.Group>
          </Space>
        </div>
        <List
          grid={listType === 'card' ? {
            gutter: 16,
            xs: 1,
            sm: 2,
            md: 4,
            lg: 4,
            xl: 4,
            xxl: 6,
          } : undefined}
          dataSource={data?.data}
          loading={loading}
          renderItem={renderListItem}
        />
        <Pagination
          total={data?.total}
          current={data?.current}
          pageSize={data?.page_size}
          onChange={(page, pageSize) => {
            runGetApplications(search, page, pageSize)
          }}
        />
      </Card>
    </Content>
  </Layout>
};

export default Home; 