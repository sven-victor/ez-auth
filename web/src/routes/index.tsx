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

import { lazy } from 'react';
import { withSuspense, IRoute } from 'ez-console';

import { UserOutlined, AppstoreOutlined, HomeOutlined } from '@ant-design/icons';
import { TabsProps } from 'antd';

// Lazy load page components
const Home = lazy(() => import('@/pages/Home'));
const UserList = lazy(() => import('@/pages/User/List'));
const UserDetail = lazy(() => import('@/pages/User/Detail'));
const UserForm = lazy(() => import('@/pages/User/Form'));
const ApplicationList = lazy(() => import('@/pages/Application/List'));
const ApplicationDetail = lazy(() => import('@/pages/Application/Detail'));
const ApplicationForm = lazy(() => import('@/pages/Application/Form'));
const LDAPSetting = lazy(() => import('@/pages/Settings/LDAPSetting'));
const OIDCTestPage = lazy(() => import('@/pages/OIDC/TestPage'));
const OIDCCallback = lazy(() => import('@/pages/OIDC/Callback'));
const OIDCAuthorize = lazy(() => import('@/pages/OIDC/Authorize'));


// Public routes - no authentication required
export const publicRoutes: IRoute[] = [
  {
    path: '/',
    element: withSuspense(Home),
    name: 'home',
    icon: <HomeOutlined />,
    index: true,
  },
  {
    path: '/oidc/test',
    element: withSuspense(OIDCTestPage),
    index: true,
  },
  {
    path: '/oidc/authorize',
    element: withSuspense(OIDCAuthorize),
    index: true,
  },
  {
    path: '/oidc/callback/:codeIndex',
    element: withSuspense(OIDCCallback),
    index: true,
  },
];

const userManagementRoute: IRoute = {
  path: '/authorization/users',
  name: 'users',
  icon: <UserOutlined />,
  permissions: ['authorization:user:list', 'authorization:user:view', 'authorization:user:create', 'authorization:user:update'],
  children: [
    {
      path: '/authorization/users',
      element: withSuspense(UserList),
      index: true,
      permissions: ['authorization:user:list'],
    },
    {
      path: '/authorization/users/:id',
      element: withSuspense(UserDetail),
      index: true,
      permissions: ['authorization:user:view'],
    },

    {
      path: '/authorization/users/create',
      element: withSuspense(UserForm),
      permissions: ['authorization:user:create'],
      index: true,
    },
    {
      path: '/authorization/users/:id/edit',
      element: withSuspense(UserForm),
      permissions: ['authorization:user:update'],
      index: true,
    },
  ],
}



export const PrivateRoutes: IRoute[] = [
  {
    path: '/applications',
    name: 'application_management',
    icon: <AppstoreOutlined />,
    permissions: ['applications:view'],
    children: [
      {
        path: '/applications',
        element: withSuspense(ApplicationList),
        index: true,
        permissions: ['applications:view'],
      },
      {
        path: '/applications/:id',
        element: withSuspense(ApplicationDetail),
        index: true,
        permissions: ['applications:view'],
      },
      {
        path: '/applications/create',
        element: withSuspense(ApplicationForm),
        permissions: ['applications:create'],
        index: true,
      },
      {
        path: '/applications/:id/edit',
        element: withSuspense(ApplicationForm),
        permissions: ['applications:update'],
        index: true,
      },
    ],
  },
]
export const transformSettingTabs = (tabs: TabsProps['items']): TabsProps['items'] => {
  if (!tabs) {
    return [{
      key: 'ldap',
      label: 'LDAP Settings',
    }];
  }
  return tabs?.map((tab) => {
    if (tab.key === 'ldap') {
      return {
        ...tab,
        children: withSuspense(LDAPSetting),
      }
    }
    return tab
  })
}

export const transformRouter = (routes: IRoute[]): IRoute[] => {
  return routes.map((route) => {
    if (route.path === '/authorization/users' && route.children && route.name === 'users') {
      return userManagementRoute;
    }
    if (route.name === 'dashboard' && route.path === '/') {
      return {
        ...route,
        path: '/undefined',
        element: <></>,
        index: false,
        children: [],
        name: undefined,
      }
    }
    if (route.children) {
      return {
        ...route,
        children: transformRouter(route.children),
      }
    }
    return route
  })
}
