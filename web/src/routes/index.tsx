import React, { lazy, Suspense } from 'react';
import Loading from '../components/Loading';
import { UserOutlined, AppstoreOutlined, SafetyOutlined, HomeOutlined } from '@ant-design/icons';

// Lazy load page components
const Home = lazy(() => import('@/pages/Home'));
const NotFound = lazy(() => import('@/pages/NotFound'));
const Forbidden = lazy(() => import('@/pages/Forbidden'));
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

// Wrap lazy loaded components
const withSuspense = (Component: React.LazyExoticComponent<any>) => (
  <Suspense fallback={<Loading />}>
    <Component />
  </Suspense>
);

// Public routes - no authentication required
export const publicRoutes: IRoute[] = [
  {
    path: '/404',
    element: withSuspense(NotFound),
    index: true,
  },
  {
    path: '/403',
    element: withSuspense(Forbidden),
    index: true,
  },
  {
    path: '/oidc/callback/:codeIndex',
    element: withSuspense(OIDCCallback),
    index: true,
  },
];

// Private routes - authentication required, uses main layout
export const privateRoutes: IRoute[] = [
  {
    path: '/',
    element: withSuspense(Home),
    name: 'home',
    icon: <HomeOutlined />,
    index: true,
  },
  {
    path: '/',
    is_private: true,
    children: [
      {
        path: '/users',
        name: 'user_management',
        icon: <UserOutlined />,
        permissions: ['users:view'],
        children: [
          {
            path: '/users',
            element: withSuspense(UserList),
            index: true,
            permissions: ['users:view'],
          },
          {
            path: '/users/:id',
            element: withSuspense(UserDetail),
            index: true,
            permissions: ['users:view'],
          },

          {
            path: '/users/create',
            element: withSuspense(UserForm),
            permissions: ['users:create'],
            index: true,
          },
          {
            path: '/users/:id/edit',
            element: withSuspense(UserForm),
            permissions: ['users:update'],
            index: true,
          },
        ],
      },
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
      {
        path: '/settings/ldap',
        name: 'ldap_settings',
        icon: <SafetyOutlined />,
        element: withSuspense(LDAPSetting),
        index: true,
        permissions: ['ldap:view'],
      },
      // Redirect and error handling
      {
        path: '*',
        element: withSuspense(NotFound),
        index: true,
      },
    ],
  },

  {
    is_private: true,
    layout: false,
    path: '/oidc/test',
    element: withSuspense(OIDCTestPage),
    index: true,
    permissions: ['oidc:view'],
  },
  {
    is_private: true,
    layout: false,
    path: '/oidc/authorize',
    element: withSuspense(OIDCAuthorize),
    index: true,
  },
];

export type IRoute = IRouteItem | IRouteGroup;

export interface IRouteItem {
  path?: string;
  element: React.ReactNode;
  name?: string;
  icon?: React.ReactNode;
  children?: undefined;
  is_private?: boolean;
  layout?: boolean;
  index: true;
  permissions?: string[];
}

export interface IRouteGroup {
  path?: string;
  element?: React.ReactNode;
  children: IRoute[];
  name?: string;
  icon?: React.ReactNode;
  is_private?: boolean;
  layout?: boolean;
  index?: false;
  permissions?: string[];
}

// Merge all routes
const routes: IRoute[] = [...publicRoutes, ...privateRoutes];

export default routes; 