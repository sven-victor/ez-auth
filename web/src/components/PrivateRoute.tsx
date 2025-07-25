import React from 'react';
import { Navigate } from 'react-router-dom';
import { Spin } from 'antd';
import { useAuth } from '../hooks/useAuth';
import { usePermission } from '../hooks/usePermission';

interface PrivateRouteProps {
  element: React.ReactElement;
  requiredPermission?: string;
  requiredPermissions?: string[];
}

/**
 * Private route component, used to protect routes that need authentication
 * 
 * Usage example:
 * <PrivateRoute element={<ProtectedComponent />} />
 * 
 * With permission control:
 * <PrivateRoute element={<UserListComponent />} requiredPermission="user:view" />
 */
const PrivateRoute: React.FC<PrivateRouteProps> = ({
  element,
  requiredPermission,
  requiredPermissions,
}) => {
  const { user, loading } = useAuth();
  const { hasPermission, hasAllPermissions } = usePermission();

  // If loading, show loading state
  if (loading) {
    return (
      <div style={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        height: '100vh'
      }}>
        <Spin size="large" tip="Loading..." />
      </div>
    );
  }

  // If not logged in, redirect to login page
  if (!user) {
    window.location.href = '/console/login?redirect=' + encodeURIComponent(window.location.href);
    return null;
  }

  // If specific permission is required
  if (requiredPermission && !hasPermission(requiredPermission)) {
    return <Navigate to="/forbidden" replace />;
  }

  // If multiple permissions are required
  if (requiredPermissions && !hasAllPermissions(requiredPermissions)) {
    return <Navigate to="/forbidden" replace />;
  }

  // If logged in and has permission, return the original component
  return element;
};

/**
 * Admin route - only admins can access
 */
export const AdminRoute: React.FC<{ element: React.ReactElement }> = ({ element }) => {
  const { user, loading } = useAuth();
  const permissionHook = usePermission();

  // If loading, show loading state
  if (loading) {
    return (
      <div style={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        height: '100vh'
      }}>
        <Spin size="large" tip="Loading..." />
      </div>
    );
  }

  // If not logged in, redirect to login page
  if (!user) {
    window.location.href = '/console/login?redirect=' + encodeURIComponent(window.location.href);
    return null;
  }

  // If not an admin, redirect to 403 page
  if (!permissionHook.isAdmin) {
    return <Navigate to="/forbidden" replace />;
  }

  // If an admin, return the original component
  return element;
};

export default PrivateRoute; 