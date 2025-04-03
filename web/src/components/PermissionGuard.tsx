import React, { ReactNode } from 'react';
import { usePermission } from '../hooks/usePermission';

interface PermissionGuardProps {
  permission?: string;
  permissions?: string[];
  checkAll?: boolean; // Whether to check all permissions, default is false (check any one permission)
  fallback?: ReactNode; // Content to display when there is no permission
  children: ReactNode;
}

/**
 * Permission guard component - control the display of content based on user permissions
 * 
 * @param permission Single required permission code
 * @param permissions Multiple required permission codes array
 * @param checkAll When providing multiple permissions, check all permissions (true) or any one permission (false, default)
 * @param fallback Content to display when there is no permission
 * @param children Content to display when there is permission
 */
export const PermissionGuard: React.FC<PermissionGuardProps> = ({
  permission,
  permissions = [],
  checkAll = false,
  fallback = null,
  children,
}) => {
  const { hasPermission, hasAnyPermission, hasAllPermissions, isAdmin, loading } = usePermission();

  // When loading, do not display any content
  if (loading) {
    return null;
  }

  // Admins have all permissions
  if (isAdmin) {
    return <>{children}</>;
  }

  // Single permission check
  if (permission) {
    return hasPermission(permission) ? <>{children}</> : <>{fallback}</>;
  }

  // Multiple permissions check
  if (permissions.length > 0) {
    const hasAccess = checkAll
      ? hasAllPermissions(permissions)
      : hasAnyPermission(permissions);

    return hasAccess ? <>{children}</> : <>{fallback}</>;
  }

  // No specified permission requirements, default display content
  return <>{children}</>;
};

/**
 * Admin guard component - only admins can view content
 */
export const AdminGuard: React.FC<Omit<PermissionGuardProps, 'permission' | 'permissions' | 'checkAll'>> = ({
  fallback = null,
  children,
}) => {
  const { isAdmin, loading } = usePermission();

  if (loading) {
    return null;
  }

  return isAdmin ? <>{children}</> : <>{fallback}</>;
}; 