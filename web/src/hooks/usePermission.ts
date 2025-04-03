import { useContext } from 'react';
import { AuthContext } from '../contexts/AuthContext';

/**
 * Permission hook, used to check if a user has a specific permission
 * 
 * Usage example:
 * const { hasPermission, hasAllPermissions, hasAnyPermission } = usePermission();
 * 
 * if (hasPermission('authorization:user:create')) {
 *   // The user has create user permission
 * }
 */
export const usePermission = () => {
  const { user } = useContext(AuthContext);

  // Whether the user is an admin
  const isAdminUser = (): boolean => {
    if (!user || !user.roles) return false;
    return user.roles.some(role => role.name === 'admin');
  };

  // Check if the user has a specific permission
  const hasPermission = (permission: string): boolean => {
    if (!user || !user.roles) return false;

    // Check if the user's role has the admin role
    if (isAdminUser()) return true;

    // If not admin, check if the role has the permission
    return user.roles.some(role => {
      if (!role.permissions) return false;
      return role.permissions.some(perm => perm.code === permission);
    });
  };

  // Check if the user has all the specified permissions
  const hasAllPermissions = (permissions: string[]): boolean => {
    return permissions.every(perm => hasPermission(perm));
  };

  // Check if the user has any of the specified permissions
  const hasAnyPermission = (permissions: string[]): boolean => {
    return permissions.some(perm => hasPermission(perm));
  };

  return {
    hasPermission,
    hasAllPermissions,
    hasAnyPermission,
    isAdmin: isAdminUser(),
    loading: !user
  };
};

export default usePermission;