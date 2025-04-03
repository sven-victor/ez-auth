import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import client from '../api/client';
import { getCurrentUser, logout as apiLogout } from '../api/base';


// Auth context type
export interface AuthContextType {
  user: API.User | null;
  token: string | null;
  loading: boolean;
  logout: () => void;
}

// Create auth context
export const AuthContext = createContext<AuthContextType>({
  user: null,
  token: null,
  loading: false,
  logout: () => { },
});

export const useAuth = () => useContext(AuthContext);

// Auth provider props
interface AuthProviderProps {
  children: ReactNode;
}

// Set token to axios and localStorage
const setAuthToken = (token: string | null) => {
  if (token) {
    localStorage.setItem('token', token);
    client.defaults.headers.common['Authorization'] = `Bearer ${token}`;
  } else {
    localStorage.removeItem('token');
    delete client.defaults.headers.common['Authorization'];
  }
};

// Auth provider component
export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<API.User | null>(null);
  const [token, setToken] = useState<string | null>(localStorage.getItem('token'));
  const [isLoading, setIsLoading] = useState(true);

  // Check if the user is logged in when initialized
  useEffect(() => {
    const initAuth = async () => {
      const storedToken = localStorage.getItem('token');
      if (storedToken) {
        setAuthToken(storedToken); // Ensure token is set to the axios header
        try {
          const currentUser = await getCurrentUser();
          // Handle the new API response format
          if (currentUser && typeof currentUser === 'object') {
            if ('code' in currentUser && currentUser.code === "0" && 'data' in currentUser) {
              setUser(currentUser.data as API.User);
            } else {
              setUser(currentUser as API.User);
            }
          }
        } catch (error) {
          console.error('Failed to get current user:', error);
          logout();
        }
      }
      setIsLoading(false);
    };

    initAuth();
  }, []);

  const logout = () => {
    apiLogout();
    setAuthToken(null); // Use the unified token setting function
    setToken(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        loading: isLoading,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}; 