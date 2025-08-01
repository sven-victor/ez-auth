import { QueryClient, QueryClientProvider } from 'react-query';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ConfigProvider } from 'antd';
import enUS from 'antd/lib/locale/en_US';
import deDE from 'antd/lib/locale/de_DE';
import esES from 'antd/lib/locale/es_ES';
import frFR from 'antd/lib/locale/fr_FR';
import arEG from 'antd/lib/locale/ar_EG';
import svSE from 'antd/lib/locale/sv_SE';
import zhCN from 'antd/lib/locale/zh_CN';
import routes, { IRoute } from './routes';
import { AuthProvider } from './contexts/AuthContext';
import PrivateRoute from './components/PrivateRoute';
import AppLayout from './components/Layout';
import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';


const antdLocales: { [key: string]: any } = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'de-DE': deDE,
  'es-ES': esES,
  'fr-FR': frFR,
  'ar-AE': arEG,
  'sv-SE': svSE,
};


// Create React Query client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
});

function App() {
  const { i18n } = useTranslation();
  const [antdLocale, setAntdLocale] = useState(antdLocales[i18n.language] || enUS);

  useEffect(() => {
    setAntdLocale(antdLocales[i18n.language] || enUS);
  }, [i18n.language]);
  const renderRoutes = (routes: IRoute[], parentRoute?: IRoute) => {

    return routes.flatMap((route) => {
      if (route.is_private) {
        return [route];
      }
      if ('children' in route && route.children) {
        return route.children;
      }
      return [route];
    }).map((route, index,) => {
      const element = route.is_private ? <PrivateRoute element={route.layout === undefined || route.layout ? <AppLayout /> : <>{route.element}</>} /> : route.element
      if ('children' in route && route.children && route.children.length > 0) {
        return <Route key={route.path ?? route.name ?? index} path={route.path} element={element} >
          {renderRoutes(route.children, route)}
        </Route>
      }
      const { path } = route;
      return <Route key={path ?? route.name ?? `${parentRoute?.path ?? ''}.${index}`} path={path} index={route.index} element={element} />
    }).filter(Boolean);
  }

  return (
    <QueryClientProvider client={queryClient}>
      <ConfigProvider locale={antdLocale}>
        <AuthProvider>
          <Router basename={'/ui/'}>
            <Routes>
              {renderRoutes(routes)}
            </Routes>
          </Router>
        </AuthProvider>
      </ConfigProvider>
    </QueryClientProvider>
  );
}

export default App; 