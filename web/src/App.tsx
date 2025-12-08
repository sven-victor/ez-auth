import "@/i18n";
import { transformRouter, transformSettingTabs, PrivateRoutes, publicRoutes } from './routes';
import { EZApp } from 'ez-console';



function App() {
  return (
    <EZApp
      basePath='/'
      extraPublicRoutes={publicRoutes}
      extraPrivateRoutes={PrivateRoutes}
      transformRouter={transformRouter}
      transformSettingTabs={transformSettingTabs}
    />
  );
}

export default App; 