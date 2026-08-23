import "@/App.css"
import Overview from "@/views/Overview";
import Scan from "@/views/Scan";
import Protection from "@/views/Protection";
import ProcessViewer from "@/views/ProcessViewer";
import { Routes, Route } from 'react-router-dom';
import MainWindowLayout from "@/components/MainWindowLayout";
import Settings from "@/views/Settings";
import StandAloneWindowLayout from "@/components/StandAloneWindowLayout";
import { WebviewWindow } from '@tauri-apps/api/webviewWindow';
import OnAccessScanningAlert from "@/views/OnAccessScanningAlert";
import { listen } from '@tauri-apps/api/event';

function App() {
  const unlisten = listen('threat-detected', (payload) => {
    new WebviewWindow('on-access-scanning-alert', {
      url: '/#/on-access-scanning-alert',
      width: 450,
      height: 250,
      center: true,
      decorations: false,
      transparent: true,
      shadow: false,
      maximizable: false,
      resizable: false
    });
  })

  return (
    <Routes>
      <Route path="/" element={<MainWindowLayout />}>
        <Route index element={<Overview />} />
        <Route path="/overview" element={<Overview />} />
        <Route path="/scan" element={<Scan />} />
        <Route path="/protection" element={<Protection />} />
        <Route path="/settings" element={<Settings />} />
      </Route>
      <Route path="/process-viewer" element={<StandAloneWindowLayout />}>
        <Route index element={<ProcessViewer />} />
      </Route>
      <Route path="/on-access-scanning-alert" element={<StandAloneWindowLayout />}>
        <Route index element={<OnAccessScanningAlert />} />
      </Route>
    </Routes >
  );
}

export default App;