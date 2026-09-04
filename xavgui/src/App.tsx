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
  const unlisten = listen('threat-detected', (event) => {
    new WebviewWindow('on-access-scanning-alert', {
      url: '/#/on-access-scanning-alert?payload=' + encodeURIComponent(event.payload as string),
      width: 450,
      height: 230,
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
      <Route path="/" element={<MainWindowLayout title="xav" />}>
        <Route index element={<Overview />} />
        <Route path="/overview" element={<Overview />} />
        <Route path="/scan" element={<Scan />} />
        <Route path="/protection" element={<Protection />} />
        <Route path="/settings" element={<Settings />} />
      </Route>
      <Route path="/process-viewer" element={<StandAloneWindowLayout title="xav Process Viewer" />}>
        <Route index element={<ProcessViewer />} />
      </Route>
      <Route path="/on-access-scanning-alert" element={<StandAloneWindowLayout title="xav On-Access Scanning" />}>
        <Route index element={<OnAccessScanningAlert />} />
      </Route>
    </Routes >
  );
}

export default App;