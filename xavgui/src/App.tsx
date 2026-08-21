import "@/App.css"
import Overview from "@/views/Overview";
import Scan from "@/views/Scan";
import Protection from "@/views/Protection";
import ProcessViewer from "@/views/ProcessViewer";
import { Routes, Route } from 'react-router-dom';
import MainWindowLayout from "@/components/MainWindowLayout";
import Settings from "@/views/Settings";
import StandAloneWindowLayout from "@/components/StandAloneWindowLayout";
import WebSocket from '@tauri-apps/plugin-websocket';
import { WebviewWindow } from '@tauri-apps/api/webviewWindow';

function App() {
  const wsconnection = async () => {
    const ws = await WebSocket.connect('ws://0.0.0.0:8000');
    const removeListener = ws.addListener((msg) => {
      console.log('Received Message:', msg);
      new WebviewWindow('process-viewer', {
        url: '/#/process-viewer',
        width: 800,
        height: 600,
        decorations: false,
        transparent: true,
        shadow: false,
        maximizable: false,
        resizable: false
      });
    });
  }
  wsconnection();

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
    </Routes>
  );
}

export default App;