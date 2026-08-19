import "@/App.css"
import Overview from "@/views/Overview";
import Scan from "@/views/Scan";
import Protection from "@/views/Protection";
import ProcessTree from "@/views/ProcessTree";
import { Routes, Route } from 'react-router-dom';
import MainWindowLayout from "@/components/MainWindowLayout";
import Settings from "@/views/Settings";
import StandAloneWindowLayout from "@/components/StandAloneWindowLayout";

function App() {
  return (
    <Routes>
      <Route path="/" element={<MainWindowLayout />}>
        <Route index element={<Overview />} />
        <Route path="/overview" element={<Overview />} />
        <Route path="/scan" element={<Scan />} />
        <Route path="/protection" element={<Protection />} />
        <Route path="/settings" element={<Settings />} />
      </Route>
      <Route path="/process-tree" element={<StandAloneWindowLayout />}>
        <Route index element={<ProcessTree />} />
      </Route>
    </Routes>
  );
}

export default App;