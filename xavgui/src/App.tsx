import "@/App.css"
import Overview from "@/views/Overview";
import Scan from "@/views/Scan";
import Protection from "@/views/Protection";
import { Shield, Search, LayoutDashboard, Bolt, Minus, X } from "lucide-react";
import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom';
import { useState } from "react";

function App() {
  return (
    <div className="w-screen h-screen bg-transparent p-2 overflow-hidden">
      <div className="w-full h-full bg-white rounded-xl shadow-lg flex">
        <BrowserRouter>
          <MainSidebar />
          <div className="w-full h-full flex-col">
            <TitleBar />
            <div className="w-full h-auto">
              <Routes>
                <Route path="/" element={<Overview />} />
                <Route path="/overview" element={<Overview />} />
                <Route path="/scan" element={<Scan />} />
                <Route path="/protection" element={<Protection />} />
              </Routes>
            </div>
          </div>
        </BrowserRouter>
      </div>
    </div >
  );
}

export default App;
