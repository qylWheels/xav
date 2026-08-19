import "@/index.css"
import "@/App.css"
import Overview from "@/views/Overview";
import Scan from "@/views/Scan";
import { Shield, Search, LayoutDashboard, Bolt, Minus, X } from "lucide-react";

function App() {
  const menuItems = [
    { icon: LayoutDashboard, text: "Overview" },
    { icon: Search, text: "Scan" },
    { icon: Shield, text: "Protection" },
    { icon: Bolt, text: "Settings" }
  ]
  const majorVersion = "0"
  const minorVersion = "1"
  const patchVersion = "0"

  return (
    <div className="w-screen h-screen bg-transparent p-2 overflow-hidden">
      <div className="w-full h-full bg-white rounded-xl shadow-lg flex">
        <ul className="menu menu-md rounded-l-xl bg-base-200 w-48 h-full">
          <div data-tauri-drag-region className="flex items-center justify-center py-8">
            <Shield data-tauri-drag-region size={36} className="pointer-events-none" />
          </div>
          {menuItems.map((item) => (
            <li key={item.text} className="my-2">
              <a className="flex items-center">
                <item.icon />
                {item.text}
              </a>
            </li>
          ))}
          <div className="badge badge-soft badge-success mt-auto self-center mb-4">{majorVersion}.{minorVersion}.{patchVersion}</div>
        </ul>
        <div className="w-full h-full flex-col">
          <div data-tauri-drag-region className="w-full h-1/9 flex justify-end items-center p-4">
            <button className="btn btn-ghost btn-sm"><Minus size={16} /></button>
            <button className="btn btn-ghost btn-sm"><X size={16} /></button>
          </div>
          <div className="w-full h-auto">
            <Overview />
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
