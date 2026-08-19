import "@/index.css"
import "@/App.css"
import Overview from "@/views/Overview";
import Scan from "@/views/Scan";
import { Shield, Search, LayoutDashboard, Bolt } from "lucide-react";

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
      <div className="w-full h-full bg-white rounded-xl shadow-lg">
        <ul className="menu menu-md rounded-l-xl bg-base-200 w-40 h-full">
          <div className="flex items-center justify-center my-8">
            <Shield size={36} />
          </div>
          {menuItems.map((item) => (
            <li key={item.text} className="my-2">
              <a className="flex items-center">
                <item.icon />
                {item.text}
              </a>
            </li>
          ))}
          <span className="mt-auto self-center mb-4">{majorVersion}.{minorVersion}.{patchVersion}</span>
        </ul>
      </div>
    </div>
  );
}

export default App;
