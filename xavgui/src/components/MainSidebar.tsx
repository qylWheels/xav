import { useState } from "react";
import { Shield, Search, LayoutDashboard, Bolt } from "lucide-react";
import { NavLink } from 'react-router-dom';

function MainSidebar() {
    const menuItems = [
        { icon: LayoutDashboard, text: "Overview", to: "/overview" },
        { icon: Search, text: "Scan", to: "/scan" },
        { icon: Shield, text: "Protection", to: "/protection" },
        { icon: Bolt, text: "Settings", to: "/settings" }
    ]
    const [activeIndex, setActiveIndex] = useState(0)

    const majorVersion = "0"
    const minorVersion = "1"
    const patchVersion = "0"

    return (
        <div className="flex">
            <ul className="menu menu-md rounded-l-xl bg-base-200 w-48 h-full">
                <div data-tauri-drag-region className="flex items-center justify-center py-8">
                    <Shield data-tauri-drag-region size={36} className="pointer-events-none" />
                </div>
                {menuItems.map((item) => (
                    <li key={item.text} className="my-2">
                        <NavLink
                            className={`flex items-center ${activeIndex === menuItems.indexOf(item) ? 'menu-active' : ''}`}
                            to={item.to}
                            onClick={() => setActiveIndex(menuItems.indexOf(item))}>
                            <item.icon />
                            {item.text}
                        </NavLink>
                    </li>
                ))}
                <div className="badge badge-soft badge-success mt-auto self-center mb-4">{majorVersion}.{minorVersion}.{patchVersion}</div>
            </ul>
        </div>
    );
}

export default MainSidebar;
