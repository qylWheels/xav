import MainSidebar from "@/components/MainSidebar";
import TitleBar from "@/components/TitleBar";
import { Outlet } from "react-router-dom";

function MainWindowLayout() {
    return (
        <div className="w-screen h-screen bg-transparent p-2 overflow-hidden">
            <div className="w-full h-full bg-white rounded-xl shadow-lg flex">
                <MainSidebar />
                <div className="w-full h-full flex flex-col">
                    <TitleBar title="" />
                    <div className="w-full h-full overflow-y-auto">
                        <Outlet />
                    </div>
                </div>
            </div >
        </div >
    )
}

export default MainWindowLayout;