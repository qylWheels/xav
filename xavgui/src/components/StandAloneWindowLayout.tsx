import { Outlet } from "react-router-dom";
import TitleBar from "./TitleBar";

function StandAloneWindowLayout() {
    return (
        <div className="w-screen h-screen bg-transparent p-2 overflow-hidden">
            <div className="w-full h-full bg-white rounded-xl shadow-lg flex">
                <div className="w-full h-full flex flex-col">
                    <TitleBar />
                    <div className="w-full h-auto">
                        <Outlet />
                    </div>
                </div>
            </div >
        </div >
    )
}

export default StandAloneWindowLayout;
