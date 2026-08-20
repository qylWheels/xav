import { AppWindow, Boxes, LayoutList, ShieldBan, SquareChartGantt } from "lucide-react";
// import { WebviewWindow } from '@tauri-apps/api/webviewWindow';

function Protection() {
    // const onOpenProcessViewerBtnClick = async () => {
    //     new WebviewWindow('process-viewer', {
    //         url: '/#/process-viewer',
    //         width: 800,
    //         height: 600,
    //         decorations: false,
    //         transparent: true,
    //         shadow: false,
    //         maximizable: false,
    //         resizable: false
    //     });
    // };

    return (
        <div className="flex flex-col mb-8 mx-6">
            <h1 className="text-2xl font-bold">Protection</h1>
            <div className="card border mt-4">
                <div className="card-body">
                    <h2 className="card-title">Proactive Protection</h2>
                    <p>Monitor and analyze process behaviors to detect and prevent potential/unknown threats</p>
                    <div className="flex items-center">
                        <div className="stat flex-2">
                            <div className="stat-title">Active Process</div>
                            <div className="stat-value">813</div>
                            <div className="stat-figure">
                                <AppWindow />
                            </div>
                        </div>
                        <div className="stat flex-3">
                            <div className="stat-title">Total Events</div>
                            <div className="stat-value">123,972</div>
                            <div className="stat-figure">
                                <SquareChartGantt />
                            </div>
                        </div>
                    </div>
                    {/* <button className="btn mt-2" onClick={onOpenProcessViewerBtnClick}>Open Process Viewer</button> */}
                    <div className="flex justify-end">
                        <button className="btn btn-link pl-0">Settings</button>
                    </div>
                </div>
            </div>
            <div className="card border mt-6">
                <div className="card-body">
                    <h2 className="card-title">HIPS</h2>
                    <p>HIPS (Host Intrusion Prevention System) blocks malicious behaviors to mitigate the risk of malware attacks</p>
                    <div className="flex items-center">
                        <div className="stat flex-1">
                            <div className="stat-title">Total Rule Groups</div>
                            <div className="stat-value">12</div>
                            <div className="stat-figure">
                                <Boxes />
                            </div>
                        </div>
                        <div className="stat flex-1">
                            <div className="stat-title">Total Rules</div>
                            <div className="stat-value">291</div>
                            <div className="stat-figure">
                                <LayoutList />
                            </div>
                        </div>
                        <div className="stat flex-1">
                            <div className="stat-title">Blocked Behavior(s)</div>
                            <div className="stat-value text-error">71</div>
                            <div className="stat-figure">
                                <ShieldBan />
                            </div>
                        </div>
                    </div>
                    <div className="flex justify-end">
                        <button className="btn btn-link pl-0">Settings</button>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default Protection;
