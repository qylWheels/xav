import { ChevronDown, ChevronUp, ShieldCheck } from "lucide-react";

function Overview() {
    return (
        <div className="flex-col">
            <div className="w-full h-16"></div>
            <div className="flex">
                <ShieldCheck size={64} color="var(--color-success)" className="ml-16 mr-8" />
                <div className="flex-col">
                    <div className="text-2xl font-bold">Your System is Safe</div>
                    <div className="mt-2">XAV is Protecting Your System</div>
                </div>
            </div>
            <div className="w-full h-16"></div>
            <div className="stats shadow mx-8 grid grid-rows-1 grid-cols-2">
                <div className="stat">
                    <div className="stat-title">Software Version</div>
                    <div className="stat-value">0.1.0</div>
                    <div className="stat-actions">
                        <button className="btn btn-soft btn-xs btn-success">Update</button>
                    </div>
                </div>
                <div className="stat">
                    <div className="stat-title">Database Version</div>
                    <div className="stat-value">2026.08.19.001</div>
                    <div className="stat-actions">
                        <button className="btn btn-soft btn-xs btn-success">Update</button>
                    </div>
                </div>
            </div>
            <div className="w-full h-6"></div>
            <div className="stats shadow mx-8 grid grid-rows-1 grid-cols-2">
                <div className="stat">
                    <div className="stat-title">Scanned Object(s)</div>
                    <div className="stat-value">29,882</div>
                    <div className="stat-desc flex">
                        <ChevronUp size={16} className="mr-1" color="var(--color-error)" />
                        <span className="text-error">21%</span>
                        <span className="ml-1">than last week</span>
                    </div>
                </div>
                <div className="stat">
                    <div className="stat-title">Blocked Object(s)</div>
                    <div className="stat-value">
                        <div className="text-error">
                            4
                        </div>
                    </div>
                    <div className="stat-desc flex">
                        <ChevronDown size={16} className="mr-1" color="var(--color-success)" />
                        <span className="text-success">84%</span>
                        <span className="ml-1">than last week</span>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default Overview;
