import { ShieldCheck } from "lucide-react";

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
        </div>
    );
}

export default Overview;
