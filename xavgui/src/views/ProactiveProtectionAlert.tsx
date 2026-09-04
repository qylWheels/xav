import { ShieldAlert } from "lucide-react";
import { useSearchParams } from 'react-router-dom';

function ProactiveProtectionAlert() {
    const [searchParams] = useSearchParams();
    const payload =
        decodeURIComponent(searchParams.get('payload') || '{}')
    const j = JSON.parse(payload);

    return (
        <div className="flex flex-col items-center">
            <div className="flex flex-col items-center w-full bg-red-50 pb-4 pt-2">
                <ShieldAlert color="var(--color-error)" size={48} className="mt-4" />
                <div className="text-2xl font-bold mt-6">Active Threat Detected</div>
                <div className="mt-2">Xav has just detected an active threat</div>
            </div>
            <div className="mt-4 flex items-center">
                <div>Location:</div>
                <div className="link ml-2 text-blue-500 max-w-64 truncate" title={j.path}>{j.path}</div>
            </div>
            <div className="flex items-center">
                <div>Threat:</div>
                <div className="ml-2 text-error max-w-64 truncate" title={j.threat_name}>{j.threat_name}</div>
            </div>
            <div className="mt-6 flex flex-col">
                <div className="flex justify-end gap-2">
                    <button className="btn">Ignore</button>
                    <button className="btn btn-success justify-self-end">Kill Process and Quarantine (Recommended)</button>
                    <button className="btn btn-soft btn-success justify-self-end">Kill Process Only</button>
                </div>
                <div className="mt-4 flex justify-center">
                    <button className="btn btn-link text-neutral">Add to Exclusion List</button>
                    <button className="btn btn-link text-neutral">Details</button>
                </div>
            </div>
        </div >
    );
}

export default ProactiveProtectionAlert;
