import { ShieldAlert } from "lucide-react";
import { useSearchParams } from 'react-router-dom';

function OnAccessScanningAlert() {
    const [searchParams] = useSearchParams();
    const payload =
        decodeURIComponent(searchParams.get('payload') || '{}')

    return (
        <div className="flex flex-col">
            <div className="flex mt-4">
                <ShieldAlert color="var(--color-error)" size={48} className="ml-8" />
                <div className="flex flex-col ml-4">
                    <div className="text-2xl font-bold">Threat Blocked</div>
                    <div>Xav has just blocked a threat</div>
                    <div className="mt-4 flex items-center">
                        <div>Location:</div>
                        <div className="link ml-2 text-blue-500 truncate max-w-64">{payload}</div>
                    </div>
                    <div className="flex items-center">
                        <div>Threat:</div>
                        <div className="ml-2 text-error truncate max-w-64">哈牛魔</div>
                    </div>
                </div>
            </div>
            <div className="mt-8">
                <div className="flex justify-end gap-2 mr-4">
                    <button className="btn btn-link text-neutral">Add to Exclusion List</button>
                    <button className="btn">Ignore</button>
                    <button className="btn btn-success justify-self-end">Quarantine</button>
                </div>
            </div>
        </div>
    );
}

export default OnAccessScanningAlert;
