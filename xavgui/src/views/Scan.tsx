import { Settings2, Zap } from "lucide-react";

function Scan() {
    const actions = ["Quarantine", "Delete", "Ignore", "Trust"]
    const scanResult = [
        {
            path: "/usr/bin/env",
            severity: "High",
            threat: "HEUR:Linux.Mirai.ax",
            action: "Quarantine",
        },
        {
            path: "/usr/bin/python",
            severity: "Medium",
            threat: "MEM:Linux.Botnet.s",
            action: "Quarantine",
        },
    ]

    return (
        <div className="w-full flex flex-col">
            <div className="mx-4 grid grid-cols-3 gap-4">
                <button className="btn btn-ghost h-15">
                    <Zap />
                    Quick Scan
                </button>
                <button className="btn btn-ghost h-15">
                    <Zap />
                    Full Scan
                </button>
                <button className="btn btn-ghost h-15">
                    <Settings2 />
                    Custom Scan
                </button>
            </div>
            <div className="h-4"></div>
            <div className="mx-8">
                <progress className="progress progress-success" value="26" max="100"></progress>
            </div>
            <div className="h-4"></div>
            <div className="mx-4">
                <table className="table table-pin-rows">
                    <thead>
                        <tr>
                            <th></th>
                            <td>Path</td>
                            <td>Severity</td>
                            <td>Threat</td>
                            <td>Action</td>
                        </tr>
                    </thead>
                    <tbody>
                        {scanResult.map((item, index) => (
                            <tr className="hover:bg-base-300">
                                <th>{index + 1}</th>
                                <td>{item.path}</td>
                                <td>
                                    <div className={`badge ${item.severity === "High" ? "badge-error" : "badge-warning"}`}>
                                        {item.severity}
                                    </div>
                                </td>
                                <td>{item.threat}</td>
                                <td>
                                    <select className="select">
                                        <option disabled selected>Choose an action</option>
                                        {actions.map((action) => (
                                            <option key={action}>{action}</option>
                                        ))}
                                    </select>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

export default Scan;
