import { Ellipsis } from "lucide-react";

function ProcessViewer() {
    const processListSlice = [
        {
            pid: 296,
            path: "/bin/ssh",
            securityLevel: "High",
        },
        {
            pid: 300,
            path: "/bin/bash",
            securityLevel: "Medium",
        },
        {
            pid: 301,
            path: "/bin/mirai",
            securityLevel: "Low",
        },
    ];
    const processList = Array(100).fill(processListSlice).flat();

    const securityLevelToStatus = (securityLevel: string) => {
        if (securityLevel === "Low") {
            return "status-error";
        }
        if (securityLevel === "Medium") {
            return "status-warning";
        }
        if (securityLevel === "High") {
            return "status-success";
        }
        throw new Error("Invalid security level");
    }

    return (
        <div>
            <div className="card card-border bg-base-100">
                <div className="card-body">
                    <h2 className="card-title">Active Processes</h2>
                    <table className="table table-pin-rows mt-2">
                        <thead>
                            <tr>
                                <th>PID</th>
                                <td>Path</td>
                                <td>Security Level</td>
                                <th></th>
                            </tr>
                        </thead>
                        <tbody>
                            {processList.map((item, _index) => (
                                <tr className="hover:bg-base-300">
                                    <th>{item.pid}</th>
                                    <td>{item.path}</td>
                                    <td>
                                        <div>
                                            <div className="inline-grid *:[grid-area:1/1]  ">
                                                <div className={`status ${securityLevelToStatus(item.securityLevel)} ${item.securityLevel === "Low" ? "animate-ping" : ""}`}></div>
                                                <div className={`status ${securityLevelToStatus(item.securityLevel)}`}></div>
                                            </div>
                                            <span className="ml-4">{item.securityLevel}</span>
                                        </div>
                                    </td>
                                    <td>
                                        <button><Ellipsis /></button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>

        </div>
    );
}

export default ProcessViewer;
