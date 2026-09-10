import { Ellipsis } from "lucide-react";

function ProcessViewer() {
    const processListSlice = [
        {
            pid: 296,
            path: "/bin/ssh",
            commandLine: "ssh -T asdlko@slic9.comsdddddddddddddddddddddddddddd",
            eventCount: 100,
            eventsViolatedRules: 50,
            severityScore: "83",
            severityLevel: "High",
        },
        {
            pid: 300,
            path: "/bin/bash",
            commandLine: "bash",
            eventCount: 2918,
            eventsViolatedRules: 12,
            severityScore: "42",
            severityLevel: "Medium",
        },
        {
            pid: 301,
            path: "/bin/mirai",
            commandLine: "mirai",
            eventCount: 100,
            eventsViolatedRules: 1,
            severityScore: "31",
            severityLevel: "Low",
        },
    ];
    const processList = Array(100).fill(processListSlice).flat();

    const severityLevelToStatus = (severityLevel: string) => {
        if (severityLevel === "High") {
            return "status-error";
        }
        if (severityLevel === "Medium") {
            return "status-warning";
        }
        if (severityLevel === "Low") {
            return "status-success";
        }
        throw new Error("Invalid severity level");
    }

    return (
        <div>
            <div className="card card-border bg-base-100">
                <div className="card-body">
                    <h2 className="card-title">Active Processes</h2>
                    <div className="overflow-y-auto h-115">
                        <table className="table table-pin-rows mt-2 whitespace-nowrap">
                            <thead>
                                <tr>
                                    <td>PID</td>
                                    <td>Path</td>
                                    <td>Command Line</td>
                                    <td>Event Count</td>
                                    <td>Events Violated Rules</td>
                                    <td>Severity Score</td>
                                    <td>Actions</td>
                                </tr>
                            </thead>
                            <tbody>
                                {processList.map((item, _index) => (
                                    <tr className="hover:bg-base-300">
                                        <th>{item.pid}</th>
                                        <td className="max-w-32 truncate">{item.path}</td>
                                        <td className="max-w-48 truncate">{item.commandLine}</td>
                                        <td>{item.eventCount}</td>
                                        <td className="text-bold">{item.eventsViolatedRules}</td>
                                        <td>
                                            <div>
                                                <div className="inline-grid *:[grid-area:1/1]  ">
                                                    <div className={`status ${severityLevelToStatus(item.severityLevel)} ${item.severityLevel === "High" ? "animate-ping" : ""}`}></div>
                                                    <div className={`status ${severityLevelToStatus(item.severityLevel)}`}></div>
                                                </div>
                                                <span className="ml-4">{item.severityLevel} ({item.severityScore})</span>
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

        </div>
    );
}

export default ProcessViewer;
