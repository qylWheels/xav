function Settings() {
    const proactiveProtectionStrategies = [
        "Rule Based Strategy", "Anomaly-Based Detection Strategy"
    ]
    const actionWhenDetectedMaliciousActivity = [
        "Kill Process", "Notify Only",
    ]

    return (
        <div className="flex flex-col mx-6">
            <h1 className="text-2xl font-bold">Settings</h1>
            <div className="card border mt-4">
                <div className="card-body">
                    <h2 className="card-title">Protection</h2>
                    <div className="divider divider-start font-bold">Proactive Protection</div>
                    <ul className="list">
                        <div className="collapse collapse-arrow bg-base-100 border border-base-300">
                            <input type="checkbox" />
                            <div className="collapse-title">Proactive Protection Strategy</div>
                            <div className="collapse-content">
                                {proactiveProtectionStrategies.map((strategy, _index) => (
                                    <fieldset className="fieldset">
                                        <label className="label">
                                            <input type="checkbox" defaultChecked className="checkbox" />
                                            {strategy}
                                        </label>
                                    </fieldset>
                                ))}
                            </div>
                        </div>
                        <div className="collapse collapse-arrow border border-base-300 mt-2">
                            <input type="checkbox" />
                            <div className="collapse-title">Action When Detected Malicious Activity</div>
                            <div className="collapse-content">
                                <select defaultValue="Choose an action" className="select">
                                    <option disabled={true}>Choose an action</option>
                                    {actionWhenDetectedMaliciousActivity.map((action, _index) => (
                                        <option>{action}</option>
                                    ))}
                                </select>
                            </div>
                        </div>
                    </ul>
                    <div className="divider divider-start font-bold">HIPS</div>
                </div>
            </div>
        </div>
    )
}

export default Settings;
