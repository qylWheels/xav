function Protection() {
    return (
        <div>
            <div className="card border mt-4">
                <div className="card-body">
                    <h2 className="card-title">On-Access Scanning</h2>

                    <div className="divider divider-start font-bold">Timing</div>
                    <div className="flex flex-col">
                        <label className="label text-base-content">
                            <input type="radio" name="timing" className="radio" defaultChecked />
                            Before execution (Low performance impact)
                        </label>
                        <label className="label text-base-content mt-4">
                            <input type="radio" name="timing" className="radio" />
                            Before execution and read (High performance impact)
                        </label>
                    </div>

                    <div className="divider divider-start font-bold">Action When Detected Threat</div>
                    <div className="flex flex-col">
                        <label className="label text-base-content">
                            <input type="radio" name="action" className="radio" defaultChecked />
                            Ask me
                        </label>
                        <label className="label text-base-content mt-4">
                            <input type="radio" name="action" className="radio" />
                            Quarantine automatically
                        </label>
                    </div>
                </div>
            </div>
        </div >
    )
}

export default Protection;
