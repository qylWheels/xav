function Protection() {
    return (
        <div className="w-full flex flex-col">
            <div className="card border mx-4">
                <div className="card-body">
                    <h2 className="card-title">Proactive Protection</h2>
                    <p>Monitor and analyze process behaviors to detect and prevent potential/unknown threats</p>
                    <div className="card-actions justify-end">
                        <button className="btn btn-primary">Buy Now</button>
                    </div>
                </div>
            </div>
            <div className="card border mx-4 mt-4">
                <div className="card-body">
                    <h2 className="card-title">HIPS</h2>
                    <p>HIPS (Host Intrusion Prevention System) blocks malicious behaviors to mitigate the risk of malware attacks</p>
                    <div className="card-actions justify-end">
                        <button className="btn btn-primary">Buy Now</button>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default Protection;
