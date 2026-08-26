import { useState } from "react";

function General() {
    const [useExactHashEngine, setUseExactHashEngine] = useState(true);
    const onClickExactHashEngineSwitch = () => {
        setUseExactHashEngine(!useExactHashEngine);
    }

    const [useFuzzyHashEngine, setUseFuzzyHashEngine] = useState(true);
    const onClickFuzzyHashEngineSwitch = () => {
        setUseFuzzyHashEngine(!useFuzzyHashEngine);
    }

    const [useStaticHeuristicDetectionEngine, setUseStaticHeuristicDetectionEngine] = useState(true);
    const onClickStaticHeuristicDetectionEngineSwitch = () => {
        setUseStaticHeuristicDetectionEngine(!useStaticHeuristicDetectionEngine);
    }

    const [useDynamicHeuristicDetectionEngine, setUseDynamicHeuristicDetectionEngine] = useState(true);
    const onClickDynamicHeuristicDetectionEngineSwitch = () => {
        setUseDynamicHeuristicDetectionEngine(!useDynamicHeuristicDetectionEngine);
    }

    return (
        <div>
            <div className="card border mt-4">
                <div className="card-body">
                    <h2 className="card-title">Scan Engine</h2>

                    <div className="divider divider-start font-bold">Exact Hash Engine</div>
                    <div className="flex flex-col">
                        <label className="label text-base-content">
                            <input type="checkbox" className="toggle" defaultChecked onClick={onClickExactHashEngineSwitch} />
                            {useExactHashEngine ? "On" : "Off"}
                        </label>
                    </div>

                    <div className="divider divider-start font-bold">Fuzzy Hash Engine</div>
                    <div className="flex flex-col">
                        <label className="label text-base-content">
                            <input type="checkbox" className="toggle" defaultChecked onClick={onClickFuzzyHashEngineSwitch} />
                            {useFuzzyHashEngine ? "On" : "Off"}
                        </label>
                    </div>

                    <div className="divider divider-start font-bold">Static Heuristic Detection Engine</div>
                    <div className="flex flex-col">
                        <label className="label text-base-content">
                            <input type="checkbox" className="toggle" defaultChecked onClick={onClickStaticHeuristicDetectionEngineSwitch} />
                            {useStaticHeuristicDetectionEngine ? "On" : "Off"}
                        </label>
                    </div>

                    <div className="divider divider-start font-bold">Dynamic Heuristic Detection Engine</div>
                    <div className="flex flex-col">
                        <label className="label text-base-content">
                            <input type="checkbox" className="toggle" defaultChecked onClick={onClickDynamicHeuristicDetectionEngineSwitch} />
                            {useDynamicHeuristicDetectionEngine ? "On" : "Off"}
                        </label>
                    </div>
                </div>
            </div>
        </div >
    )
}

export default General;
