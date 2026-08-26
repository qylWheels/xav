import Protection from '@/views/settings/Protection';

function Settings() {
    return (
        <div className="flex flex-col mx-6">
            <h1 className="text-2xl font-bold">Settings</h1>
            <div className="tabs tabs-border mt-2">
                <input type="radio" name="settings_tab" className="tab" aria-label="General" defaultChecked />
                <input type="radio" name="settings_tab" className="tab" aria-label="Scan" />

                <input type="radio" name="settings_tab" className="tab" aria-label="Protection" />
                <div className="tab-content">
                    <Protection />
                </div>
            </div>
        </div>
    )
}

export default Settings;
