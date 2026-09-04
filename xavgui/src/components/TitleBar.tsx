import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";
import { Minus, X } from "lucide-react";

function TitleBar(props: { title: string }) {
    const handleClose = async () => {
        const currentWindow = getCurrentWebviewWindow();
        await currentWindow.close();
    };

    return (
        <div data-tauri-drag-region className="w-full h-1/9 flex items-center">
            <div data-tauri-drag-region className="font-bold m-auto">{props.title}</div>
            <div data-tauri-drag-region className="flex justify-end items-center p-4">
                <button className="btn btn-ghost btn-sm"><Minus size={16} /></button>
                <button className="btn btn-ghost btn-sm" onClick={handleClose}><X size={16} /></button>
            </div>
        </div>
    );
}

export default TitleBar;
