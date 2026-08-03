import { Button } from "@/components/ui/button"
import { X, Minus } from "lucide-react";

function TitleBar() {
    return (
        <div data-tauri-drag-region className="w-full h-12 grid grid-cols-3 items-center px-4 select-none">
            <div data-tauri-drag-region></div>

            <div data-tauri-drag-region className="text-center font-semibold text-sm tracking-wide">
                Xav
            </div>

            <div className="flex items-center gap-3 justify-self-end">
                <Button size="icon" variant="ghost"><Minus /></Button>
                <Button size="icon" variant="ghost"><X /></Button>
            </div>

        </div>
    );
}

export default TitleBar;
