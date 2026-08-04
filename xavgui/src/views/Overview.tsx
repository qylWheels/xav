import { CircleCheck } from "lucide-react";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import {
    Card,
    CardContent,
} from "@/components/ui/card"
import { Separator } from "@/components/ui/separator";

function Overview() {
    return (
        <div className="relative min-h-screen">
            <div className="h-32"></div>
            <div className="container mx-auto p-6 space-y-4">
                <Label className="text-2xl font-bold">Xav is protecting your system</Label>
                <Card>
                    <CardContent className="flex justify-between items-center">
                        <div className="mr-4">
                            <Label>Scanned Files</Label>
                            <Label className="text-gray-500 mt-2">1,208</Label>
                        </div>
                        <Separator orientation="vertical" />
                        <div className="ml-4 mr-4">
                            <Label>Event Analyzed</Label>
                            <Label className="text-gray-500 mt-2">231,208</Label>
                        </div>
                        <Separator orientation="vertical" />
                        <div className="ml-4">
                            <Label>Database Version</Label>
                            <Label className="text-green-500 mt-2">2026-08-04.4</Label>
                        </div>
                    </CardContent>
                </Card>
                <Button variant="outline">Quick Scan</Button>
                <Button variant="link">Update</Button>
            </div>

            <div className="fixed right-0 top-1/2 -translate-y-1/2 pointer-events-none">
                <CircleCheck
                    className="w-56 h-56 text-green-200 mr-16 opacity-70"
                />
            </div>
        </div >
    );
}

export default Overview;
