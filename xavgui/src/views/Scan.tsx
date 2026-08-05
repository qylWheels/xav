import {
    Table,
    TableBody,
    TableCaption,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from "@/components/ui/table"
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import {
    Field,
    FieldContent,
    FieldDescription,
    FieldLabel,
    FieldTitle,
} from "@/components/ui/field"
import { Button } from "@/components/ui/button";
import {
    Select,
    SelectContent,
    SelectGroup,
    SelectItem,
    SelectLabel,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select"
import { ScrollArea } from "@/components/ui/scroll-area"

function Scan() {
    const actions = [
        { label: "Quarantine", value: "quarantine" },
        { label: "Delete", value: "delete" },
        { label: "Ignore", value: "ignore" }
    ];

    return (
        <div className="container max-h-screen pr-6 pb-32">
            <RadioGroup defaultValue="plus" className="w-full flex flex-row gap-4">
                <FieldLabel>
                    <Field orientation="horizontal">
                        <FieldContent>
                            <FieldTitle>Quick Scan</FieldTitle>
                            <FieldDescription>
                                Scan critical area of your system.
                            </FieldDescription>
                        </FieldContent>
                        <RadioGroupItem value="quick" id="quick-scan" />
                    </Field>
                </FieldLabel>
                <FieldLabel>
                    <Field orientation="horizontal">
                        <FieldContent>
                            <FieldTitle>Full Scan</FieldTitle>
                            <FieldDescription>
                                Scan all areas of your system.
                            </FieldDescription>
                        </FieldContent>
                        <RadioGroupItem value="full" id="full-scan" />
                    </Field>
                </FieldLabel>
                <FieldLabel>
                    <Field orientation="horizontal">
                        <FieldContent>
                            <FieldTitle>Custom Scan</FieldTitle>
                            <FieldDescription>
                                Scan areas that you want.
                            </FieldDescription>
                        </FieldContent>
                        <RadioGroupItem value="enterprise" id="enterprise-plan" />
                    </Field>
                </FieldLabel>
            </RadioGroup>
            <div className="h-4"></div>
            <Button variant="default" className="w-full">Start Scan</Button>
            <div className="h-2"></div>
            <ScrollArea className="h-[57vh] w-full p-4">
                <Table className="w-full">
                    <TableCaption>Detected threat(s).</TableCaption>
                    <TableHeader className="sticky top-0 z-10 bg-background">
                        <TableRow>
                            <TableHead>Path</TableHead>
                            <TableHead>Threat Name</TableHead>
                            <TableHead>Action</TableHead>
                        </TableRow>
                    </TableHeader>
                    <TableBody>
                        {Array.from({ length: 20 }).map((_i) => (
                            <TableRow>
                                <TableCell>/home/user/.bashrc</TableCell>
                                <TableCell className="text-red-500">Generic.ailiw32</TableCell>
                                <TableCell>
                                    <Select items={actions}>
                                        <SelectTrigger className="w-full max-w-48">
                                            <SelectValue />
                                        </SelectTrigger>
                                        <SelectContent>
                                            <SelectGroup>
                                                <SelectLabel>Action</SelectLabel>
                                                {actions.map((item) => (
                                                    <SelectItem key={item.value} value={item.value}>
                                                        {item.label}
                                                    </SelectItem>
                                                ))}
                                            </SelectGroup>
                                        </SelectContent>
                                    </Select>
                                </TableCell>
                            </TableRow>
                        ))}
                    </TableBody>
                </Table>
            </ScrollArea>
            <div className="h-2"></div>
            <Button className="w-full">Execute Actions</Button>
        </div>
    );
}

export default Scan;
