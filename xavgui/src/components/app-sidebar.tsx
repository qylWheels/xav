import {
    Sidebar,
    SidebarContent,
    SidebarHeader,
    SidebarMenu,
    SidebarMenuButton,
    SidebarTrigger,
    SidebarMenuItem,
    SidebarGroup,
    SidebarGroupContent,
} from "@/components/ui/sidebar"
import { Separator } from "@/components/ui/separator"
import { Compass, Search, Shield, Settings } from "lucide-react"

const menuItems = [
    { title: "Overview", url: "#", icon: Compass },
    { title: "Scan", url: "#", icon: Search },
    { title: "Protection", url: "#", icon: Shield },
    { title: "Settings", url: "#", icon: Settings },
]

export function AppSidebar() {
    return (
        <Sidebar variant="floating" collapsible="icon" className="h-[45vh] mt-[15vh]">
            <SidebarHeader>
                <SidebarTrigger />
            </SidebarHeader>
            <Separator />
            <SidebarContent>
                <SidebarGroup>
                    <SidebarGroupContent>
                        <SidebarMenu>
                            {menuItems.map((item) => (
                                <SidebarMenuItem key={item.title}>
                                    <SidebarMenuButton>
                                        <item.icon />
                                        <span>{item.title}</span>
                                    </SidebarMenuButton>
                                </SidebarMenuItem>
                            ))}
                        </SidebarMenu>
                    </SidebarGroupContent>
                </SidebarGroup>
            </SidebarContent>
        </Sidebar>
    )
}