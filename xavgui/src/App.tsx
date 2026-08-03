import "@/index.css"
import "./App.css"
import { AppSidebar } from "@/components/app-sidebar";
import { SidebarProvider } from "@/components/ui/sidebar"

function App({ children }: { children: React.ReactNode }) {
  return (
    <SidebarProvider style={
      {
        "--sidebar-width": "12rem",
      } as React.CSSProperties
    }>
      <AppSidebar />
      <main>
        {children}
      </main>
    </SidebarProvider>
  );
}

export default App;
