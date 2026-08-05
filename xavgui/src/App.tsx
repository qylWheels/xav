import "@/index.css"
import "./App.css"
import { AppSidebar } from "@/components/app-sidebar";
import { SidebarProvider } from "@/components/ui/sidebar"
import TitleBar from "@/components/TitleBar"
import Overview from "@/views/Overview";
import Scan from "@/views/Scan";

function App({ children }: { children: React.ReactNode }) {
  return (
    <div className="w-screen h-screen bg-transparent p-4 overflow-hidden">
      <div className="w-full h-full bg-white rounded-xl shadow-lg">
        <TitleBar />
        <SidebarProvider style={
          {
            "--sidebar-width": "12rem",
          } as React.CSSProperties
        }>
          <AppSidebar />
          <main>
            <Scan />
            {children}
          </main>
        </SidebarProvider>
      </div>
    </div>
  );
}

export default App;
