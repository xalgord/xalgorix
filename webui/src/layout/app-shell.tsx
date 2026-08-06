import { useCallback, useEffect, useState } from "react";
import { Outlet, useLocation } from "react-router-dom";
import { Sidebar } from "./sidebar";
import { Topbar } from "./topbar";
import { ConnectionBanner } from "@/components/connection-status";
import { LegacyImportBanner } from "@/components/legacy-import-banner";
import { CommandPalette } from "@/components/command-palette";
import { useWSStore } from "@/store/ws";

export function AppShell() {
  const connect = useWSStore((s) => s.connect);
  const disconnect = useWSStore((s) => s.disconnect);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const location = useLocation();

  useEffect(() => {
    connect();
    return () => disconnect();
  }, [connect, disconnect]);

  // Close mobile sidebar on navigation
  useEffect(() => {
    setSidebarOpen(false);
  }, [location.pathname]);

  const handleSidebarToggle = useCallback(() => setSidebarOpen((o) => !o), []);
  const handleSidebarClose = useCallback(() => setSidebarOpen(false), []);

  // No bg-background on the shell: body paints it, so the decorative radar
  // motif behind the shell stays visible through transparent regions.
  return (
    <div className="flex h-screen overflow-hidden text-foreground">
      {/* Desktop sidebar */}
      <div className="hidden md:block">
        <Sidebar />
      </div>

      {/* Mobile sidebar overlay */}
      {sidebarOpen && (
        <div className="fixed inset-0 z-40 md:hidden">
          <div
            className="absolute inset-0 z-40 bg-black/60 backdrop-blur-sm"
            onClick={handleSidebarClose}
            aria-hidden
          />
          <div className="absolute inset-y-0 left-0 z-50 w-60 animate-in slide-in-from-left duration-200">
            <Sidebar onNavigate={handleSidebarClose} />
          </div>
        </div>
      )}

      <div className="flex min-h-0 min-w-0 flex-1 flex-col">
        <Topbar onMenuToggle={handleSidebarToggle} />
        <ConnectionBanner />
        <LegacyImportBanner />
        <main className="min-h-0 flex-1 overflow-y-auto">
          <div className="mx-auto max-w-7xl px-4 py-4 sm:px-6 sm:py-6">
            <Outlet />
          </div>
        </main>
      </div>
      <CommandPalette />
    </div>
  );
}
