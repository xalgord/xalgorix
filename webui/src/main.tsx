import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "react-router-dom";
import { Toaster } from "sonner";
import { router } from "./router";
import { useTheme } from "./store/theme";
import "./styles.css";

// Toaster wired to the active theme. Colors reference the app tokens (which
// flip with the theme) and the sonner `theme` prop selects its light/dark base.
function AppToaster() {
  const { resolved } = useTheme();
  return (
    <Toaster
      position="bottom-right"
      theme={resolved}
      toastOptions={{
        style: {
          background: "var(--popover)",
          border: "1px solid var(--border)",
          color: "var(--popover-foreground)",
          fontSize: "13px",
        },
      }}
    />
  );
}

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
      staleTime: 10_000,
    },
  },
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
      <AppToaster />
    </QueryClientProvider>
  </StrictMode>,
);
