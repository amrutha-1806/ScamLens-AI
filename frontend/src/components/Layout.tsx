import { ReactNode } from "react";
import { Link, useLocation } from "@tanstack/react-router";
import { motion, AnimatePresence } from "motion/react";

/**
 * Shared application layout.
 * Includes a sidebar navigation, a subtle animated background, and page transition handling.
 * All existing routes are rendered via <Outlet /> in __root.tsx, so we wrap that outlet here.
 */
export default function Layout({ children }: { children: ReactNode }) {
  const location = useLocation();

  const navItems = [
    { to: "/", label: "Dashboard" },
    { to: "/message-analyzer", label: "Message Analyzer" },
    { to: "/url-analyzer", label: "URL Analyzer" },
    { to: "/batch-scanner", label: "Batch Scanner" },
    { to: "/analytics", label: "Analytics" },
    { to: "/ai-models", label: "AI & Models" },
    { to: "/scan-history", label: "Scan History" },
    { to: "/reports", label: "Reports" },
    { to: "/about", label: "About" },
  ] as const;

  return (
    <div className="flex min-h-screen bg-[#080E1A] text-[#F1F5F9]">
      {/* Animated background – simple CSS animation */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden">
        <div className="grid-bg absolute inset-0 animate-grid"></div>
      </div>

      {/* Sidebar */}
      <aside className="relative z-10 w-64 flex flex-col bg-[#0B1220] p-4">
        <div className="mb-8 flex items-center justify-center text-2xl font-bold text-[#3B82F6]">
          SCAMLENS AI
        </div>
        <nav className="flex-1 space-y-2">
          {navItems.map((item) => {
            const isActive = location.pathname === item.to;
            return (
              <Link
                key={item.to}
                to={item.to}
                className={`group flex items-center rounded-md px-3 py-2 text-sm font-medium transition-colors 
                  ${isActive ? "bg-[#111C2E] text-[#3B82F6]" : "text-[#F1F5F9] hover:bg-[#111C2E] hover:text-[#60A5FA]"}`}
              >
                <span className="flex-1">{item.label}</span>
                {/* Indicator */}
                {isActive && (
                  <motion.span
                    layoutId="sidebar-indicator"
                    className="absolute inset-y-0 left-0 w-1 bg-[#3B82F6] rounded-r"
                  />
                )}
              </Link>
            );
          })}
        </nav>
        {/* Sign out button – uses Supabase client directly */}
        <div className="mt-6 border-t border-[#111C2E] pt-4">
          <Link
            to="/auth"
            className="group flex w-full items-center rounded-md px-3 py-2 text-sm font-medium text-[#EF4444] hover:bg-[#111C2E] hover:text-[#EF4444]"
          >
            Sign Out
          </Link>
        </div>
      </aside>

      {/* Main content area with page transition animation */}
      <main className="relative z-10 flex-1 overflow-auto p-6">
        <AnimatePresence mode="wait" initial={false}>
          <motion.div
            key={location.pathname}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            transition={{ duration: 0.2 }}
            className="h-full"
          >
            {children}
          </motion.div>
        </AnimatePresence>
      </main>
    </div>
  );
}

/**
 * Tailwind utilities for animated grid background.
 * Add the following to your global CSS (e.g., src/index.css):
 *
 * .grid-bg {
 *   background-image: radial-gradient(circle at 20% 20%, rgba(60,130,246,0.15) 0px, transparent 50%),
 *                    radial-gradient(circle at 80% 80%, rgba(96,165,250,0.15) 0px, transparent 50%);
 *   background-size: 200% 200%;
 * }
 * .animate-grid { animation: gridMove 12s linear infinite; }
 * @keyframes gridMove { 0% { background-position: 0% 0%; } 100% { background-position: 100% 100%; } }
 */
