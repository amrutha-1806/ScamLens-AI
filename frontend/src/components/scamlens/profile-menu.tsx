import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import {
  Bell,
  ChevronDown,
  KeyRound,
  LogOut,
  Settings,
  Shield,
  ShieldCheck,
  User,
} from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { ProfileSettingsDialog, type ProfileTab } from "./profile-settings-dialog";
import { cn } from "@/lib/utils";

export function ProfileMenu() {
  const [dialogOpen, setDialogOpen] = useState(false);
  const [dialogTab, setDialogTab] = useState<ProfileTab>("profile");
  const queryClient = useQueryClient();
  const navigate = useNavigate();

  const userQuery = useQuery({
    queryKey: ["auth-user"],
    queryFn: async () => (await supabase.auth.getUser()).data.user,
    staleTime: 60_000,
  });

  const user = userQuery.data;
  const email = user?.email ?? "analyst@scamlens.local";
  const displayName =
    (user?.user_metadata?.["display_name"] as string) ||
    (user?.user_metadata?.["full_name"] as string) ||
    "";

  const initials = (() => {
    if (displayName.trim()) {
      const parts = displayName.trim().split(/\s+/);
      return (parts[0][0] + (parts[1]?.[0] || "")).toUpperCase();
    }
    if (email) {
      return email.slice(0, 2).toUpperCase();
    }
    return "SL";
  })();

  const openTab = (tab: ProfileTab) => {
    setDialogTab(tab);
    setDialogOpen(true);
  };

  async function handleSignOut() {
    await queryClient.cancelQueries();
    queryClient.clear();
    await supabase.auth.signOut();
    navigate({ to: "/auth", replace: true });
  }

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <button
            type="button"
            className="flex items-center gap-2 rounded-lg border border-border bg-card/80 p-1.5 transition-all duration-150 hover:border-primary/50 hover:bg-secondary/60 focus:outline-none focus:ring-2 focus:ring-primary/40 min-h-10 sm:px-2.5"
            aria-label="Open user profile menu"
          >
            <div className="relative">
              <Avatar className="size-7 border border-primary/40 bg-primary/10 text-primary">
                <AvatarFallback className="bg-transparent text-[11px] font-bold font-mono text-primary">
                  {initials}
                </AvatarFallback>
              </Avatar>
              <span className="absolute -bottom-0.5 -right-0.5 size-2 rounded-full bg-safe border border-card" />
            </div>

            <div className="hidden min-w-0 text-left lg:block max-w-36">
              <p className="truncate text-xs font-semibold text-foreground leading-tight">
                {displayName || "Security Analyst"}
              </p>
              <p className="truncate font-mono text-[10px] text-muted-foreground">
                {email}
              </p>
            </div>

            <ChevronDown className="size-3.5 text-muted-foreground hidden sm:block" />
          </button>
        </DropdownMenuTrigger>

        <DropdownMenuContent
          align="end"
          sideOffset={8}
          className="w-64 border-border bg-popover/95 backdrop-blur-md p-1.5 shadow-xl sm:w-72"
        >
          {/* User Information Header */}
          <DropdownMenuLabel className="p-2 font-normal">
            <div className="flex items-start gap-2.5">
              <Avatar className="size-9 border border-primary/40 bg-primary/15 text-primary">
                <AvatarFallback className="bg-transparent text-xs font-bold font-mono text-primary">
                  {initials}
                </AvatarFallback>
              </Avatar>
              <div className="min-w-0 flex-1">
                <p className="truncate text-xs font-bold text-foreground">
                  {displayName || "Security Analyst"}
                </p>
                <p className="truncate font-mono text-[11px] text-muted-foreground">
                  {email}
                </p>
                <div className="mt-1 flex items-center gap-1 text-[10px] text-safe font-semibold">
                  <ShieldCheck className="size-3" />
                  <span>Verified Analyst</span>
                </div>
              </div>
            </div>
          </DropdownMenuLabel>

          <DropdownMenuSeparator />

          <DropdownMenuGroup>
            <DropdownMenuItem
              onClick={() => openTab("profile")}
              className="flex items-center gap-2.5 p-2 text-xs cursor-pointer focus:bg-secondary"
            >
              <User className="size-4 text-primary" />
              <span>My Profile</span>
            </DropdownMenuItem>

            <DropdownMenuItem
              onClick={() => openTab("password")}
              className="flex items-center gap-2.5 p-2 text-xs cursor-pointer focus:bg-secondary"
            >
              <KeyRound className="size-4 text-primary" />
              <span>Change Password</span>
            </DropdownMenuItem>

            <DropdownMenuItem
              onClick={() => openTab("security")}
              className="flex items-center gap-2.5 p-2 text-xs cursor-pointer focus:bg-secondary"
            >
              <Shield className="size-4 text-primary" />
              <span>Security Settings</span>
            </DropdownMenuItem>

            <DropdownMenuItem
              onClick={() => openTab("notifications")}
              className="flex items-center gap-2.5 p-2 text-xs cursor-pointer focus:bg-secondary"
            >
              <Bell className="size-4 text-primary" />
              <span>Notifications</span>
            </DropdownMenuItem>

            <DropdownMenuItem
              onClick={() => openTab("preferences")}
              className="flex items-center gap-2.5 p-2 text-xs cursor-pointer focus:bg-secondary"
            >
              <Settings className="size-4 text-primary" />
              <span>Preferences</span>
            </DropdownMenuItem>
          </DropdownMenuGroup>

          <DropdownMenuSeparator />

          <DropdownMenuItem
            onClick={handleSignOut}
            className="flex items-center gap-2.5 p-2 text-xs cursor-pointer text-danger focus:bg-danger/10 focus:text-danger"
          >
            <LogOut className="size-4" />
            <span>Sign Out</span>
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <ProfileSettingsDialog
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        defaultTab={dialogTab}
      />
    </>
  );
}
