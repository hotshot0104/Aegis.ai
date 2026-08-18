"use client";
import React, { useState, useEffect, useRef } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Home,
  Zap,
  Plug,
  PanelLeftClose,
  PanelLeftOpen,
  Settings,
  LogOut,
  User,
} from "lucide-react";
import { cn } from "@/lib/utils";

export function AppSidebarContainer({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const [collapsed] = useState(true);
  const [avatarUrl, setAvatarUrl] = useState<string | null>(null);
  const [userName, setUserName] = useState<string>("kushagara singh");
  const [userEmail, setUserEmail] = useState<string>("kushagrasingh175@g...");
  const [isProfileMenuOpen, setIsProfileMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  // Close menu when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setIsProfileMenuOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const handleSignOut = () => {
    window.location.href = "/dashboard";
  };

  const links = [
    {
      label: "Home",
      href: "/dashboard",
      icon: Home,
      exact: true,
    },
    {
      label: "Workflows",
      href: "/dashboard/flows",
      icon: Zap,
    },
  ];

  return (
    <div className="flex h-screen w-full overflow-hidden bg-[#0A0A0C] text-white p-2 gap-2">
      {/* Sidebar Pane — Base background */}
      <aside
        className={cn(
          "flex flex-col justify-between h-full bg-[#0A0A0C] transition-all duration-300 ease-in-out shrink-0 py-2 px-3 relative",
          collapsed ? "w-[60px]" : "w-[220px]"
        )}
      >
        {/* Top Section: Links */}
        <div className="flex flex-col gap-4 pt-1">

          {/* Navigation Links */}
          <nav className="flex flex-col gap-1">
            {links.map((link) => {
              const IconComponent = link.icon;
              const isActive = link.exact
                ? pathname === link.href
                : pathname?.startsWith(link.href);

              return (
                <Link
                  key={link.label}
                  href={link.href}
                  className={cn(
                    "flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-all duration-150 font-medium",
                    isActive
                      ? "bg-[#222226] text-white shadow-sm"
                      : "text-neutral-400 hover:text-neutral-200 hover:bg-[#18181C]"
                  )}
                >
                  <IconComponent className="w-4 h-4 shrink-0" />
                  {!collapsed && <span>{link.label}</span>}
                </Link>
              );
            })}
          </nav>
        </div>

        {/* Bottom Section: Settings Icon Button with Profile Popover Menu */}
        <div className="pt-2 relative" ref={menuRef}>
          {/* Profile Popover Popup */}
          {isProfileMenuOpen && (
            <div className="absolute bottom-12 left-0 z-50 w-64 bg-[#141418]/95 border border-white/20 rounded-xl p-3 shadow-2xl backdrop-blur-xl animate-in fade-in zoom-in-95 duration-150">
              <div className="flex items-center gap-3 p-2 mb-2 bg-white/[0.04] rounded-lg">
                {avatarUrl ? (
                  <img
                    src={avatarUrl}
                    alt={userName}
                    className="w-9 h-9 rounded-full object-cover shrink-0 border border-white/20"
                  />
                ) : (
                  <div className="w-9 h-9 rounded-full bg-gradient-to-tr from-red-600 via-orange-500 to-amber-400 flex items-center justify-center text-white text-xs font-bold shrink-0 border border-white/20">
                    {userName ? userName.slice(0, 2).toUpperCase() : "KS"}
                  </div>
                )}
                <div className="flex flex-col min-w-0">
                  <span className="text-xs font-medium text-white truncate">
                    {userName}
                  </span>
                  <span className="text-[11px] text-neutral-400 truncate">
                    {userEmail}
                  </span>
                </div>
              </div>

              <div className="h-px bg-white/10 my-1" />

              <button
                onClick={handleSignOut}
                className="flex items-center gap-2.5 w-full px-2.5 py-2 rounded-lg text-xs text-red-400 hover:text-red-300 hover:bg-red-500/10 transition-colors mt-0.5"
              >
                <LogOut className="w-4 h-4" />
                <span>Sign Out</span>
              </button>
            </div>
          )}

          {/* Minimal Pure Settings Icon Trigger Button */}
          <button
            onClick={() => setIsProfileMenuOpen(!isProfileMenuOpen)}
            className={cn(
              "p-2 text-neutral-400 hover:text-white transition-colors rounded-lg cursor-pointer flex items-center justify-center",
              isProfileMenuOpen ? "text-white bg-white/[0.08]" : "hover:bg-white/[0.04]"
            )}
            title="Settings & Profile"
          >
            <Settings className="w-4 h-4" />
          </button>
        </div>
      </aside>

      {/* Floating Main Workspace Panel Container with Sharper Glassy Edges */}
      <main className="flex-1 h-full min-w-0 bg-[#0E0E12] border border-white/20 rounded-lg relative overflow-auto shadow-[0_8px_32px_rgba(0,0,0,0.8),_0_0_20px_rgba(255,255,255,0.02)] backdrop-blur-xl">
        {children}
      </main>
    </div>
  );
}
