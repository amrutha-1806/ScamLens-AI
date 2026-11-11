import * as React from "react";
import { Button as BaseButton } from "@/components/ui/button";
import { Input as BaseInput } from "@/components/ui/input";
import { Textarea as BaseTextarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";

export { cn };

export const Input = BaseInput;
export const Textarea = BaseTextarea;
export const Button = BaseButton;

export function Card({
  className,
  children,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "rounded-xl border border-border bg-card text-card-foreground shadow-panel",
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
}

export function Badge({
  tone = "neutral",
  className,
  children,
  ...props
}: React.HTMLAttributes<HTMLSpanElement> & {
  tone?: "neutral" | "info" | "success" | "warning" | "danger";
}) {
  const toneClasses =
    tone === "danger"
      ? "border-rose-500/35 bg-rose-500/15 text-rose-300"
      : tone === "warning"
        ? "border-amber-500/35 bg-amber-500/15 text-amber-300"
        : tone === "success"
          ? "border-emerald-500/35 bg-emerald-500/15 text-emerald-300"
          : tone === "info"
            ? "border-cyan-500/35 bg-cyan-500/15 text-cyan-300"
            : "border-slate-700 bg-slate-800/80 text-slate-300";

  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border px-2.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider",
        toneClasses,
        className
      )}
      {...props}
    >
      {children}
    </span>
  );
}
