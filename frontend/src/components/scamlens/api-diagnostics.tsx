import { useState } from "react";
import { Activity, LoaderCircle, RefreshCw } from "lucide-react";
import { AnimatePresence, motion } from "motion/react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { Panel } from "./primitives";
import { runApiDiagnostics, scamlensApi, type DiagnosticResult, type DiagnosticsRun } from "@/lib/scamlens-api";
import { useScamlensPreferences } from "@/lib/scamlens-preferences";

const overallTone: Record<DiagnosticsRun["overall"], string> = {
  Connected: "border-safe/30 bg-safe/10 text-safe",
  "Partially connected": "border-warning/30 bg-warning/10 text-warning",
  "Browser blocked": "border-danger/30 bg-danger/10 text-danger",
  "Backend unavailable": "border-danger/30 bg-danger/10 text-danger",
};
const statusTone: Record<DiagnosticResult["status"], string> = { PASS: "text-safe", FAIL: "text-danger", BLOCKED: "text-warning" };

function troubleshooting(results: DiagnosticResult[], embedded: boolean): string[] {
  const tips = new Set<string>();
  const blockedLna = results.some((r) => r.category === "Local Network Access");
  for (const r of results) {
    if (r.category === "CORS") tips.add("Check that FastAPI allows this frontend origin and required HTTP methods/headers.");
    else if (r.category === "Mixed content") tips.add("The frontend is HTTPS while the API is HTTP. The browser may block this connection.");
    else if (r.category === "Local Network Access") tips.add("Chrome may require permission for an HTTPS page to access a local/loopback API.");
    else if (r.category === "Network connection" || r.category === "Timeout") tips.add("Start the FastAPI server and verify that the configured API origin is reachable.");
    else if (r.category === "Backend HTTP error" && r.httpStatus) tips.add(`Backend responded with HTTP ${r.httpStatus} on ${r.path}. Check the endpoint response.`);
    else if (r.category === "Malformed response") tips.add(`${r.path} returned a response that did not match the expected format. Check the endpoint response.`);
  }
  if (blockedLna && embedded) tips.add("This page is running inside an embedded frame controlled by the hosting editor, so site-level permissions may not apply. Open the app in its own browser tab and allow local network access there.");
  return tips.size ? [...tips] : ["API connectivity checks passed."];
}

export function ApiDiagnosticsPanel() {
  const [run, setRun] = useState<DiagnosticsRun | null>(null);
  const [running, setRunning] = useState(false);
  const { shouldReduceMotion } = useScamlensPreferences();
  const start = async () => { setRunning(true); try { setRun(await runApiDiagnostics()); } finally { setRunning(false); } };
  const origin = scamlensApi.baseUrl ?? "Not configured";

  return (
    <Panel
      title="API Diagnostics"
      description="Read-only browser checks against the configured API origin. POST checks send clearly labeled diagnostic payloads and may appear in backend history."
      action={
        <Button size="sm" variant="outline" onClick={start} disabled={running}>
          {running ? <LoaderCircle className="animate-spin" /> : <RefreshCw />}
          {run ? "Run diagnostics again" : "Run diagnostics"}
        </Button>
      }
    >
      <div className="grid gap-3 sm:grid-cols-3">
        <div className="rounded-md border border-border bg-secondary/30 p-3 transition-colors hover:border-primary/25">
          <p className="text-xs text-muted-foreground">Configured origin</p>
          <p className="mt-1 break-all font-mono text-xs text-foreground">{origin}</p>
        </div>
        <div className="rounded-md border border-border bg-secondary/30 p-3 transition-colors hover:border-primary/25">
          <p className="text-xs text-muted-foreground">Overall status</p>
          {run ? (
            <span className={cn("mt-1 inline-flex rounded-md border px-2 py-0.5 text-xs font-medium", overallTone[run.overall])}>
              {run.overall}
            </span>
          ) : (
            <p className="mt-1 text-xs text-foreground">Not run yet</p>
          )}
        </div>
        <div className="rounded-md border border-border bg-secondary/30 p-3 transition-colors hover:border-primary/25">
          <p className="text-xs text-muted-foreground">Last diagnostics run</p>
          <p className="mt-1 text-xs text-foreground">{run ? new Date(run.finishedAt).toLocaleString() : "—"}</p>
        </div>
      </div>

      <AnimatePresence mode="wait">
        {run ? (
          <motion.div
            key={run.finishedAt}
            initial={shouldReduceMotion ? false : { opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={shouldReduceMotion ? { opacity: 1 } : { opacity: 0 }}
            transition={{ duration: shouldReduceMotion ? 0 : 0.25 }}
          >
            <div className="mt-3 grid gap-3 sm:grid-cols-3">
              {(
                [
                  ["loopback-network permission", run.permissions.loopbackNetwork],
                  ["local-network permission", run.permissions.localNetwork],
                  ["Browsing context", run.embedded ? "Embedded frame" : "Top-level tab"],
                ] as const
              ).map(([label, value]) => (
                <div key={label} className="rounded-md border border-border bg-secondary/30 p-3">
                  <p className="text-xs text-muted-foreground">{label}</p>
                  <p className="mt-1 font-mono text-xs text-foreground">{value}</p>
                </div>
              ))}
            </div>
            <div className="mt-5 overflow-x-auto rounded-md border border-border">
              <table className="w-full min-w-[760px] text-left text-xs">
                <thead className="bg-secondary/40 text-muted-foreground">
                  <tr>
                    <th className="p-3">Endpoint</th>
                    <th className="p-3">Method</th>
                    <th className="p-3">Status</th>
                    <th className="p-3">HTTP</th>
                    <th className="p-3">Time</th>
                    <th className="p-3">Classification</th>
                    <th className="p-3">Detail</th>
                  </tr>
                </thead>
                <tbody>
                  {run.results.map((r, idx) => (
                    <motion.tr
                      key={r.path}
                      initial={shouldReduceMotion ? false : { opacity: 0, x: -6 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{
                        duration: shouldReduceMotion ? 0 : 0.2,
                        delay: shouldReduceMotion ? 0 : idx * 0.04,
                      }}
                      className="border-t border-border align-top transition-colors hover:bg-secondary/25"
                    >
                      <td className="p-3 font-mono text-foreground">{r.path}</td>
                      <td className="p-3 text-muted-foreground">{r.method}</td>
                      <td className={cn("p-3 font-semibold", statusTone[r.status])}>{r.status}</td>
                      <td className="p-3 text-foreground">{r.httpStatus ?? "—"}</td>
                      <td className="p-3 text-foreground">{r.durationMs !== undefined ? `${r.durationMs} ms` : "—"}</td>
                      <td className="p-3 text-muted-foreground">{r.category ?? "OK"}</td>
                      <td className="p-3 text-muted-foreground">{r.detail}</td>
                    </motion.tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="mt-5 rounded-md border border-primary/20 bg-primary/5 p-4">
              <p className="flex items-center gap-2 text-sm font-medium text-foreground">
                <Activity className="size-4 text-primary" /> Actionable troubleshooting
              </p>
              <ul className="mt-2 list-disc space-y-1 pl-5 text-xs leading-5 text-muted-foreground">
                {troubleshooting(run.results, run.embedded).map((t) => (
                  <li key={t}>{t}</li>
                ))}
              </ul>
            </div>
          </motion.div>
        ) : (
          <motion.p
            key="diagnostics-empty"
            initial={shouldReduceMotion ? false : { opacity: 0 }}
            animate={{ opacity: 1 }}
            className="mt-5 text-xs text-muted-foreground"
          >
            Run diagnostics to test each endpoint from this browser. Nothing is shown until real results are received.
          </motion.p>
        )}
      </AnimatePresence>
    </Panel>
  );
}
