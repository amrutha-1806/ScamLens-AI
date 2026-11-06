import { queryOptions } from "@tanstack/react-query";
import { scamlensApi } from "./scamlens-api";

export const healthQueryOptions = () => queryOptions({
  queryKey: ["scamlens", "health"],
  queryFn: scamlensApi.getHealth,
  enabled: scamlensApi.isConfigured,
  retry: 2,
  retryDelay: (attemptIndex) => Math.min(1000 * 2 ** attemptIndex, 4000),
  refetchInterval: 30_000,
});

export const historyQueryOptions = () => queryOptions({
  queryKey: ["scamlens", "history"],
  queryFn: scamlensApi.getHistory,
  enabled: scamlensApi.isConfigured,
  retry: 2,
  retryDelay: (attemptIndex) => Math.min(1000 * 2 ** attemptIndex, 4000),
  staleTime: 10_000,
});

export const modelInfoQueryOptions = () => queryOptions({
  queryKey: ["scamlens", "model-info"],
  queryFn: scamlensApi.getModelInfo,
  enabled: scamlensApi.isConfigured,
  retry: 2,
  retryDelay: (attemptIndex) => Math.min(1000 * 2 ** attemptIndex, 4000),
  staleTime: 60_000,
});
