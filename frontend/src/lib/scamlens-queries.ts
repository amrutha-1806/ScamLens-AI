import { queryOptions } from "@tanstack/react-query";
import { scamlensApi } from "./scamlens-api";

export const healthQueryOptions = () => queryOptions({
  queryKey: ["scamlens", "health"],
  queryFn: scamlensApi.getHealth,
  enabled: scamlensApi.isConfigured,
  retry: false,
  refetchInterval: 30_000,
});

export const historyQueryOptions = () => queryOptions({
  queryKey: ["scamlens", "history"],
  queryFn: scamlensApi.getHistory,
  enabled: scamlensApi.isConfigured,
  retry: false,
  staleTime: 10_000,
});

export const modelInfoQueryOptions = () => queryOptions({
  queryKey: ["scamlens", "model-info"],
  queryFn: scamlensApi.getModelInfo,
  enabled: scamlensApi.isConfigured,
  retry: false,
  staleTime: 60_000,
});