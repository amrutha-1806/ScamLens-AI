import { queryOptions } from "@tanstack/react-query";
import { scamlensApi } from "./scamlens-api";

export const healthQueryOptions = () =>
  queryOptions({
    queryKey: ["scamlens", "health"],
    queryFn: () => scamlensApi.getHealth(),
    enabled: scamlensApi.isConfigured,
    staleTime: 30_000,
    refetchInterval: 30_000,
    refetchOnWindowFocus: false,
    retry: 3,
    retryDelay: (attemptIndex) => Math.min(2000 * 2 ** attemptIndex, 8000),
  });

export const historyQueryOptions = (userId?: string) =>
  queryOptions({
    queryKey: ["scamlens", "history", userId ?? "all"],
    queryFn: () => scamlensApi.getHistory(userId),
    enabled: scamlensApi.isConfigured,
    staleTime: 15_000,
    refetchOnWindowFocus: false,
    retry: 3,
    retryDelay: (attemptIndex) => Math.min(2000 * 2 ** attemptIndex, 8000),
  });

export const modelInfoQueryOptions = () =>
  queryOptions({
    queryKey: ["scamlens", "model-info"],
    queryFn: () => scamlensApi.getModelInfo(),
    enabled: scamlensApi.isConfigured,
    staleTime: 60_000,
    refetchOnWindowFocus: false,
    retry: 3,
    retryDelay: (attemptIndex) => Math.min(2000 * 2 ** attemptIndex, 8000),
  });
