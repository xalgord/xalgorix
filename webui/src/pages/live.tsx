import { useMemo, useState } from "react"
import { useI18n } from "@/i18n"
import { useQueries } from "@tanstack/react-query"
import {
  eventOrderMs,
  mergeFeedEvents,
  toFeedEvent,
  useWSStore,
} from "@/store/ws"
import { LiveFeed, type FeedFilter } from "@/components/live-feed"
import { ConnectionStatus } from "@/components/connection-status"
import { api } from "@/api/client"
import { qk, useInstances } from "@/api/queries"

export default function LivePage() {
  const { t } = useI18n()
  const events = useWSStore((s) => s.events)
  const clearEvents = useWSStore((s) => s.clearEvents)
  const { data: instances } = useInstances()
  const [filter, setFilter] = useState<FeedFilter>("all")
  const [clearedAt, setClearedAt] = useState<number | null>(null)
  const activeInstanceIds = useMemo(
    () =>
      (instances?.instances ?? [])
        .filter((i) => isActiveStatus(i.status))
        .map((i) => i.id)
        .slice(0, 8),
    [instances],
  )
  const historyQueries = useQueries({
    queries: activeInstanceIds.map((id) => ({
      queryKey: qk.instanceEvents(id),
      queryFn: () => api.instanceEvents(id),
      staleTime: 1000,
      refetchInterval: 5000,
    })),
  })
  const feedEvents = useMemo(() => {
    const persisted = historyQueries.flatMap((q, queryIndex) =>
      (q.data ?? []).map((event, eventIndex) =>
        toFeedEvent(
          event,
          `live:${activeInstanceIds[queryIndex] || queryIndex}`,
          eventIndex,
        ),
      ),
    )
    const merged = mergeFeedEvents(persisted, events)
    if (!clearedAt) return merged
    return merged.filter((event) => eventOrderMs(event) > clearedAt)
  }, [activeInstanceIds, clearedAt, events, historyQueries])

  return (
    <div className="space-y-6">
      <header className="flex items-center justify-between gap-3">
        <div>
          <h1 className="font-sans text-2xl font-semibold tracking-tight">{t("live.title")}</h1>
          <p className="text-sm text-muted-foreground">
            Streaming events from every active scan and worker.
          </p>
        </div>
        <ConnectionStatus />
      </header>
      <LiveFeed
        events={feedEvents}
        filter={filter}
        onFilterChange={setFilter}
        exportFilePrefix="xalgorix-live-feed"
        exportScope="active scans"
        onClearEvents={() => {
          setClearedAt(Date.now())
          clearEvents()
        }}
        emptyTitle="Quiet on the wire"
        emptyDescription="Events from any running instance will appear here in real time."
      />
    </div>
  )
}

function isActiveStatus(status?: string): boolean {
  const s = (status || "").toLowerCase()
  return s === "running" || s === "pending" || s === "paused"
}
