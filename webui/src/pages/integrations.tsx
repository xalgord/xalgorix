import { Link } from "react-router-dom";
import { useI18n } from "@/i18n";
import {
  CheckCircle2,
  ExternalLink,
  Mail,
  MessageSquare,
  Plug,
  Send,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  useAgentMail,
  useEnvironmentSettings,
  useRateLimit,
  useVersion,
} from "@/api/queries";
import { cn } from "@/lib/utils";

type Integration = {
  key: string;
  name: string;
  description: string;
  category: "AI" | "Email" | "Notifications" | "Engagement";
  icon: typeof Plug;
  configurePath?: string;
  configureLabel?: string;
  external?: string;
  isConfigured: boolean;
  detail?: string;
};

export default function IntegrationsPage() {
  const { t } = useI18n();
  const mail = useAgentMail();
  const rate = useRateLimit();
  const version = useVersion();
  const environment = useEnvironmentSettings();
  const ai = version.data?.ai;
  const usesVercelGateway = ai?.gateway === "vercel";
  const discordWebhook = environment.data?.variables.find(
    (variable) => variable.key === "XALGORIX_DISCORD_WEBHOOK",
  );
  const telegramToken = environment.data?.variables.find(
    (variable) => variable.key === "XALGORIX_TELEGRAM_BOT_TOKEN",
  );

  const integrations: Integration[] = [
    {
      key: "llm-provider",
      name: usesVercelGateway ? "Vercel AI Gateway" : "LLM Provider",
      description: usesVercelGateway
        ? "Multi-provider LLM access for the security agent through Vercel AI Gateway."
        : "Direct model provider used by the security agent for planning, testing, and reporting.",
      category: "AI",
      icon: Sparkles,
      configurePath: "/settings?tab=llm",
      configureLabel: "Open settings",
      external: usesVercelGateway ? "https://vercel.com/docs/ai-gateway" : undefined,
      isConfigured: Boolean(ai?.configured),
      detail: ai
        ? `${ai.provider}${ai.model ? ` · ${ai.model}` : ""}`
        : "Loading provider status...",
    },
    {
      key: "agentmail",
      name: "AgentMail",
      description:
        "Inbound email triage: forward security inboxes and let the agent classify, prioritize, and respond.",
      category: "Email",
      icon: Mail,
      configurePath: "/settings?tab=email",
      configureLabel: "Configure",
      external: "https://agentmail.to",
      isConfigured: Boolean(mail.data?.hasApiKey && mail.data?.pod),
      detail: mail.data?.pod ? `Pod: ${mail.data.pod}` : "Not connected",
    },
    {
      key: "discord",
      name: "Discord webhook",
      description:
        "Stream critical findings and scan summaries to a Discord channel as they happen.",
      category: "Notifications",
      icon: MessageSquare,
      configurePath: "/settings?tab=notifications",
      configureLabel: "Configure",
      external: "https://discord.com/developers/docs/resources/webhook",
      isConfigured: Boolean(discordWebhook?.hasValue),
      detail: discordWebhook?.hasValue
        ? "Global webhook configured"
        : "Global default, with per-scan overrides available.",
    },
    {
      key: "telegram",
      name: "Telegram bot",
      description:
        "Receive scan events, severity-gated findings, and the finished PDF report in a Telegram chat or channel.",
      category: "Notifications",
      icon: Send,
      configurePath: "/settings?tab=notifications",
      configureLabel: "Configure",
      external: "https://core.telegram.org/bots/api",
      isConfigured: Boolean(telegramToken?.hasValue),
      detail: telegramToken?.hasValue
        ? "Bot token configured"
        : "Set a bot token and chat ID to enable Telegram alerts.",
    },
    {
      key: "rate-limit",
      name: "Outbound rate limiter",
      description:
        "Throttle the agent so it stays within target SLAs and bug bounty engagement rules.",
      category: "Engagement",
      icon: ShieldCheck,
      configurePath: "/settings?tab=engagement",
      configureLabel: "Adjust",
      isConfigured: Boolean(rate.data?.requests),
      detail: rate.data
        ? `${rate.data.requests} req / ${rate.data.window}s window`
        : "Loading…",
    },
  ];

  const byCategory = groupBy(integrations, (i) => i.category);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{t("integrations.title")}</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Services the agent can talk to. Configure once, reuse across every
          scan.
        </p>
      </div>

      {(["AI", "Email", "Notifications", "Engagement"] as const).map((cat) => {
        const items = byCategory[cat] ?? [];
        if (!items.length) return null;
        return (
          <section key={cat} className="space-y-3">
            <h2 className="text-[11px] uppercase tracking-wider text-muted-foreground">
              {t(`integrations.category.${cat}`)}
            </h2>
            <div className="grid gap-3 md:grid-cols-2">
              {items.map((it) => (
                <IntegrationCard key={it.key} integration={it} />
              ))}
            </div>
          </section>
        );
      })}
    </div>
  );
}

function IntegrationCard({ integration }: { integration: Integration }) {
  const { t } = useI18n();
  const Icon = integration.icon;
  return (
    <Card className="overflow-hidden">
      <CardContent className="space-y-3 p-4">
        <div className="flex items-start gap-3">
          <div
            className={cn(
              "flex h-10 w-10 shrink-0 items-center justify-center rounded-md border",
              integration.isConfigured
                ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                : "border-border bg-muted text-muted-foreground",
            )}
          >
            <Icon className="h-5 w-5" />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-medium text-foreground">
                {integration.name}
              </h3>
              {integration.isConfigured ? (
                <Badge className="bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30 text-[10px]">
                  <CheckCircle2 className="h-3 w-3" /> {t("integrations.connected")}
                </Badge>
              ) : (
                <Badge variant="outline" className="text-[10px] text-muted-foreground">
                  {t("integrations.notConnected")}
                </Badge>
              )}
            </div>
            <p className="mt-1 text-xs text-muted-foreground text-pretty">
              {integration.description}
            </p>
            {integration.detail && (
              <p className="mt-2 mono text-[11px] text-muted-foreground">
                {integration.detail}
              </p>
            )}
          </div>
        </div>
        <div className="flex items-center justify-end gap-2 border-t border-border pt-3">
          {integration.external && (
            <Button asChild size="sm" variant="ghost">
              <a href={integration.external} target="_blank" rel="noreferrer">
                Docs <ExternalLink className="h-3 w-3" />
              </a>
            </Button>
          )}
          {integration.configurePath && (
            <Button asChild size="sm" variant="outline">
              <Link to={integration.configurePath}>
                {integration.configureLabel || "Configure"}
              </Link>
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

function groupBy<T, K extends string>(arr: T[], key: (t: T) => K) {
  return arr.reduce<Record<string, T[]>>((acc, item) => {
    const k = key(item);
    (acc[k] ||= []).push(item);
    return acc;
  }, {});
}
