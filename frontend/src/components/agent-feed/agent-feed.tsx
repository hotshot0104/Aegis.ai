"use client"

/**
 * AgentFeed — Renders real agent messages using the existing
 * timeline nodes and generative card components.
 *
 * Maps AI SDK v6 message parts → UI components:
 *   - TextUIPart       → AgentSpeechBlock
 *   - ReasoningUIPart  → MonologueBlock
 *   - ToolUIPart/DynamicToolUIPart (input-streaming/input-available) → TimelineNode loading
 *   - ToolUIPart/DynamicToolUIPart (output-available) → TimelineNode completed + result card
 *   - StepStartUIPart  → ignored (batching boundary)
 */

import * as React from "react"
import { useChatContext, type UIMessage, type MessagePart } from "./chat-provider"
import {
  TimelineNode,
  AgentSpeechBlock,
  MonologueBlock,
  InlineQueryBlock,
  MiniResultCard,
  AgentReasoningBatch,
  AgentApprovalBlock,
} from "./timeline-nodes"
import { DotmSquare12 } from "@/components/ui/dotm-square-12"
import { USER_EMOJI_PALETTE } from "@/lib/emoji-palette"
import {
  Search,
  Loader2,
  Zap,
  Database,
  Mail,
  CreditCard,
  MessageSquare,
  Calendar,
  User,
  Globe,
  AlertCircle,
  ChevronRight,
  Shield,
  Terminal,
  Cpu,
  Lock,
  Network,
} from "lucide-react"

// ─── Tool → Icon mapping (AEGIS Cyber & SOC Tools) ────────────────────────────────────────────
const TOOL_ICONS: Record<string, React.ReactNode> = {
  tool_inspect_flow_metrics: <Network className="w-4 h-4 text-cyan-400 shrink-0" />,
  tool_query_asset_registry: <Database className="w-4 h-4 text-blue-400 shrink-0" />,
  tool_mitre_vector_search: <Shield className="w-4 h-4 text-purple-400 shrink-0" />,
  tool_generate_containment_command: <Lock className="w-4 h-4 text-rose-400 shrink-0" />,
  threat_hunter_investigate: <Search className="w-4 h-4 text-amber-400 shrink-0" />,
  asset_investigate: <Database className="w-4 h-4 text-blue-400 shrink-0" />,
  rule_generator_compile: <Terminal className="w-4 h-4 text-emerald-400 shrink-0" />,
}

// ─── Human-readable names for tools ──────────────────────────────────
const TOOL_LABELS: Record<string, string> = {
  getAccountDetails: "Reading account profile",
  getAllAccounts: "Scanning customer accounts",
  getRecentSignals: "Analyzing workspace signals & activity",
  getExistingDrafts: "Checking draft responses",
  getStripeAccountState: "Querying Stripe billing state",
  getPostHogAccountUsage: "Analyzing product engagement",
  getGmailThreadsForAccount: "Searching Gmail communications",
  getMyInbox: "Reading your inbox",
  generateFollowUpDraft: "Drafting follow-up response",
  createSignal: "Recording workspace signal",
  updateAccountRisk: "Updating risk assessment",
  addTimelineEvent: "Logging timeline event",
  createBriefItem: "Adding brief item",
  updateBriefSummary: "Updating brief summary",
  resolveAccountByContact: "Resolving account from contact",
  syncStripeWorkspaceTool: "Syncing Stripe billing data",
  syncPostHogWorkspaceTool: "Syncing PostHog analytics",
  syncGmailWorkspaceTool: "Syncing Gmail messages",
  syncIntercomWorkspaceTool: "Syncing Intercom support",
  syncHubSpotWorkspaceTool: "Syncing HubSpot CRM",
  syncSentryWorkspaceTool: "Syncing Sentry errors",
  syncLinearWorkspaceTool: "Syncing Linear issues",
  deliverSlackBriefTool: "Delivering brief to Slack",
  buildDailyBriefFromLiveState: "Building executive brief",
  createRescueDiscountTool: "Creating rescue discount",
  webSearchTool: "Searching web intelligence",
  webExtractTool: "Extracting webpage data",
  webCrawlTool: "Crawling website domain",
  webMapTool: "Indexing sitemap",
  listCalendarEventsTool: "Checking Google Calendar",
  getCalendarEventTool: "Fetching Calendar event",
  createCalendarEventTool: "Creating Calendar event",
  updateCalendarEventTool: "Updating Calendar event",
  deleteCalendarEventTool: "Deleting Calendar event",
  queryFreeBusyTool: "Checking Calendar availability",
  listCalendarsTool: "Listing Google Calendars",
  getSlackHistory: "Scanning Slack channels",
  sendSlackMessage: "Sending Slack message",
  searchSlack: "Searching Slack messages",
  replyInSlackThread: "Replying in Slack thread",
  getSlackChannels: "Listing Slack channels",
}

const PROVIDER_LOGOS: Record<string, string> = {
  gmail: '/logos/gmail.svg',
  slack: '/logos/slack.svg',
  stripe: '/logos/stripe.svg',
  posthog: '/logos/posthog.svg',
  linear: '/logos/linear.svg',
  sentry: '/logos/sentry-light.svg',
  hubspot: '/logos/hubspot.svg',
  notion: '/logos/notion.svg',
  google_calendar: '/logos/google-calendar.svg',
  airtable: '/logos/airtable.svg',
}

function getProviderFromTool(toolName: string, errorMsg: string): { name: string; slug: string; logoUrl?: string } | null {
  const lowName = toolName.toLowerCase()
  const lowMsg = errorMsg.toLowerCase()
  let slug: string | null = null
  let name = ''

  if (lowName.includes('calendar') || lowMsg.includes('calendar')) { slug = 'google_calendar'; name = 'Google Calendar' }
  else if (lowName.includes('gmail') || toolName === 'getMyInbox' || lowMsg.includes('gmail')) { slug = 'gmail'; name = 'Gmail' }
  else if (lowName.includes('slack') || lowMsg.includes('slack')) { slug = 'slack'; name = 'Slack' }
  else if (lowName.includes('stripe') || lowMsg.includes('stripe')) { slug = 'stripe'; name = 'Stripe' }
  else if (lowName.includes('posthog') || lowMsg.includes('posthog')) { slug = 'posthog'; name = 'PostHog' }
  else if (lowName.includes('linear') || lowMsg.includes('linear')) { slug = 'linear'; name = 'Linear' }
  else if (lowName.includes('sentry') || lowMsg.includes('sentry')) { slug = 'sentry'; name = 'Sentry' }
  else if (lowName.includes('hubspot') || lowMsg.includes('hubspot')) { slug = 'hubspot'; name = 'HubSpot' }
  else if (lowName.includes('notion') || lowMsg.includes('notion')) { slug = 'notion'; name = 'Notion' }
  else if (lowName.includes('calendar') || lowMsg.includes('calendar')) { slug = 'google_calendar'; name = 'Google Calendar' }

  if (!slug) return null
  return { name, slug, logoUrl: PROVIDER_LOGOS[slug] }
}

export function UnconnectedIntegrationBadge({
  toolName,
  errorText,
}: {
  toolName: string
  errorText: string
}) {
  const provider = getProviderFromTool(toolName, errorText)
  const cleanMsg = formatCleanErrorMessage(errorText)

  return (
    <div className="flex items-center gap-2.5 text-[12px] text-neutral-400 font-normal py-0.5 mt-0.5">
      <span>{cleanMsg}</span>
    </div>
  )
}

/** Human-readable summary of what the tool is doing based on its input */
function ToolThinkingSummary({ toolName, input }: { toolName: string; input: unknown }) {
  const data = (input && typeof input === 'object') ? input as Record<string, unknown> : {}

  let summary = ''

  // Calendar tools
  if (toolName === 'listCalendarEventsTool' || toolName === 'searchCalendarEventsTool') {
    const q = data.query ?? data.q
    const timeMin = data.timeMin as string | undefined
    if (q) {
      summary = `Searching for "${q}" events`
    } else if (timeMin) {
      try {
        const d = new Date(timeMin)
        summary = `Looking up events from ${d.toLocaleDateString('en-IN', { month: 'short', day: 'numeric' })}`
      } catch { summary = 'Fetching calendar events' }
    } else {
      summary = 'Fetching upcoming events'
    }
  } else if (toolName === 'createCalendarEventTool') {
    const title = data.summary as string ?? ''
    const start = data.startDateTime as string ?? ''
    if (title && start) {
      try {
        const d = new Date(start)
        summary = `Creating "${title}" on ${d.toLocaleDateString('en-IN', { month: 'short', day: 'numeric' })} at ${d.toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' })}`
      } catch { summary = `Creating "${title}"` }
    } else {
      summary = title ? `Creating "${title}"` : 'Creating calendar event'
    }
  } else if (toolName === 'deleteCalendarEventTool') {
    const eid = data.eventId ? String(data.eventId).slice(0, 12) + '…' : ''
    summary = eid ? `Removing event ${eid}` : 'Removing calendar event'
  } else if (toolName === 'updateCalendarEventTool') {
    summary = 'Updating calendar event'
  } else if (toolName === 'checkCalendarFreeBusy' || toolName === 'queryFreeBusyTool') {
    summary = 'Checking availability'
  } else if (toolName === 'listCalendarsTool') {
    summary = 'Listing available calendars'
  }
  // Gmail tools
  else if (toolName === 'getMyInbox') {
    summary = 'Scanning inbox for recent messages'
  } else if (toolName === 'sendGmailReply' || toolName === 'composeNewEmail') {
    const to = (data.to ?? data.recipientEmail ?? '') as string
    summary = to ? `Composing email to ${to}` : 'Composing email'
  } else if (toolName === 'getGmailThreadsForAccount') {
    summary = 'Pulling email threads for account'
  }
  // Slack tools
  else if (toolName === 'getSlackHistory') {
    summary = 'Reading Slack channel history'
  } else if (toolName === 'sendSlackMessage') {
    summary = 'Sending Slack message'
  } else if (toolName === 'searchSlack') {
    const q = data.query as string
    summary = q ? `Searching Slack for "${q}"` : 'Searching Slack'
  } else if (toolName === 'replyInSlackThread') {
    summary = 'Replying in Slack thread'
  } else if (toolName === 'getSlackChannels') {
    summary = 'Listing Slack channels'
  }
  // Notion tools
  else if (toolName.includes('Notion') || toolName.includes('notion')) {
    const q = data.query as string
    summary = q ? `Searching Notion for "${q}"` : 'Querying Notion'
  }
  // Stripe tools
  else if (toolName.includes('Stripe') || toolName.includes('stripe')) {
    summary = 'Pulling Stripe data'
  }
  // PostHog tools
  else if (toolName.includes('PostHog') || toolName.includes('posthog')) {
    summary = 'Checking PostHog analytics'
  }
  // Intercom tools
  else if (toolName.includes('Intercom') || toolName.includes('intercom')) {
    summary = 'Checking Intercom conversations'
  }
  // Web tools
  else if (toolName === 'webSearchTool') {
    const q = data.query as string
    summary = q ? `Searching: "${q}"` : 'Searching the web'
  } else if (toolName === 'webExtractTool') {
    const url = data.url as string
    summary = url ? `Reading ${url.slice(0, 40)}…` : 'Extracting webpage'
  }
  // Account tools
  else if (toolName === 'getAccountDetails') {
    summary = 'Pulling account details'
  } else if (toolName === 'getAllAccounts') {
    summary = 'Listing all accounts'
  } else if (toolName === 'getAccountTimeline') {
    summary = 'Checking account history'
  }
  // Generic — use the TOOL_LABELS display name
  else {
    summary = 'Processing…'
  }

  return (
    <div className="text-[11px] text-neutral-500 italic py-0.5">
      {summary}
    </div>
  )
}

function ToolResultSummary({ toolName, result }: { toolName: string; result: unknown }) {
  if (!result || typeof result !== 'object') return null
  const data = result as Record<string, unknown>

  // Error state — only show "Connect" badge for actual connection/auth errors
  if (data.error) {
    const errorStr = String(data.error).toLowerCase()
    const isConnectionError =
      errorStr.includes('not connected') ||
      errorStr.includes('not configured') ||
      errorStr.includes('reconnect') ||
      errorStr.includes('credentials are missing') ||
      errorStr.includes('refresh token') ||
      errorStr.includes('oauth') ||
      errorStr.includes('authentication') ||
      errorStr.includes('unauthorized') ||
      errorStr.includes('integration') ||
      data.dataSource === 'connection_guard'

    if (isConnectionError) {
      return (
        <UnconnectedIntegrationBadge toolName={toolName} errorText={String(data.error)} />
      )
    }

    // Generic error (Bad Request, etc.) — show as plain text, no misleading Connect button
    return (
      <div className="text-[12px] text-red-400/80 font-normal py-0.5 mt-0.5">
        {formatCleanErrorMessage(String(data.error))}
      </div>
    )
  }

  // Account details
  if (toolName === 'getAccountDetails' && data.name) {
    return (
      <MiniResultCard
        icon={<Database className="w-4 h-4 text-neutral-400" />}
        title={<span className="text-white">{String(data.name)}</span>}
        subtitle={`${data.mrr ?? ''} · Risk: ${data.riskLevel ?? 'unknown'} · Usage: ${data.usageDelta ?? '?'}`}
      />
    )
  }

  // All accounts
  if (toolName === 'getAllAccounts' && Array.isArray(data.accounts)) {
    const accounts = data.accounts as Array<Record<string, unknown>>
    return (
      <div className="flex flex-col gap-1">
        {accounts.slice(0, 5).map((acc, i) => (
          <MiniResultCard
            key={i}
            icon={<img src="/logos/stripe.svg" alt="Stripe" className="w-3.5 h-3.5 object-contain" />}
            title={<span className="text-white">{String(acc.name)}</span>}
            subtitle={`${acc.mrr ?? ''} · ${String(acc.riskLevel ?? 'unknown')} risk`}
          />
        ))}
        {accounts.length > 5 && (
          <div className="text-[12px] text-neutral-500 pl-7">+ {accounts.length - 5} more accounts</div>
        )}
      </div>
    )
  }

  // Gmail threads (both account-level and founder's own inbox)
  if ((toolName === 'getGmailThreadsForAccount' || toolName === 'getMyInbox') && Array.isArray(data.threads)) {
    const threads = data.threads as Array<Record<string, unknown>>
    if (threads.length === 0) {
      return (
        <div className="text-[12px] text-neutral-500 flex items-center gap-1.5 mb-2">
          <img src="/logos/gmail.svg" alt="Gmail" className="w-3.5 h-3.5 object-contain opacity-60" /> No threads found
        </div>
      )
    }
    return (
      <div className="flex flex-col gap-1">
        {threads.map((thread, i) => (
          <MiniResultCard
            key={i}
            index={i}
            icon={<img src="/logos/gmail.svg" alt="Gmail" className="w-3.5 h-3.5 object-contain" />}
            title={<span className="text-white">{String(thread.subject ?? 'No subject')}</span>}
            subtitle={`From: ${String(thread.from ?? 'unknown')}${thread.needsReply ? ' · Needs reply' : ''}`}
          />
        ))}
      </div>
    )
  }

  // Stripe account state
  if (toolName === 'getStripeAccountState' && Array.isArray(data.subscriptions)) {
    const subs = data.subscriptions as Array<Record<string, unknown>>
    return (
      <div className="flex flex-col gap-1">
        {subs.map((sub, i) => (
          <MiniResultCard
            key={i}
            icon={<img src="/logos/stripe.svg" alt="Stripe" className="w-3.5 h-3.5 object-contain" />}
            title={<span className="text-white">{String(sub.plan ?? 'Subscription')}</span>}
            subtitle={`Status: ${String(sub.status)} ${sub.cancelAtPeriodEnd ? '· Cancelling' : ''}`}
          />
        ))}
      </div>
    )
  }

  // Draft generated
  if (toolName === 'generateFollowUpDraft' && data.success) {
    return (
      <MiniResultCard
        icon={<img src="/logos/gmail.svg" alt="Gmail" className="w-3.5 h-3.5 object-contain" />}
        title={<span className="text-white">Draft created: {String(data.subject ?? '')}</span>}
        subtitle={`For ${String(data.accountName ?? 'account')} · ${String(data.draftType ?? '')}`}
      />
    )
  }

  // Risk updated
  if (toolName === 'updateAccountRisk' && data.success) {
    return (
      <MiniResultCard
        icon={<Zap className="w-4 h-4 text-amber-400" />}
        title={<span className="text-white">{String(data.accountName ?? 'Account')} risk updated</span>}
        subtitle={`${String(data.previousRisk ?? '?')} → ${String(data.newRisk ?? '?')}`}
      />
    )
  }

  // Sync results — keep timeline clean, don't show technical data counters
  if (data.success && (data.syncedAccounts !== undefined || data.delivered !== undefined)) {
    return null
  }

  // Web Search results
  if (toolName === 'webSearchTool' && data.results && Array.isArray(data.results)) {
    const results = data.results as Array<Record<string, unknown>>
    return (
      <div className="flex flex-col gap-1 mb-2">
        {results.slice(0, 3).map((item, i) => (
          <MiniResultCard
            key={i}
            icon={<Globe className="w-4 h-4 text-sky-400" />}
            title={<span className="text-white">{String(item.title ?? 'Web result')}</span>}
            subtitle={String(item.snippet || item.url || '')}
          />
        ))}
      </div>
    )
  }

  // Generic success
  if (data.success) {
    return (
      <div className="text-[12px] text-emerald-400/70 mb-2 flex items-center gap-1.5">
        <div className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
        Completed successfully
      </div>
    )
  }

  return null
}

// ─── Extract tool name from part ─────────────────────────────────────
function extractToolName(part: Record<string, unknown>): string {
  // DynamicToolUIPart has toolName directly
  if (typeof part.toolName === 'string') return part.toolName
  // ToolUIPart has type: `tool-${NAME}` — extract from type string
  const partType = String(part.type ?? '')
  if (partType.startsWith('tool-')) return partType.slice(5)
  return 'unknown'
}

// ─── Single Message Renderer ─────────────────────────────────────────

function AgentMessageBubble({ message, avatarUrl }: { message: UIMessage; avatarUrl: string | null }) {
  const { sendMessage, executeContainment } = useChatContext()
  if (message.role === "user") {
    // User prompt bubble (right-aligned like the mock)
    const textContent = message.parts
      ?.filter((p: MessagePart): p is MessagePart & { text: string } => p.type === "text" && typeof p.text === "string")
      .map((p) => p.text)
      .join("") ?? ""

    if (!textContent) return null

    const displayAvatar = avatarUrl || "/user-avatar.svg"

    return (
      <div className="w-full flex justify-end items-start gap-3 relative z-10 mt-6 mb-4 pl-8">
        <div className="text-[13.5px] font-semibold text-white tracking-tight leading-relaxed break-words text-right max-w-[88%] pt-0.5">
          {textContent}
        </div>
        <div className="w-8 h-8 rounded-full border border-white/20 flex items-center justify-center shrink-0 shadow-sm overflow-hidden p-0.5 mt-0.5" title="You">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img
            src={displayAvatar}
            alt="User Avatar"
            className="w-full h-full object-contain rounded-full"
          />
        </div>
      </div>
    )
  }

  // Assistant message — render parts sequentially
  const parts = message.parts ?? []

  // Group sequential tool calls into reasoning batches
  const rendered: React.ReactNode[] = []
  let toolBatch: React.ReactNode[] = []
  let toolBatchCount = 0

  const flushToolBatch = () => {
    if (toolBatch.length > 0) {
      // Check if any tool in this batch is still executing (input-streaming or input-available)
      const isExecuting = toolBatch.some(node =>
        React.isValidElement(node) && (node.props as { isLoading?: boolean }).isLoading
      )

      rendered.push(
        <AgentReasoningBatch key={`batch-${rendered.length}`} stepsCount={toolBatchCount} isExecuting={isExecuting}>
          {toolBatch}
        </AgentReasoningBatch>
      )
      toolBatch = []
      toolBatchCount = 0
    }
  }

  for (let i = 0; i < parts.length; i++) {
    const part = parts[i]

    if (part.type === "text" && part.text && part.text.trim()) {
      flushToolBatch()
      rendered.push(<AgentSpeechBlock key={`text-${i}`} text={part.text} />)
    }

    if (part.type === "reasoning" && typeof part.text === 'string' && part.text.trim()) {
      toolBatch.push(
        <MonologueBlock key={`reasoning-${i}`} text={part.text} />
      )
    }

    // Tool parts: in AI SDK v6, tool types are `tool-${NAME}` or `dynamic-tool`
    // They have state, input, output properties directly on the part
    const rawPart = part as Record<string, unknown>
    const partType = String(rawPart.type ?? '')
    const isTool = partType.startsWith('tool-') || partType === 'dynamic-tool'

    if (isTool) {
      const toolName = extractToolName(rawPart)
      const label = TOOL_LABELS[toolName] ?? toolName
      const icon = TOOL_ICONS[toolName] ?? <Search className="w-3.5 h-3.5 text-neutral-500" />
      const state = String(rawPart.state ?? '')
      // AI SDK may store input as 'input', 'args', or nested — try all
      const toolInput = rawPart.input ?? rawPart.args ?? rawPart.toolInput ?? null

      if (state === "input-streaming" || state === "input-available") {
        toolBatch.push(
          <TimelineNode
            key={`tool-${i}`}
            title={label}
            icon={icon}
            isLoading={true}
          >
            <ToolThinkingSummary toolName={toolName} input={toolInput} />
          </TimelineNode>
        )
        toolBatchCount++
      } else if (state === "output-available") {
        toolBatch.push(
          <TimelineNode
            key={`tool-${i}`}
            title={label}
            icon={icon}
            isCompleted={true}
            isCollapsible={true}
          >
            <ToolThinkingSummary toolName={toolName} input={toolInput} />
            <ToolResultSummary toolName={toolName} result={rawPart.output} />
          </TimelineNode>
        )
        toolBatchCount++
      } else if (state === "output-error") {
        // Tool failed — show clean error alert badge with Connect [Provider] button
        toolBatch.push(
          <TimelineNode
            key={`tool-${i}`}
            title={label}
            icon={icon}
            isCompleted={true}
          >
            <UnconnectedIntegrationBadge toolName={toolName} errorText={String(rawPart.errorText ?? 'Integration not connected for this workspace')} />
          </TimelineNode>
        )
        toolBatchCount++
      }
    }
  }

  flushToolBatch()

  const hasContainment =
    message.incidentId ||
    message.id === "demo-assistant-3" ||
    parts.some(
      (p: any) =>
        (typeof p.text === "string" && (p.text.includes("iptables") || p.text.includes("Containment Staged"))) ||
        p.toolName === "tool_generate_containment_command"
    )

  if (hasContainment) {
    rendered.push(
      <AgentApprovalBlock
        key={`approval-${message.id}`}
        title="Human-in-the-Loop Containment Execution Gate"
        description="Authorize non-destructive firewall source-drop script across Linux iptables and Cisco ACL."
        onApproved={() => {
          if (message.incidentId) {
            executeContainment(message.incidentId, "iptables")
          }
        }}
      />
    )
  }

  if (rendered.length === 0) return null

  return (
    <div className="w-full relative z-10 pt-2 mb-6">
      <div className="w-full flex flex-col gap-2">
        {rendered}
      </div>
    </div>
  )
}

// ─── Loading Indicator ───────────────────────────────────────────────
function AgentThinking() {
  return (
    <div className="w-full flex items-center gap-2.5 mt-2 mb-3 py-1">
      <DotmSquare12 size={16} dotSize={2.5} speed={1.2} bloom />
      <span className="text-[13px] font-medium text-neutral-400 tracking-tight">Thinking...</span>
    </div>
  )
}

// ─── Error Message Formatter ──────────────────────────────────────────
export function formatCleanErrorMessage(rawMsg: string): string {
  if (!rawMsg) return "An unexpected error occurred."

  let msg = rawMsg
  try {
    if (msg.includes('{') && msg.includes('}')) {
      const jsonStart = msg.indexOf('{')
      const jsonEnd = msg.lastIndexOf('}')
      const jsonStr = msg.substring(jsonStart, jsonEnd + 1)
      const parsed = JSON.parse(jsonStr)
      if (parsed.error?.message) {
        msg = parsed.error.message
      } else if (parsed.message) {
        msg = parsed.message
      }
    }
  } catch {
    // Keep original
  }

  const low = msg.toLowerCase()

  if (low.includes("rate_limit") || low.includes("429") || low.includes("tpm") || low.includes("rpm")) {
    return "OpenAI API rate limit reached. Please wait a few moments before trying again or check your OpenAI plan quota."
  }

  if (
    low.includes("500") ||
    low.includes("502") ||
    low.includes("503") ||
    low.includes("504") ||
    low.includes("overloaded") ||
    low.includes("timeout") ||
    low.includes("service_unavailable") ||
    low.includes("bad gateway")
  ) {
    return "The AI model service is temporarily unavailable. Please try your request again in a few moments."
  }

  if (
    low.includes("401") ||
    low.includes("403") ||
    low.includes("invalid_api_key") ||
    low.includes("unauthorized") ||
    low.includes("not configured")
  ) {
    return "AI model authentication or configuration issue. Please check your API key settings."
  }

  if (
    low.includes("context_length") ||
    low.includes("maximum context length") ||
    low.includes("token limit")
  ) {
    return "The request exceeded the maximum conversation context limit. Try starting a fresh thread or asking a more focused question."
  }

  if (
    low.includes("content_filter") ||
    low.includes("policy_violation") ||
    low.includes("flagged")
  ) {
    return "The request could not be processed due to content safety policies."
  }

  // Strip any vendor URLs or request IDs that passed through
  const sanitized = msg
    .replace(/https?:\/\/[^\s]+/gi, '')
    .replace(/\b(?:request\s*id|apim-request-id|req_[a-zA-Z0-9]+)[:=]?\s*[^\s]+/gi, '')
    .trim()

  if (!sanitized || sanitized.startsWith('{') || sanitized.includes('"error"')) {
    return "The agent encountered an unexpected issue while processing your request. Please try again."
  }

  return sanitized
}

// ─── Main Feed Component ─────────────────────────────────────────────

export function AgentFeed() {
  const { messages, isLoading, status, hydrationStatus, error } = useChatContext()
  const feedRef = React.useRef<HTMLDivElement>(null)
  const avatarUrl = "/user-avatar.svg"

  // Auto-scroll on new messages
  React.useEffect(() => {
    if (feedRef.current) {
      feedRef.current.scrollTop = feedRef.current.scrollHeight
    }
  }, [messages, status])

  // Show loading state during server hydration
  if (hydrationStatus === "loading") {
    return (
      <div className="flex-1 flex items-center justify-center">
        <div className="flex items-center gap-3">
          <Loader2 className="w-4 h-4 text-neutral-500 animate-spin" />
          <span className="text-[13px] text-neutral-500">Restoring conversation...</span>
        </div>
      </div>
    )
  }

  if (messages.length === 0 && !isLoading) {
    return <div className="flex-1" />
  }

  return (
    <div ref={feedRef} className="flex-1 overflow-y-auto px-6 py-6 flex flex-col custom-scrollbar">
      <div className="w-full flex flex-col gap-4">
        {messages.map((message) => (
          <AgentMessageBubble key={message.id} message={message} avatarUrl={avatarUrl} />
        ))}

        {(() => {
          const lastMsg = messages[messages.length - 1]
          const hasTextOutput = lastMsg?.parts?.some(
            (p: MessagePart) => p.type === "text" && Boolean(p.text?.trim())
          )
          const isThinkingActive = isLoading && (!lastMsg || lastMsg.role === "user" || !hasTextOutput) && !error
          return isThinkingActive ? <AgentThinking /> : null
        })()}

        {error && (
          <div className="w-full flex justify-center mt-2 mb-4">
            <div className="w-full bg-red-500/10 border border-red-500/20 rounded-xl p-3.5 flex gap-2.5 shadow-md">
              <div className="w-5 h-5 rounded-full bg-red-500/20 flex items-center justify-center shrink-0 mt-0.5">
                <AlertCircle className="w-3.5 h-3.5 text-red-400" />
              </div>
              <div className="flex flex-col min-w-0">
                <h4 className="text-[12px] font-semibold text-red-400 mb-0.5">
                  {error.message?.toLowerCase().includes('rate limit') || error.message?.includes('429')
                    ? 'API Rate Limit Exceeded'
                    : 'Execution Notice'}
                </h4>
                <p className="text-[12px] text-red-200/90 leading-relaxed font-sans break-words whitespace-pre-wrap">
                  {formatCleanErrorMessage(error.message || "The agent encountered an error.")}
                </p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
