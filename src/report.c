// SPDX-License-Identifier: MIT

#include "report.h"

#include <inttypes.h>

static int write_json_string(FILE *stream, const char *text)
{
    const unsigned char *cursor =
        (const unsigned char *)(text ? text : "");

    if (fputc('"', stream) == EOF)
        return -1;
    while (*cursor) {
        unsigned char character = *cursor++;

        switch (character) {
        case '"':
            if (fputs("\\\"", stream) == EOF)
                return -1;
            break;
        case '\\':
            if (fputs("\\\\", stream) == EOF)
                return -1;
            break;
        case '\b':
            if (fputs("\\b", stream) == EOF)
                return -1;
            break;
        case '\f':
            if (fputs("\\f", stream) == EOF)
                return -1;
            break;
        case '\n':
            if (fputs("\\n", stream) == EOF)
                return -1;
            break;
        case '\r':
            if (fputs("\\r", stream) == EOF)
                return -1;
            break;
        case '\t':
            if (fputs("\\t", stream) == EOF)
                return -1;
            break;
        case '<':
            if (fputs("\\u003c", stream) == EOF)
                return -1;
            break;
        case '>':
            if (fputs("\\u003e", stream) == EOF)
                return -1;
            break;
        case '&':
            if (fputs("\\u0026", stream) == EOF)
                return -1;
            break;
        default:
            if (character < 0x20) {
                if (fprintf(stream, "\\u%04x", character) < 0)
                    return -1;
            } else if (fputc(character, stream) == EOF) {
                return -1;
            }
        }
    }
    return fputc('"', stream) == EOF ? -1 : 0;
}

int cw_write_chain_json(FILE *stream, const struct cw_report_chain *chain)
{
    uint32_t index;

    if (fputs("{\"type\":\"chain\",\"kind\":", stream) == EOF ||
        write_json_string(stream, chain->kind ? chain->kind : "async") ||
        fputs(",\"name\":", stream) == EOF ||
        write_json_string(stream, chain->name ? chain->name : "") ||
        fprintf(stream,
                ",\"timestamp_ms\":%" PRIu64
                ",\"pid\":%u,\"tid\":%u,\"comm\":",
                chain->timestamp_ms, chain->pid, chain->tid) < 0 ||
        write_json_string(stream, chain->comm) ||
        fprintf(stream,
                ",\"duration_ns\":%" PRIu64
                ",\"offcpu_ns\":%" PRIu64
                ",\"blocked_ns\":%" PRIu64
                ",\"runqueue_ns\":%" PRIu64
                ",\"truncated\":%u,\"hops\":[",
                chain->duration_ns, chain->offcpu_ns,
                chain->blocked_ns, chain->runqueue_ns,
                chain->truncated) < 0)
        return -1;

    for (index = 0; index < chain->hop_count; index++) {
        const struct cw_report_hop *hop = &chain->hops[index];

        if (index && fputc(',', stream) == EOF)
            return -1;
        if (fprintf(stream,
                    "{\"index\":%u,\"source\":",
                    hop->index) < 0 ||
            write_json_string(stream, hop->source) ||
            fputs(",\"target\":", stream) == EOF ||
            write_json_string(stream, hop->target) ||
            fprintf(stream,
                    ",\"source_exit\":%s,"
                    "\"pid\":%u,\"tid\":%u,\"target_tid\":%u,"
                    "\"target_arg\":%u,"
                    "\"comm\":",
                    hop->source_exit ? "true" : "false",
                    hop->pid, hop->tid, hop->target_tid,
                    hop->target_arg) < 0 ||
            write_json_string(stream, hop->comm) ||
            fprintf(stream,
                    ",\"key\":\"0x%016" PRIx64
                    "\",\"queue_ns\":%" PRIu64
                    ",\"handoff_kind\":%u"
                    ",\"handoff_flags\":%u"
                    ",\"publish_ns\":%" PRIu64
                    ",\"notify_ns\":%" PRIu64
                    ",\"loop_ns\":%" PRIu64
                    ",\"poll_ns\":%" PRIu64
                    ",\"dispatch_ns\":%" PRIu64
                    ",\"work_ns\":%" PRIu64
                    ",\"offcpu_ns\":%" PRIu64
                    ",\"blocked_ns\":%" PRIu64
                    ",\"runqueue_ns\":%" PRIu64
                    ",\"work_kind\":%u",
                    hop->key, hop->queue_ns,
                    hop->handoff_kind, hop->handoff_flags,
                    hop->publish_ns, hop->notify_ns,
                    hop->loop_ns, hop->poll_ns,
                    hop->dispatch_ns, hop->work_ns,
                    hop->offcpu_ns, hop->blocked_ns,
                    hop->runqueue_ns, hop->work_kind) < 0)
            return -1;
        if (hop->wait_kind) {
            if (fprintf(stream,
                        ",\"wait\":{\"kind\":\"futex\","
                        "\"operation\":%u,"
                        "\"address\":\"0x%016" PRIx64 "\","
                        "\"duration_ns\":%" PRIu64 ","
                        "\"wake_after_start_ns\":%" PRIu64 ","
                        "\"waker_pid\":%u,\"waker_tid\":%u,"
                        "\"waker_comm\":",
                        hop->wait_operation, hop->wait_address,
                        hop->wait_duration_ns, hop->wait_wake_ns,
                        hop->waker_pid, hop->waker_tid) < 0 ||
                write_json_string(stream, hop->waker_comm) ||
                fputc('}', stream) == EOF)
                return -1;
        } else if (fputs(",\"wait\":null", stream) == EOF) {
            return -1;
        }
        if (fputc('}', stream) == EOF)
            return -1;
    }
    return fputs("]}", stream) == EOF ? -1 : 0;
}

static int write_queue_diagnostic(FILE *stream,
                                  const struct cw_queue_diagnostic *item)
{
    if (fprintf(stream, "{\"index\":%u,\"source\":", item->index) < 0 ||
        write_json_string(stream, item->source) ||
        fprintf(stream, ",\"source_exit\":%s",
                item->source_exit ? "true" : "false") < 0 ||
        fputs(",\"target\":", stream) == EOF ||
        write_json_string(stream, item->target) ||
        fprintf(stream,
                ",\"submitted\":%" PRIu64
                ",\"started\":%" PRIu64
                ",\"completed\":%" PRIu64
                ",\"pending\":%" PRIu64
                ",\"peak_pending\":%" PRIu64
                ",\"active\":%" PRIu64
                ",\"peak_active\":%" PRIu64
                ",\"queue_total_ns\":%" PRIu64
                ",\"work_total_ns\":%" PRIu64
                ",\"futex_waits\":%" PRIu64
                ",\"futex_wait_ns\":%" PRIu64
                ",\"duplicate_keys\":%" PRIu64
                ",\"expired\":%" PRIu64
                ",\"unmatched_targets\":%" PRIu64
                ",\"dropped\":%" PRIu64
                ",\"worker_count\":%u"
                ",\"busiest_worker_tid\":%u"
                ",\"busiest_worker_started\":%" PRIu64
                ",\"busiest_worker_average_work_ns\":%" PRIu64 "}",
                item->submitted, item->started, item->completed,
                item->pending, item->peak_pending, item->active,
                item->peak_active, item->queue_total_ns,
                item->work_total_ns, item->futex_waits,
                item->futex_wait_ns, item->duplicate_keys,
                item->expired, item->unmatched_targets, item->dropped,
                item->worker_count, item->busiest_worker_tid,
                item->busiest_worker_started,
                item->busiest_worker_average_work_ns) < 0)
        return -1;
    return 0;
}

int cw_write_queue_diagnostics_json(
    FILE *stream, const struct cw_queue_diagnostic *diagnostics,
    size_t count)
{
    size_t index;

    if (fputs("{\"type\":\"queue_diagnostics\",\"hops\":[",
              stream) == EOF)
        return -1;
    for (index = 0; index < count; index++) {
        if (index && fputc(',', stream) == EOF)
            return -1;
        if (write_queue_diagnostic(stream, &diagnostics[index]))
            return -1;
    }
    return fputs("]}", stream) == EOF ? -1 : 0;
}

int cw_html_report_begin_mode(FILE *stream, const char *mode)
{
    static const char header[] =
        "<!doctype html>\n"
        "<html lang=\"en\"><head><meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
        "<title>callweave async latency report</title>\n"
        "<style>\n"
        ":root{color-scheme:dark;--bg:#0b1020;--panel:#121a2d;--line:#27324a;"
        "--text:#e8edf7;--muted:#8f9bb3;--queue:#8b5cf6;--cpu:#22c55e;"
        "--blocked:#ef4444;--runq:#f59e0b;--unknown:#3b82f6;"
        "--accent:#38bdf8;--work:#2563eb;--publish:#a78bfa;"
        "--notify:#d946ef;--loop:#f59e0b;--poll:#6366f1;--dispatch:#7c3aed}\n"
        "*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle "
        "at top,#17213a 0,var(--bg) 42%);color:var(--text);font:14px/1.45 "
        "Inter,ui-sans-serif,system-ui,sans-serif}main{max-width:1380px;margin:auto;"
        "padding:32px}.eyebrow{color:#7dd3fc;text-transform:uppercase;"
        "letter-spacing:.16em;font-size:11px;font-weight:700}h1{margin:.25rem 0;"
        "font-size:30px}p{color:var(--muted)}.toolbar{display:flex;gap:16px;"
        "align-items:end;flex-wrap:wrap;margin:24px 0}.field{display:grid;gap:6px;"
        "min-width:320px;width:min(100%,860px)}.field span{color:var(--muted);font-size:12px}select{"
        "background:#0d1528;color:var(--text);border:1px solid var(--line);"
        "border-radius:9px;padding:10px 12px;width:100%}.cards{display:grid;"
        "grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;"
        "margin:16px 0}"
        ".card,.panel{background:color-mix(in srgb,var(--panel) 94%,transparent);"
        "border:1px solid var(--line);border-radius:14px;box-shadow:"
        "0 18px 50px #0004}.card{padding:16px}.card span{display:block;color:"
        "var(--muted);font-size:12px}.card strong{display:block;margin-top:5px;"
        "font-size:22px}.panel{padding:20px;margin:16px 0}.panel h2{font-size:17px;"
        "margin:0}.panel-head{display:flex;justify-content:space-between;"
        "gap:20px;align-items:start;margin-bottom:18px}.legend{display:flex;"
        "gap:12px;flex-wrap:wrap;color:var(--muted);font-size:12px}.dot{width:9px;"
        "height:9px;border-radius:3px;display:inline-block;margin-right:5px}"
        ".timeline,.breakdown{display:grid;gap:11px}.row{display:grid;"
        "grid-template-columns:250px 1fr;gap:14px;align-items:center}.label{"
        "overflow:hidden}.label strong,.label span{display:block;white-space:"
        "nowrap;overflow:hidden;text-overflow:ellipsis}.label span{color:"
        "var(--muted);font-size:12px}.track{height:34px;background:#0b1222;"
        "border:1px solid #202a40;border-radius:7px;position:relative;overflow:"
        "hidden}.segment{position:absolute;top:0;height:100%;min-width:2px;"
        "border-right:1px solid #07101fbb}.queue{background:var(--queue)}"
        ".cpu{background:var(--cpu)}.blocked{background:var(--blocked)}"
        ".runq{background:var(--runq)}.unknown{background:var(--unknown)}"
        ".publish{background:var(--publish)}.notify{background:var(--notify)}"
        ".loop{background:var(--loop)}"
        ".poll{background:var(--poll)}.dispatch{background:var(--dispatch)}"
        ".axis{margin-left:264px;display:flex;justify-content:space-between;"
        "color:var(--muted);font-size:11px}.empty{padding:36px;text-align:center;"
        "color:var(--muted)}table{width:100%;border-collapse:collapse}"
        "th,td{text-align:left;padding:10px;border-bottom:1px solid var(--line)}"
        "th{color:var(--muted);font-size:11px;text-transform:uppercase;"
        "letter-spacing:.08em}code{color:#bae6fd}.view-tabs{display:flex;gap:6px;"
        "width:max-content;padding:5px;margin:22px 0 8px;background:#0d1528;"
        "border:1px solid var(--line);border-radius:11px}.view-tab{appearance:none;"
        "border:0;border-radius:7px;padding:9px 18px;background:transparent;"
        "color:var(--muted);font:inherit;font-weight:650;cursor:pointer}.view-tab:hover{"
        "color:var(--text);background:#ffffff0a}.view-tab[aria-selected=true]{"
        "color:#e0f2fe;background:#12304b;box-shadow:inset 0 0 0 1px #38bdf855}"
        ".view-tab:focus-visible{outline:2px solid var(--accent);outline-offset:2px}"
        "[role=tabpanel][hidden]{display:none}.sequence-note{margin:0 0 14px;"
        "font-size:12px}.sequence-scroll{overflow-x:auto;padding-bottom:5px;"
        "border-radius:10px;background:#0b1222;border:1px solid #202a40}"
        ".sequence-chart{display:block;width:100%;min-width:980px;height:auto}"
        ".seq-axis{stroke:#334155;stroke-width:1}.seq-life{stroke:#41506a;"
        "stroke-width:1}.seq-thread{fill:#111c31;stroke:#2b3955}"
        ".seq-thread-name{fill:var(--text);font-size:12px;font-weight:650}"
        ".seq-thread-id,.seq-tick{fill:var(--muted);font-size:11px}"
        ".seq-queue-band{fill:var(--queue);opacity:.22}.seq-queue{fill:none;"
        "stroke:var(--queue);stroke-width:2.6;"
        "stroke-linecap:round;stroke-linejoin:round}"
        ".seq-publish-band{fill:var(--publish);opacity:.34}"
        ".seq-notify-band{fill:var(--notify);opacity:.44}"
        ".seq-loop-band{fill:var(--loop);opacity:.42}"
        ".seq-poll-band{fill:var(--poll);opacity:.38}"
        ".seq-dispatch-band{fill:var(--dispatch);opacity:.34}"
        ".seq-submit{fill:none;stroke:#64748b;stroke-width:1.6;stroke-linecap:round;"
        "stroke-linejoin:round}.seq-work{fill:#1d4ed8;"
        "stroke:#60a5fa;stroke-width:1}.seq-wait{fill:#334155;"
        "stroke:#94a3b8;stroke-width:1}.seq-dot{fill:#dbeafe;stroke:#0b1222;"
        "stroke-width:2}.seq-label{fill:var(--text);font-size:11px;font-weight:500;"
        "paint-order:stroke;stroke:#0b1222;stroke-width:5px;stroke-linejoin:round}"
        ".seq-queue-label{fill:#c4b5fd;font-size:11px;font-weight:500;"
        "letter-spacing:.02em;paint-order:stroke;stroke:#0b1222;"
        "stroke-width:6px;stroke-linejoin:round}.sequence-queue-key{display:inline-block;"
        "margin-right:5px;padding:2px 7px;border:1px solid #8b5cf688;"
        "border-radius:999px;background:#8b5cf622;color:#c4b5fd;font-weight:500}"
        ".seq-sub{fill:var(--muted);font-size:11px;paint-order:stroke;"
        "stroke:#0b1222;stroke-width:4px}.sequence-total{white-space:nowrap;"
        "color:#bae6fd}.waterfall-legend{justify-content:flex-end}"
        "footer{color:var(--muted);"
        "text-align:center;padding:12px}@media(max-width:800px){main{padding:18px}"
        ".cards{grid-template-columns:repeat(2,1fr)}.row{grid-template-columns:1fr}"
        ".axis{margin-left:0}.field{min-width:100%}.view-tabs{width:100%}"
        ".view-tab{flex:1;padding-inline:8px}.panel{padding:15px}}\n"
        "</style></head><body><main>\n"
        "<div class=\"eyebrow\">eBPF causal tracing</div>\n"
        "<h1 id=\"reportTitle\">callweave async latency report</h1>\n"
        "<p id=\"reportSubtitle\">Queue and work latency across asynchronous thread handoffs. Work "
        "colors are aggregate scheduler-state attribution, not chronological "
        "sub-intervals.</p>\n"
        "<div class=\"toolbar\"><label class=\"field\"><span id=\"selectLabel\">Completed chain</span>"
        "<select id=\"chain\"></select></label></div>\n"
        "<section class=\"cards\">"
        "<div class=\"card\"><span id=\"countLabel\">Captured chains</span><strong id=\"count\">0</strong></div>"
        "<div class=\"card\"><span>Selected total</span><strong id=\"selected\">—</strong></div>"
        "<div class=\"card\"><span id=\"selectedQueueLabel\">Selected queue</span><strong id=\"selectedQueue\">—</strong></div>"
        "<div class=\"card\"><span id=\"selectedWorkLabel\">Selected work</span><strong id=\"selectedWork\">—</strong></div>"
        "<div class=\"card\"><span>Average latency</span><strong id=\"average\">—</strong></div>"
        "<div class=\"card\"><span>P95 latency</span><strong id=\"p95\">—</strong></div>"
        "<div class=\"card\"><span>Maximum latency</span><strong id=\"maximum\">—</strong></div>"
        "</section>\n"
        "<nav class=\"view-tabs\" role=\"tablist\" aria-label=\"Report view\">"
        "<button class=\"view-tab\" id=\"tab-sequence\" type=\"button\" role=\"tab\" "
        "aria-selected=\"true\" aria-controls=\"sequence-view\">Sequence</button>"
        "<button class=\"view-tab\" id=\"tab-waterfall\" type=\"button\" role=\"tab\" "
        "aria-selected=\"false\" aria-controls=\"waterfall-view\" tabindex=\"-1\">Waterfall</button>"
        "<button class=\"view-tab\" id=\"tab-details\" type=\"button\" role=\"tab\" "
        "aria-selected=\"false\" aria-controls=\"details-view\" tabindex=\"-1\">Details</button>"
        "</nav>\n"
        "<div id=\"sequence-view\" role=\"tabpanel\" aria-labelledby=\"tab-sequence\">"
        "<section class=\"panel\"><div class=\"panel-head\"><div><h2 id=\"sequenceTitle\">Cross-thread "
        "sequence</h2><p id=\"sequenceMeta\"></p></div><strong id=\"sequenceTotal\" "
        "class=\"sequence-total\"></strong></div><p class=\"sequence-note\" id=\"sequenceNote\">"
        "Vertical order follows elapsed time; spacing is compressed so short phases "
        "remain readable. <span class=\"sequence-queue-key\">Queue wait</span> "
        "connectors show handoff delay; blue activations show target work. "
        "Scheduler-state breakdown remains an "
        "aggregate and is shown in Waterfall.</p><div class=\"sequence-scroll\">"
        "<div id=\"sequence\"></div></div></section></div>\n"
        "<div id=\"waterfall-view\" role=\"tabpanel\" aria-labelledby=\"tab-waterfall\" hidden>"
        "<section class=\"panel\"><div class=\"panel-head\"><div><h2>Causal "
        "waterfall</h2><p id=\"chainMeta\"></p></div><strong id=\"chainTotal\">"
        "</strong></div><div class=\"legend waterfall-legend\">"
        "<span><i class=\"dot queue\"></i>queue</span>"
        "<span><i class=\"dot cpu\"></i>on-CPU</span>"
        "<span><i class=\"dot blocked\"></i>blocked</span>"
        "<span><i class=\"dot runq\"></i>run queue</span>"
        "<span><i class=\"dot unknown\"></i>preempt / unknown / in-flight</span>"
        "</div><div id=\"axis\" class=\"axis\"></div><div id=\"timeline\" "
        "class=\"timeline\"></div></section>\n"
        "<section class=\"panel\"><div class=\"panel-head\"><div><h2>Per-hop "
        "latency composition</h2><p>Bars share one scale for direct comparison."
        "</p></div></div><div id=\"breakdown\" class=\"breakdown\"></div></section>"
        "</div>\n"
        "<div id=\"details-view\" role=\"tabpanel\" aria-labelledby=\"tab-details\" hidden>"
        "<section class=\"panel\" id=\"asyncDiagnostics\"><div class=\"panel-head\"><div><h2>Live queue "
        "diagnostics</h2><p>Final BPF counters include queued and running work, "
        "not only completed chains.</p></div></div><div style=\"overflow:auto\">"
        "<table><thead><tr><th>Stage</th><th>Submitted / started / done</th>"
        "<th>Pending</th><th>Active</th><th>Average queue</th>"
        "<th>Average work</th><th>Workers</th><th>Diagnosis</th>"
        "</tr></thead><tbody id=\"diagnostics\"></tbody></table></div></section>\n"
        "<section class=\"panel\"><div class=\"panel-head\"><div><h2 id=\"distributionTitle\">Completed-"
        "chain latency</h2><p id=\"distributionNote\">Exact values calculated from the completed chains "
        "embedded in this report. P95 requires 20 samples; P99 requires 100."
        "</p></div></div><div style=\"overflow:auto\"><table><thead><tr>"
        "<th>Stage</th><th>Samples</th><th>Queue avg / P50 / P95 / P99 / max</th>"
        "<th>Work avg / P50 / P95 / P99 / max</th><th>Observation</th>"
        "</tr></thead><tbody id=\"latencyStats\"></tbody></table></div></section>\n"
        "<section class=\"panel\"><div class=\"panel-head\"><div><h2>Hop details"
        "</h2><p>Raw correlation and scheduler timing for the selected chain."
        "</p></div></div><div style=\"overflow:auto\"><table><thead><tr>"
        "<th>Hop</th><th>Source → target</th><th>Threads</th><th>Key</th>"
        "<th>Queue</th><th>Handoff phases</th><th>Work</th><th>Dominant</th><th>Wait</th>"
        "<th>Waker</th></tr></thead>"
        "<tbody id=\"details\"></tbody></table></div></section></div>\n"
        "<footer>Generated locally by callweave. No external scripts or network "
        "requests.</footer></main>\n"
        "<script>const reportMode=";

    if (fputs(header, stream) == EOF ||
        write_json_string(stream, mode ? mode : "async") ||
        fputs(";const chains=[", stream) == EOF)
        return -1;
    return 0;
}

int cw_html_report_begin(FILE *stream)
{
    return cw_html_report_begin_mode(stream, "async");
}

int cw_html_report_write(FILE *stream, const struct cw_report_chain *chain,
                         bool *first)
{
    if (!*first && fputc(',', stream) == EOF)
        return -1;
    if (cw_write_chain_json(stream, chain))
        return -1;
    *first = false;
    return 0;
}

int cw_html_report_end(FILE *stream,
                       const struct cw_queue_diagnostic *diagnostics,
                       size_t count)
{
    static const char footer[] =
        ";\n"
        "const $=id=>document.getElementById(id);"
        "const ns=n=>{if(n>=1e9)return(n/1e9).toFixed(n>=1e10?2:3)+' s';"
        "if(n>=1e6)return(n/1e6).toFixed(n>=1e8?1:3)+' ms';"
        "if(n>=1e3)return(n/1e3).toFixed(n>=1e5?1:3)+' µs';return n+' ns'};"
        "const exact=n=>{if(n>=1e9)return(n/1e9).toFixed(6)+' s';"
        "if(n>=1e6)return(n/1e6).toFixed(3)+' ms';"
        "if(n>=1e3)return(n/1e3).toFixed(3)+' µs';return n+' ns'};"
        "const clock=t=>{const d=new Date(t);return d.toLocaleTimeString()+'.'+"
        "String(d.getMilliseconds()).padStart(3,'0')};"
        "const sum=c=>c.hops.reduce((n,h)=>n+h.queue_ns+h.work_ns,0);"
        "const sourceLabel=h=>h.source+(h.source_exit?' completed':' started');"
        "const handoffParts=h=>{if(h.handoff_kind!==1||!(h.handoff_flags&1))"
        "return[{n:'queue',v:h.queue_ns,c:'queue'}];const p="
        "[{n:'completion publish',v:h.publish_ns,c:'publish'},"
        "{n:'uv_async_send',v:h.notify_ns,c:'notify'}];"
        "if(h.handoff_flags&4){if(h.loop_ns)p.push({n:'loop active / backlog',"
        "v:h.loop_ns,c:'loop'});p.push({n:'epoll wait / wakeup',v:h.poll_ns,c:'poll'},"
        "{n:'ready to callback',v:h.dispatch_ns,c:'dispatch'})}"
        "else p.push({n:'loop active / backlog',v:h.loop_ns,c:'dispatch'});"
        "return p.reduce((n,x)=>n+x.v,0)===h.queue_ns?p:"
        "[{n:'queue',v:h.queue_ns,c:'queue'}]};"
        "const handoffText=h=>h.handoff_kind===1?(h.handoff_flags&1)?"
        "'publish '+exact(h.publish_ns)+'; uv_async_send '+"
        "((h.handoff_flags&2)?exact(h.notify_ns):'exit unobserved')+"
        "'; '+((h.handoff_flags&4)?(h.loop_ns?'loop-active/backlog '+"
        "exact(h.loop_ns)+'; ':'')+'epoll wait/wakeup '+exact(h.poll_ns)+"
        "'; ready→callback '+exact(h.dispatch_ns):'loop-active/backlog '+"
        "exact(h.loop_ns)+' (no epoll return)'):"
        "'notification boundary unavailable':'—';"
        "const workName=h=>h.work_kind===1?'in-flight':h.work_kind===2?'I/O':'work';"
        "const parts=h=>{const queued=handoffParts(h);if(h.work_kind)return[...queued,"
        "{n:workName(h),v:h.work_ns,c:'unknown'}];const cpu=Math.max(0,h.work_ns-h.offcpu_ns);"
        "const unknown=Math.max(0,h.offcpu_ns-h.blocked_ns-h.runqueue_ns);"
        "return[...queued,{n:'on-CPU',v:cpu,c:'cpu'},"
        "{n:'blocked',v:h.blocked_ns,c:'blocked'},"
        "{n:'run queue',v:h.runqueue_ns,c:'runq'},"
        "{n:'preempt / unknown',v:unknown,c:'unknown'}]};"
        "const dominant=h=>parts(h).reduce((a,b)=>b.v>a.v?b:a,{n:'none',v:0});"
        "const diagnose=d=>{const anomalies=d.duplicate_keys+d.expired+d.dropped;"
        "if(!d.submitted)return'waiting for samples';"
        "if(d.pending&&d.active&&d.active>=d.peak_active)return'workers saturated';"
        "if(d.completed&&d.futex_waits*4>=d.completed)return'lock contention';"
        "if(anomalies)return'correlation loss observed';return'no clear bottleneck'};"
        "function renderDiagnostics(){const body=$('diagnostics');"
        "body.replaceChildren();diagnosticReport.hops.forEach(d=>{"
        "const tr=document.createElement('tr');const worker=d.worker_count+"
        "(d.busiest_worker_tid?' (busiest TID '+d.busiest_worker_tid+')':'');"
        "const avgQueue=d.started?d.queue_total_ns/d.started:0;"
        "const avgWork=d.completed?d.work_total_ns/d.completed:0;"
        "[d.index+' · '+sourceLabel(d)+' → '+d.target,d.submitted+' / '+d.started+"
        "' / '+d.completed,d.pending+' (peak '+d.peak_pending+')',"
        "d.active+' (peak '+d.peak_active+')',ns(avgQueue),ns(avgWork),"
        "worker,diagnose(d)]."
        "forEach(v=>{const td=document.createElement('td');td.textContent=v;"
        "tr.appendChild(td)});body.appendChild(tr)});if(!diagnosticReport.hops."
        "length)body.innerHTML='<tr><td colspan=\"8\">No queue diagnostics."
        "</td></tr>'};"
        "const percentile=(sorted,p)=>sorted[Math.min(sorted.length-1,"
        "Math.ceil(sorted.length*p)-1)];"
        "const distribution=v=>{if(!v.length)return'n/a';const s=[...v].sort("
        "(a,b)=>a-b),avg=s.reduce((a,b)=>a+b,0)/s.length,p50=percentile(s,.5),"
        "p95=s.length>=20?exact(percentile(s,.95)):'n/a (<20)',"
        "p99=s.length>=100?exact(percentile(s,.99)):'n/a (<100)';return exact(avg)+"
        "' / '+exact(p50)+' / '+p95+' / '+p99+' / '+exact(s[s.length-1])};"
        "function completedStages(){const stages=new Map();chains.forEach(c=>"
        "c.hops.forEach(h=>{const key=h.index+'\\u0000'+sourceLabel(h)+'\\u0000'+h.target;"
        "if(!stages.has(key))stages.set(key,{index:h.index,source:sourceLabel(h),"
        "target:h.target,queue:[],work:[]});const s=stages.get(key);"
        "s.queue.push(h.queue_ns);s.work.push(h.work_ns)}));return[...stages.values()]"
        ".sort((a,b)=>a.index-b.index)}"
        "function latencyObservation(s){if(s.queue.length<20||s.work.length<20)"
        "return'not enough samples';const q=[...s.queue].sort((a,b)=>a-b),"
        "w=[...s.work].sort((a,b)=>a-b),qp=percentile(q,.95),wp=percentile(w,.95);"
        "if(qp>wp*2)return'queue/capacity pressure';if(wp>qp*2)return'slow task "
        "execution';return'balanced latency'}"
        "function renderLatencyStats(){const body=$('latencyStats');"
        "body.replaceChildren();completedStages().forEach(s=>{const tr=document."
        "createElement('tr');[s.index+' · '+s.source+' → '+s.target,"
        "Math.min(s.queue.length,s.work.length),distribution(s.queue),"
        "distribution(s.work),latencyObservation(s)].forEach(v=>{const td=document."
        "createElement('td');td.textContent=v;tr.appendChild(td)});body.appendChild("
        "tr)});if(!body.children.length)body.innerHTML='<tr><td colspan=\"5\">No "
        "completed chains.</td></tr>'};"
        "const waitText=h=>h.wait?'futex '+h.wait.address+' · '+"
        "exact(h.wait.duration_ns):'—';"
        "const wakerText=h=>h.wait&&h.wait.waker_tid?"
        "h.wait.waker_pid+'/'+h.wait.waker_tid+' '+h.wait.waker_comm:'—';"
        "function segment(track,p,left,total){if(!p.v)return;const d=document."
        "createElement('div');d.className='segment '+p.c;d.style.left=(left/"
        "total*100)+'%';d.style.width=(p.v/total*100)+'%';d.title=p.n+': '+"
        "ns(p.v);track.appendChild(d)}"
        "function rowLabel(h){const d=document.createElement('div');d.className="
        "'label';const strong=document.createElement('strong');strong.textContent="
        "='hop '+h.index+' · '+sourceLabel(h)+' → '+h.target+(h.target_arg?' arg'+h.target_arg:'');"
        "strong.title=strong.textContent;"
        "const span=document."
        "createElement('span');span.textContent='TID '+h.tid+' → '+h.target_tid;"
        "d.append(strong,span);return d}"
        "const SVG='http://www.w3.org/2000/svg';"
        "function svgNode(name,attrs){const node=document.createElementNS(SVG,name);"
        "Object.entries(attrs||{}).forEach(([key,value])=>node.setAttribute(key,value));"
        "return node}"
        "function svgText(parent,x,y,value,className,anchor){const node=svgNode('text',"
        "{x,y,class:className||'', 'text-anchor':anchor||'start'});"
        "node.textContent=value;node.setAttribute('aria-label',value);svgTitle(node,value);"
        "parent.appendChild(node);return node}"
        "function svgLines(parent,x,y,lines,className,anchor){const node=svgNode('text',"
        "{x,y,class:className||'','text-anchor':anchor||'start'});lines.forEach((value,index)=>{"
        "const span=svgNode('tspan',{x,dy:index?'14':'0'});span.textContent=value;"
        "node.appendChild(span)});svgTitle(node,lines.join(' · '));parent.appendChild(node);return node}"
        "function svgTitle(parent,value){const title=svgNode('title');title.textContent=value;"
        "parent.appendChild(title)}"
        "function threadName(c,tid){const hop=c.hops.find(h=>h.tid===tid&&h.comm);"
        "if(hop)return hop.comm;if(c.tid===tid&&c.comm)return c.comm;return'worker'}"
        "function threadRole(c,tid){const target=c.hops.find(h=>h.target_tid===tid&&h.target);"
        "if(target)return target.target;const source=c.hops.find(h=>h.tid===tid&&h.source);"
        "return source?sourceLabel(source):threadName(c,tid)}"
        "const shortText=(value,limit)=>value.length>limit?value.slice(0,limit-1)+'…':value;"
        "function compressedTimeScale(phases,total,top,plotHeight){"
        "const weights=phases.map(value=>value?Math.max(.1,Math.pow(value/total,.55)):0),"
        "weightTotal=Math.max(1e-9,weights.reduce((a,b)=>a+b,0));return value=>{"
        "let actual=0,visual=0;for(let p=0;p<phases.length;p++){const duration=phases[p],"
        "weight=weights[p];if(duration&&value<=actual+duration)return top+plotHeight*"
        "(visual+(value-actual)/duration*weight)/weightTotal;actual+=duration;visual+=weight}"
        "return top+plotHeight}}"
        "function chainDescription(c,i){const last=c.hops[c.hops.length-1],date=new Date(c.timestamp_ms);"
        "return'#'+(i+1)+(c.name?' · '+c.name:'')+' · '+date.toLocaleString()+'.'+String(date.getMilliseconds()).padStart(3,'0')+"
        "' · PID '+c.pid+'/TID '+c.tid+(last&&last.key!=='0x0000000000000000'?' · key '+last.key:'')+"
        "(c.truncated?' · '+c.truncated+' earlier hop(s) truncated':'')}"
        "function renderIoUringSequence(c){const root=$('sequence');root.replaceChildren();"
        "if(!c.hops.length){root.innerHTML='<div class=\"empty\">No request phases were captured.</div>';return}"
        "const request=c.hops[0],callback=c.hops.length>1?c.hops[1]:null,total=Math.max(1,sum(c)),"
        "width=1180,height=500,left=105,top=100,bottom=52,plotHeight=height-top-bottom,"
        "submitX=callback?220:330,kernelX=callback?590:850,callbackX=960,"
        "phases=[request.queue_ns,request.work_ns,"
        "callback?callback.queue_ns:0],timeY=compressedTimeScale(phases,total,top,plotHeight),"
        "queueY=timeY(request.queue_ns),cqeY=timeY(request.queue_ns+request.work_ns),finalY=timeY(total);"
        "const svg=svgNode('svg',{class:'sequence-chart',viewBox:'0 0 '+width+' '+height,"
        "role:'img','aria-labelledby':'sequence-title sequence-desc'}),"
        "title=svgNode('title',{id:'sequence-title'}),desc=svgNode('desc',{id:'sequence-desc'});"
        "title.textContent='io_uring request lifecycle';desc.textContent='The SQE enters the kernel,"
        " remains in flight until a CQE is produced, and optionally reaches an application callback.';"
        "svg.append(title,desc);const defs=svgNode('defs');"
        "function arrow(id,color){const marker=svgNode('marker',{id,viewBox:'0 0 10 10',refX:'8',"
        "refY:'5',markerWidth:'6',markerHeight:'6',orient:'auto-start-reverse'});"
        "marker.appendChild(svgNode('path',{d:'M 0 0 L 10 5 L 0 10 z',fill:color}));"
        "defs.appendChild(marker)}arrow('sequence-neutral-arrow','#64748b');"
        "arrow('sequence-io-queue-arrow','#8b5cf6');svg.appendChild(defs);"
        "svg.appendChild(svgNode('line',{x1:left-16,y1:top,x2:left-16,y2:height-bottom,class:'seq-axis'}));"
        "[0,.25,.5,.75,1].forEach(part=>{const y=timeY(total*part);svg.appendChild(svgNode('line',"
        "{x1:left-21,y1:y,x2:left-11,y2:y,class:'seq-axis'}));"
        "svgText(svg,left-28,y+4,ns(total*part),'seq-tick','end')});"
        "function lane(x,titleText,subText,boxWidth){const group=svgNode('g'),laneWidth=boxWidth||180;"
        "group.appendChild(svgNode('rect',{x:x-laneWidth/2,y:15,width:laneWidth,height:48,rx:8,class:'seq-thread'}));"
        "svgText(group,x,36,shortText(titleText,laneWidth>=340?52:laneWidth>180?32:22),'seq-thread-name','middle');"
        "svgText(group,x,53,shortText(subText,25),'seq-thread-id','middle');"
        "group.appendChild(svgNode('line',{x1:x,y1:70,x2:x,y2:height-bottom+8,class:'seq-life'}));"
        "svg.appendChild(group)}lane(submitX,request.source,'submitter · TID '+request.tid);"
        "lane(kernelX,'io_uring kernel','request lifecycle');"
        "if(callback)lane(callbackX,callback.target,'callback · TID '+callback.target_tid,360);"
        "const submitPath=svgNode('path',{class:'seq-submit','marker-end':'url(#sequence-neutral-arrow)',"
        "d:'M '+submitX+' '+top+' H '+kernelX});svgTitle(submitPath,request.source+' submitted');"
        "svg.appendChild(submitPath);svg.appendChild(svgNode('circle',{cx:submitX,cy:top,r:4,class:'seq-dot'}));"
        "svg.appendChild(svgNode('circle',{cx:kernelX,cy:top,r:4,class:'seq-dot'}));"
        "svgText(svg,(submitX+kernelX)/2,top-9,'SQE submitted','seq-sub','middle');"
        "if(request.queue_ns){svg.appendChild(svgNode('rect',{x:kernelX-5,y:top,width:10,"
        "height:Math.max(3,queueY-top),rx:5,class:'seq-queue-band'}));"
        "svg.appendChild(svgNode('line',{x1:kernelX,y1:top,x2:kernelX,y2:queueY,class:'seq-queue'}));"
        "svgText(svg,kernelX+18,(top+queueY)/2+4,'defer/io-wq queue · '+exact(request.queue_ns),"
        "'seq-queue-label','start')}"
        "const inFlightHeight=cqeY-queueY,compactInFlight=request.work_ns&&inFlightHeight<44;"
        "if(request.work_ns){const inFlight=svgNode('rect',{x:kernelX-8,y:queueY,width:16,"
        "height:Math.max(3,cqeY-queueY),rx:3,class:'seq-work'});"
        "svgTitle(inFlight,'kernel in-flight: '+exact(request.work_ns));svg.appendChild(inFlight);"
        "if(!compactInFlight)svgText(svg,kernelX+20,(queueY+cqeY)/2+4,"
        "'kernel in-flight · '+exact(request.work_ns),'seq-label','start')}"
        "svg.appendChild(svgNode('circle',{cx:kernelX,cy:cqeY,r:5,class:'seq-dot'}));"
        "const cqeLabel=compactInFlight?request.target+' · in-flight '+exact(request.work_ns):"
        "request.target;svgText(svg,compactInFlight?kernelX-18:kernelX+18,"
        "compactInFlight?cqeY+4:cqeY-9,cqeLabel,'seq-label',"
        "compactInFlight?'end':'start');"
        "if(callback){const delay=callback.queue_ns,path=svgNode('path',{class:delay?'seq-queue':'seq-submit',"
        "'marker-end':delay?'url(#sequence-io-queue-arrow)':'url(#sequence-neutral-arrow)'}),"
        "elbowX=kernelX+62,corner=Math.min(8,Math.max(0,(finalY-cqeY)/2));"
        "if(delay&&corner>=2)path.setAttribute('d','M '+kernelX+' '+cqeY+' H '+(elbowX-corner)+"
        "' Q '+elbowX+' '+cqeY+' '+elbowX+' '+(cqeY+corner)+' V '+(finalY-corner)+"
        "' Q '+elbowX+' '+finalY+' '+(elbowX+corner)+' '+finalY+' H '+callbackX);"
        "else path.setAttribute('d','M '+kernelX+' '+cqeY+' H '+callbackX);"
        "svgTitle(path,delay?'CQE ready to callback entry: '+exact(delay):"
        "'CQE reached the callback without a measurable delay');svg.appendChild(path);"
        "if(delay){svg.appendChild(svgNode('rect',{x:elbowX-5,y:cqeY,width:10,"
        "height:Math.max(3,finalY-cqeY),rx:5,class:'seq-queue-band'}));"
        "svgText(svg,elbowX+14,(cqeY+finalY)/2+4,'CQE-to-callback wait · '+exact(delay),"
        "'seq-queue-label','start')}else svgText(svg,(kernelX+callbackX)/2,cqeY-9,"
        "'callback immediately','seq-sub','middle');"
        "svg.appendChild(svgNode('circle',{cx:callbackX,cy:finalY,r:5,class:'seq-dot'}))}"
        "const finalX=callback?callbackX:kernelX;svg.appendChild(svgNode('circle',"
        "{cx:finalX,cy:finalY,r:6,class:'seq-dot'}));svgText(svg,finalX,"
        "Math.min(height-12,finalY+23),'request complete · '+exact(total),'seq-label','middle');"
        "root.appendChild(svg)}"
        "function renderEventLoopSequence(c){const root=$('sequence');root.replaceChildren();"
        "if(!c.hops.length){root.innerHTML='<div class=\"empty\">No event phases were captured.</div>';return}"
        "const first=c.hops[0],singleOperation=c.hops.length===1&&first.source==='ready event',"
        "operation=c.hops.length>1?c.hops[c.hops.length-1]:(singleOperation?first:null),"
        "precursor=operation===first?null:first,waitPhase=precursor&&/^epoll_(wait|pwait|pwait2)$/.test(precursor.source),"
        "loopTid=operation?operation.tid:(precursor?precursor.target_tid:first.tid),"
        "crossThread=!!(precursor&&precursor.tid&&precursor.tid!==loopTid),"
        "initialDelay=precursor?precursor.queue_ns:0,dispatchDelay=operation?operation.queue_ns:0,"
        "execution=operation?operation.work_ns:0,total=Math.max(1,sum(c)),"
        "width=1180,height=500,left=105,top=100,bottom=52,plotHeight=height-top-bottom,"
        "sourceX=280,loopX=crossThread?850:590,phases=[initialDelay,dispatchDelay,execution],"
        "timeY=compressedTimeScale(phases,total,top,plotHeight),readyY=timeY(initialDelay),"
        "actionY=timeY(initialDelay+dispatchDelay),finalY=timeY(total),"
        "runtime=reportMode==='libuv'?'libuv':reportMode==='libevent'?'libevent':'epoll',"
        "callbackName=operation?operation.target:(precursor?precursor.target:'event dispatch'),"
        "pollName=waitPhase?precursor.source:'epoll_wait*',"
        "readyName=precursor&&precursor.target?precursor.target:'ready event';"
        "const svg=svgNode('svg',{class:'sequence-chart',viewBox:'0 0 '+width+' '+height,"
        "role:'img','aria-labelledby':'sequence-title sequence-desc'}),title=svgNode('title',"
        "{id:'sequence-title'}),desc=svgNode('desc',{id:'sequence-desc'});"
        "title.textContent=runtime+' event lifecycle';desc.textContent='Only observed threads receive lanes. Waiting, dispatch, and callback or I/O execution are vertical phases on the event-loop thread.';"
        "svg.append(title,desc);const defs=svgNode('defs');"
        "function arrow(id,color){const marker=svgNode('marker',{id,viewBox:'0 0 10 10',refX:'8',"
        "refY:'5',markerWidth:'6',markerHeight:'6',orient:'auto-start-reverse'});"
        "marker.appendChild(svgNode('path',{d:'M 0 0 L 10 5 L 0 10 z',fill:color}));"
        "defs.appendChild(marker)}arrow('event-neutral-arrow','#64748b');"
        "arrow('event-delay-arrow','#8b5cf6');svg.appendChild(defs);"
        "svg.appendChild(svgNode('line',{x1:left-16,y1:top,x2:left-16,y2:height-bottom,class:'seq-axis'}));"
        "[0,.25,.5,.75,1].forEach(part=>{const y=timeY(total*part);svg.appendChild(svgNode('line',"
        "{x1:left-21,y1:y,x2:left-11,y2:y,class:'seq-axis'}));"
        "svgText(svg,left-28,y+4,ns(total*part),'seq-tick','end')});"
        "function lane(x,titleText,subText,boxWidth){const group=svgNode('g'),laneWidth=boxWidth||300;"
        "group.appendChild(svgNode('rect',{x:x-laneWidth/2,y:15,width:laneWidth,height:48,rx:8,class:'seq-thread'}));"
        "svgText(group,x,36,shortText(titleText,laneWidth>=480?72:laneWidth>300?50:38),'seq-thread-name','middle');"
        "svgText(group,x,53,shortText(subText,laneWidth>=480?64:laneWidth>300?46:36),'seq-thread-id','middle');"
        "group.appendChild(svgNode('line',{x1:x,y1:70,x2:x,y2:height-bottom+8,class:'seq-life'}));"
        "svg.appendChild(group)}"
        "if(crossThread)lane(sourceX,precursor.source,threadName(c,precursor.tid)+' · TID '+precursor.tid,320);"
        "lane(loopX,callbackName,runtime+' event loop · TID '+loopTid,500);"
        "if(crossThread){svg.appendChild(svgNode('circle',{cx:sourceX,cy:top,r:4,class:'seq-dot'}));"
        "const wakePath=svgNode('path',{class:'seq-queue','marker-end':'url(#event-delay-arrow)',"
        "d:'M '+sourceX+' '+top+' H '+(sourceX+64)+' V '+readyY+' H '+loopX});"
        "svgTitle(wakePath,'cross-thread wake-to-ready: '+exact(initialDelay));svg.appendChild(wakePath);"
        "svgText(svg,(sourceX+loopX)/2,top-10,precursor.source+' → '+readyName+' · '+"
        "exact(initialDelay),'seq-queue-label','middle')}"
        "else{svg.appendChild(svgNode('circle',{cx:loopX,cy:top,r:4,class:'seq-dot'}));"
        "if(initialDelay){const wait=svgNode('rect',{x:loopX-8,y:top,width:16,"
        "height:Math.max(3,readyY-top),rx:3,class:waitPhase?'seq-wait':'seq-queue-band'});"
        "svgTitle(wait,(waitPhase?'waiting in ':'waiting before ')+pollName+': '+exact(initialDelay));"
        "svg.appendChild(wait);svgText(svg,loopX+20,(top+readyY)/2+4,pollName+' · '+"
        "exact(initialDelay),'seq-label','start')}}"
        "svg.appendChild(svgNode('circle',{cx:loopX,cy:readyY,r:5,class:'seq-dot'}));"
        "if(operation){if(dispatchDelay){const dispatch=svgNode('rect',{x:loopX-7,y:readyY,width:14,"
        "height:Math.max(3,actionY-readyY),rx:4,class:'seq-dispatch-band'});"
        "svgTitle(dispatch,'FD ready to callback entry: '+exact(dispatchDelay));svg.appendChild(dispatch);"
        "const dispatchAnchor='end',dispatchX=loopX-20;"
        "svgLines(svg,dispatchX,(readyY+actionY)/2-3,["
        "readyName+' → '+callbackName,'pre-callback dispatch · '+exact(dispatchDelay)],"
        "'seq-queue-label',dispatchAnchor)}"
        "svg.appendChild(svgNode('circle',{cx:loopX,cy:actionY,r:5,class:'seq-dot'}));"
        "if(execution){const work=svgNode('rect',{x:loopX-8,y:actionY,width:16,"
        "height:Math.max(3,finalY-actionY),rx:3,class:'seq-work'});"
        "svgTitle(work,(operation.work_kind===2?'I/O execution: ':'callback execution: ')+exact(execution));"
        "svg.appendChild(work);const workAnchor='start',workX=loopX+20;svgLines(svg,workX,"
        "(actionY+finalY)/2-3,[callbackName,(operation.work_kind===2?'I/O execution':'callback execution')+"
        "' · '+exact(execution)],'seq-label',workAnchor)}}"
        "svg.appendChild(svgNode('circle',{cx:loopX,cy:finalY,r:6,class:'seq-dot'}));"
        "svgText(svg,loopX,Math.min(height-12,finalY+23),'event complete · '+exact(total),"
        "'seq-label','middle');root.appendChild(svg)}"
        "function isLibuvWorkChain(c){return c.hops.length===2&&c.hops.some(h=>"
        "h.handoff_kind===1&&(h.handoff_flags&1)&&h.source_exit)}"
        "function renderLibuvWorkSequence(c){const root=$('sequence');root.replaceChildren();"
        "const submit=c.hops[0],handoff=c.hops[1],total=Math.max(1,sum(c)),"
        "width=1180,height=610,left=105,top=100,bottom=54,plotHeight=height-top-bottom,"
        "loopX=300,workerX=870,phases=[submit.queue_ns,submit.work_ns,"
        "handoff.publish_ns,handoff.notify_ns,handoff.loop_ns,handoff.poll_ns,"
        "handoff.dispatch_ns,handoff.work_ns],timeY=compressedTimeScale(phases,total,top,plotHeight),"
        "workerStartY=timeY(submit.queue_ns),workDoneY=timeY(submit.queue_ns+submit.work_ns),"
        "publishEndY=timeY(submit.queue_ns+submit.work_ns+handoff.publish_ns),"
        "notifyEndY=timeY(submit.queue_ns+submit.work_ns+handoff.publish_ns+handoff.notify_ns),"
        "loopEndY=timeY(submit.queue_ns+submit.work_ns+handoff.publish_ns+handoff.notify_ns+handoff.loop_ns),"
        "pollEndY=timeY(submit.queue_ns+submit.work_ns+handoff.publish_ns+handoff.notify_ns+handoff.loop_ns+handoff.poll_ns),"
        "dispatchEndY=timeY(total-handoff.work_ns),finalY=timeY(total);"
        "const svg=svgNode('svg',{class:'sequence-chart',viewBox:'0 0 '+width+' '+height,"
        "role:'img','aria-labelledby':'sequence-title sequence-desc'}),title=svgNode('title',"
        "{id:'sequence-title'}),desc=svgNode('desc',{id:'sequence-desc'});"
        "title.textContent='libuv work lifecycle';desc.textContent='Two real thread lanes show the event loop and worker. Completion publishing and notification stay on the worker lane; backlog, polling, dispatch, and the after-work callback stay on the event-loop lane.';"
        "svg.append(title,desc);const defs=svgNode('defs');"
        "function arrow(id,color){const marker=svgNode('marker',{id,viewBox:'0 0 10 10',refX:'8',"
        "refY:'5',markerWidth:'6',markerHeight:'6',orient:'auto-start-reverse'});"
        "marker.appendChild(svgNode('path',{d:'M 0 0 L 10 5 L 0 10 z',fill:color}));"
        "defs.appendChild(marker)}arrow('libuv-neutral-arrow','#64748b');"
        "arrow('libuv-delay-arrow','#8b5cf6');svg.appendChild(defs);"
        "svg.appendChild(svgNode('line',{x1:left-16,y1:top,x2:left-16,y2:height-bottom,class:'seq-axis'}));"
        "[0,.25,.5,.75,1].forEach(part=>{const y=timeY(total*part);svg.appendChild(svgNode('line',"
        "{x1:left-21,y1:y,x2:left-11,y2:y,class:'seq-axis'}));"
        "svgText(svg,left-28,y+4,ns(total*part),'seq-tick','end')});"
        "function lane(x,titleText,subText,boxWidth){const group=svgNode('g'),laneWidth=boxWidth||260;"
        "group.appendChild(svgNode('rect',{x:x-laneWidth/2,y:15,width:laneWidth,height:48,rx:8,class:'seq-thread'}));"
        "svgText(group,x,36,shortText(titleText,30),'seq-thread-name','middle');"
        "svgText(group,x,53,shortText(subText,laneWidth>280?42:32),'seq-thread-id','middle');"
        "group.appendChild(svgNode('line',{x1:x,y1:70,x2:x,y2:height-bottom+8,class:'seq-life'}));"
        "svg.appendChild(group)}"
        "lane(loopX,'libuv event loop',submit.source+' → '+handoff.target+' · TID '+submit.tid,330);"
        "lane(workerX,'libuv worker',handoff.source+' · TID '+handoff.tid,260);"
        "function phaseBand(x,y1,y2,className,label,value,labelSide,detail){if(!value)return;"
        "const band=svgNode('rect',{x:x-7,y:y1,width:14,height:Math.max(3,y2-y1),rx:4,"
        "class:'seq-'+className+'-band'});svgTitle(band,(detail||label)+': '+exact(value));svg.appendChild(band);"
        "svgText(svg,x+(labelSide==='left'?-18:18),(y1+y2)/2+4,label+' · '+exact(value),"
        "'seq-label',labelSide==='left'?'end':'start')}"
        "const submitPath=svgNode('path',{class:'seq-queue','marker-end':'url(#libuv-delay-arrow)',"
        "d:'M '+loopX+' '+top+' H '+(loopX+70)+' V '+workerStartY+' H '+workerX});"
        "svgTitle(submitPath,submit.source+' queued for '+submit.target+': '+exact(submit.queue_ns));"
        "svg.appendChild(submitPath);svg.appendChild(svgNode('circle',{cx:loopX,cy:top,r:4,class:'seq-dot'}));"
        "svg.appendChild(svgNode('circle',{cx:workerX,cy:workerStartY,r:4,class:'seq-dot'}));"
        "svgText(svg,(loopX+workerX)/2,top-10,submit.source+' → '+submit.target+"
        "' · '+exact(submit.queue_ns),'seq-queue-label','middle');"
        "if(submit.work_ns){const work=svgNode('rect',{x:workerX-8,y:workerStartY,width:16,"
        "height:Math.max(3,workDoneY-workerStartY),rx:3,class:'seq-work'});"
        "svgTitle(work,submit.target+' execution: '+exact(submit.work_ns));svg.appendChild(work);"
        "svgText(svg,workerX-20,(workerStartY+workDoneY)/2+4,submit.target+' · '+"
        "exact(submit.work_ns),'seq-label','end')}"
        "svg.appendChild(svgNode('circle',{cx:workerX,cy:workDoneY,r:5,class:'seq-dot'}));"
        "phaseBand(workerX,workDoneY,publishEndY,'publish',handoff.source+' → uv_async_send',"
        "handoff.publish_ns,'left','completion publish');"
        "phaseBand(workerX,publishEndY,notifyEndY,'notify','uv_async_send()',handoff.notify_ns,'left',"
        "'notification call');"
        "const notified=svgNode('path',{class:'seq-submit','marker-end':'url(#libuv-neutral-arrow)',"
        "d:'M '+workerX+' '+notifyEndY+' H '+loopX});svgTitle(notified,'completion notification reached the event-loop thread');"
        "svg.appendChild(notified);svgText(svg,(loopX+workerX)/2,notifyEndY-9,'completion notified',"
        "'seq-sub','middle');svg.appendChild(svgNode('circle',{cx:loopX,cy:notifyEndY,r:4,class:'seq-dot'}));"
        "phaseBand(loopX,notifyEndY,loopEndY,'loop','uv_async_send → epoll_wait*',handoff.loop_ns,'right',"
        "'event loop active / backlog');"
        "phaseBand(loopX,loopEndY,pollEndY,'poll','epoll_wait*()',handoff.poll_ns,'right',"
        "'epoll wait / wakeup');"
        "phaseBand(loopX,pollEndY,dispatchEndY,'dispatch','epoll_wait* → '+handoff.target,"
        "handoff.dispatch_ns,'right','ready-to-callback dispatch');"
        "if(handoff.work_ns){const afterWork=svgNode('rect',{x:loopX-8,y:dispatchEndY,width:16,"
        "height:Math.max(3,finalY-dispatchEndY),rx:3,class:'seq-work'});"
        "svgTitle(afterWork,handoff.target+' execution: '+exact(handoff.work_ns));svg.appendChild(afterWork);"
        "svgText(svg,loopX+20,(dispatchEndY+finalY)/2+4,handoff.target+' · '+"
        "exact(handoff.work_ns),'seq-label','start')}"
        "svg.appendChild(svgNode('circle',{cx:loopX,cy:finalY,r:6,class:'seq-dot'}));"
        "svgText(svg,loopX,Math.min(height-12,finalY+23),'chain complete · '+exact(total),"
        "'seq-label','middle');root.appendChild(svg)}"
        "function renderSequence(c,i){const root=$('sequence');root.replaceChildren();"
        "if(reportMode==='io_uring'){renderIoUringSequence(c);return}"
        "if(['epoll','libuv','libevent'].includes(reportMode)){renderEventLoopSequence(c);return}"
        "if(isLibuvWorkChain(c)){renderLibuvWorkSequence(c);return}"
        "if(!c.hops.length){root.innerHTML='<div class=\"empty\">No hops in the selected chain.</div>';return}"
        "const lanes=[],seen=new Set();c.hops.forEach(h=>{[h.tid,h.target_tid].forEach(tid=>{"
        "if(tid&&!seen.has(tid)){seen.add(tid);lanes.push(tid)}})});"
        "const total=Math.max(1,sum(c)),width=Math.max(1180,240+lanes.length*230),"
        "height=Math.max(480,190+c.hops.length*100),left=115,right=115,top=92,bottom=48,"
        "plotHeight=height-top-bottom,laneWidth=width-left-right;"
        "const laneX=tid=>{const index=lanes.indexOf(tid);return lanes.length===1?"
        "left+laneWidth/2:left+index*laneWidth/(lanes.length-1)};"
        "const phases=[];c.hops.forEach(h=>{handoffParts(h).forEach(p=>phases.push(p.v));"
        "phases.push(h.work_ns)});"
        "const timeY=compressedTimeScale(phases,total,top,plotHeight);"
        "const svg=svgNode('svg',{class:'sequence-chart',viewBox:'0 0 '+width+' '+height,"
        "role:'img','aria-labelledby':'sequence-title sequence-desc'});"
        "const title=svgNode('title',{id:'sequence-title'});title.textContent='Cross-thread asynchronous sequence';"
        "const desc=svgNode('desc',{id:'sequence-desc'});desc.textContent='Time flows from top to bottom with compressed phase spacing. Queue arrows connect source and target threads, and blue bars show target execution.';"
        "svg.append(title,desc);const defs=svgNode('defs');const marker=svgNode('marker',"
        "{id:'sequence-arrow',viewBox:'0 0 10 10',refX:'8',refY:'5',markerWidth:'6',"
        "markerHeight:'6',orient:'auto-start-reverse'});marker.appendChild(svgNode('path',"
        "{d:'M 0 0 L 10 5 L 0 10 z',fill:'#8b5cf6'}));defs.appendChild(marker);svg.appendChild(defs);"
        "svg.appendChild(svgNode('line',{x1:left-16,y1:top,x2:left-16,y2:height-bottom,class:'seq-axis'}));"
        "[0,.25,.5,.75,1].forEach(part=>{const y=timeY(total*part);svg.appendChild(svgNode('line',"
        "{x1:left-21,y1:y,x2:left-11,y2:y,class:'seq-axis'}));"
        "svgText(svg,left-28,y+4,ns(total*part),'seq-tick','end')});"
        "lanes.forEach(tid=>{const x=laneX(tid),group=svgNode('g'),comm=threadName(c,tid);"
        "group.appendChild(svgNode('rect',{x:x-90,y:15,width:180,height:48,rx:8,class:'seq-thread'}));"
        "svgText(group,x,36,shortText(threadRole(c,tid),22),'seq-thread-name','middle');"
        "svgText(group,x,53,'TID '+tid+(comm&&comm!=='worker'?' · '+shortText(comm,13):''),"
        "'seq-thread-id','middle');group.appendChild(svgNode('line',"
        "{x1:x,y1:70,x2:x,y2:height-bottom+8,class:'seq-life'}));svg.appendChild(group)});"
        "let elapsed=0;c.hops.forEach(h=>{const queueEnd=elapsed+h.queue_ns,workEnd=queueEnd+h.work_ns,"
        "sourceX=laneX(h.tid),targetX=laneX(h.target_tid),sourceY=timeY(elapsed),"
        "queueY=timeY(queueEnd),workY=timeY(workEnd),group=svgNode('g');"
        "const path=svgNode('path',{class:'seq-queue','marker-end':'url(#sequence-arrow)'}),"
        "sameLane=sourceX===targetX,direction=sameLane?(sourceX>width/2?-1:1):(targetX>sourceX?1:-1),"
        "distance=Math.abs(targetX-sourceX),"
        "elbowX=sameLane?sourceX+direction*58:"
        "sourceX+direction*Math.min(64,Math.max(34,distance*.24)),"
        "corner=Math.min(8,Math.max(0,(queueY-sourceY)/2),Math.abs(targetX-elbowX)/2);"
        "if(corner>=2)path.setAttribute('d','M '+sourceX+' '+sourceY+' H '+"
        "(elbowX-direction*corner)+' Q '+elbowX+' '+sourceY+' '+elbowX+' '+"
        "(sourceY+corner)+' V '+(queueY-corner)+' Q '+elbowX+' '+queueY+' '+"
        "(elbowX+direction*corner)+' '+queueY+' H '+targetX);"
        "else path.setAttribute('d','M '+sourceX+' '+sourceY+' H '+elbowX+' V '+queueY+' H '+targetX);"
        "svgTitle(path,'hop '+h.index+' queue: '+exact(h.queue_ns)+' · '+handoffText(h)+' · '+sourceLabel(h)+' → '+h.target);"
        "if(h.queue_ns&&h.handoff_kind===1){let phaseStart=elapsed;handoffParts(h).forEach(p=>{"
        "const phaseEnd=phaseStart+p.v,phaseY=timeY(phaseStart),phaseEndY=timeY(phaseEnd);"
        "if(p.v)group.appendChild(svgNode('rect',{x:elbowX-5,y:phaseY,width:10,"
        "height:Math.max(3,phaseEndY-phaseY),rx:5,class:'seq-'+p.c+'-band'}));"
        "phaseStart=phaseEnd})}else if(h.queue_ns)group.appendChild(svgNode('rect',{x:elbowX-5,y:sourceY,width:10,"
        "height:Math.max(3,queueY-sourceY),rx:5,class:'seq-queue-band'}));"
        "group.appendChild(path);group.appendChild(svgNode('circle',{cx:sourceX,cy:sourceY,r:4,class:'seq-dot'}));"
        "const queueLabelX=elbowX+direction*13,queueLabelY=(sourceY+queueY)/2+4,"
        "queueAnchor=direction>0?'start':'end';svgText(group,queueLabelX,queueLabelY,"
        "'H'+h.index+' · '+(h.handoff_kind===1?'libuv handoff ':'queued ')+exact(h.queue_ns),'seq-queue-label',queueAnchor);"
        "group.appendChild(svgNode('circle',{cx:targetX,cy:queueY,r:4,class:'seq-dot'}));"
        "if(h.work_ns){const visualHeight=Math.max(3,workY-queueY),activation=svgNode('rect',"
        "{x:targetX-7,y:queueY,width:14,height:visualHeight,rx:3,class:'seq-work'});"
        "svgTitle(activation,h.target+' '+workName(h)+': '+exact(h.work_ns)+"
        "(h.work_kind?'':' · on-CPU '+exact(Math.max(0,h.work_ns-h.offcpu_ns))+"
        "' · blocked '+exact(h.blocked_ns)+' · run queue '+exact(h.runqueue_ns)));"
        "group.appendChild(activation);"
        "const placeLeft=targetX>width-230,labelX=targetX+(placeLeft?-18:18),"
        "labelY=(queueY+workY)/2+4;svgText(group,labelX,labelY,"
        "shortText(h.target,18)+' · '+workName(h)+' '+exact(h.work_ns),"
        "'seq-label',placeLeft?'end':'start')}"
        "svg.appendChild(group);elapsed=workEnd});"
        "const finalHop=c.hops[c.hops.length-1],finalX=laneX(finalHop.target_tid),finalY=timeY(elapsed);"
        "svg.appendChild(svgNode('circle',{cx:finalX,cy:finalY,r:6,class:'seq-dot'}));"
        "svgText(svg,finalX,Math.min(height-12,finalY+22),'chain complete · '+exact(total),"
        "'seq-label','middle');root.appendChild(svg)}"
        "function setView(tab){document.querySelectorAll('[role=tab]').forEach(button=>{"
        "const active=button===tab;button.setAttribute('aria-selected',active);"
        "button.tabIndex=active?0:-1;$(button.getAttribute('aria-controls')).hidden=!active})}"
        "function initTabs(){const tabs=[...document.querySelectorAll('[role=tab]')];"
        "tabs.forEach((tab,index)=>{tab.onclick=()=>setView(tab);tab.onkeydown=event=>{"
        "if(!['ArrowLeft','ArrowRight','Home','End'].includes(event.key))return;event.preventDefault();"
        "let next=event.key==='Home'?0:event.key==='End'?tabs.length-1:"
        "(index+(event.key==='ArrowRight'?1:-1)+tabs.length)%tabs.length;"
        "setView(tabs[next]);tabs[next].focus()}})}"
        "function render(i){const c=chains[i],total=Math.max(1,sum(c));"
        "const selectedQueue=c.hops.reduce((n,h)=>n+h.queue_ns,0);"
        "const selectedWork=c.hops.reduce((n,h)=>n+h.work_ns,0);"
        "const last=c.hops[c.hops.length-1];$('selected').textContent=exact(total);"
        "$('selectedQueue').textContent=exact(selectedQueue);"
        "$('selectedWork').textContent=exact(selectedWork);"
        "$('chainTotal').textContent=exact(total);$('sequenceTotal').textContent=exact(total);"
        "$('chainMeta').textContent=chainDescription(c,i);"
        "$('sequenceMeta').textContent=chainDescription(c,i);"
        "if(reportMode==='async'){if(isLibuvWorkChain(c)){"
        "$('selectedQueueLabel').textContent='Selected handoff';"
        "$('selectedWorkLabel').textContent='Selected execution';"
        "$('sequenceTitle').textContent='libuv work lifecycle';"
        "$('sequenceNote').textContent='Time flows downward across two real thread lanes. Visible phase labels use observed function boundaries; hover a segment or open Details for its runtime meaning.'}"
        "else{$('selectedQueueLabel').textContent='Selected queue';"
        "$('selectedWorkLabel').textContent='Selected work';"
        "$('sequenceTitle').textContent='Cross-thread sequence';"
        "$('sequenceNote').innerHTML='Vertical order follows elapsed time; spacing is compressed so short phases remain readable. <span class=\"sequence-queue-key\">Queue wait</span> connectors show handoff delay; blue activations show target work. Scheduler-state breakdown remains an aggregate and is shown in Waterfall.'}}"
        "renderSequence(c,i);"
        "$('axis').replaceChildren(...[0,.25,.5,.75,1].map(v=>{const s=document."
        "createElement('span');s.textContent=ns(total*v);return s}));"
        "const timeline=$('timeline');timeline.replaceChildren();let start=0;"
        "c.hops.forEach(h=>{const row=document.createElement('div');row.className="
        "'row';row.appendChild(rowLabel(h));const track=document.createElement("
        "'div');track.className='track';const ps=parts(h);ps.forEach(p=>{segment("
        "track,p,start,total);start+=p.v});row.appendChild(track);timeline."
        "appendChild(row)});const maxHop=Math.max(1,...c.hops.map(h=>h.queue_ns+"
        "h.work_ns));const breakdown=$('breakdown');breakdown.replaceChildren();"
        "c.hops.forEach(h=>{const row=document.createElement('div');row.className="
        "'row';row.appendChild(rowLabel(h));const track=document.createElement("
        "'div');track.className='track';let x=0;parts(h).forEach(p=>{segment(track,"
        "p,x,maxHop);x+=p.v});row.appendChild(track);breakdown.appendChild(row)});"
        "const details=$('details');details.replaceChildren();c.hops.forEach(h=>{"
        "const tr=document.createElement('tr');[h.index,sourceLabel(h)+' → '+h.target,"
        "h.pid+'/'+h.tid+' → '+h.target_tid,h.key,exact(h.queue_ns),handoffText(h),"
        "exact(h.work_ns),dominant(h).n+' '+exact(dominant(h).v),waitText(h),"
        "wakerText(h)].forEach(v=>{"
        "const td=document."
        "createElement('td');td.textContent=v;tr.appendChild(td)});details."
        "appendChild(tr)})}"
        "function init(){const runtime=reportMode!=='async';if(runtime){document.title='callweave '+reportMode+' latency report';"
        "$('reportTitle').textContent='callweave '+reportMode.replaceAll('_',' ')+' latency report';"
        "$('reportSubtitle').textContent='Captured runtime operations shown as correlated queue, handoff, and execution phases.';"
        "$('selectLabel').textContent='Captured operation';$('countLabel').textContent='Captured operations';"
        "$('distributionTitle').textContent='Operation latency';$('distributionNote').textContent='Exact values calculated from captured runtime operations embedded in this report.';"
        "if(reportMode==='io_uring'){$('selectedQueueLabel').textContent='Selected delay';"
        "$('selectedWorkLabel').textContent='Selected in-flight';"
        "$('sequenceTitle').textContent='io_uring request lifecycle';"
        "$('sequenceNote').textContent='Blue is SQE-to-CQE kernel in-flight time. Violet is observed delay outside that phase: defer/io-wq before execution or CQE-ready to callback entry. A fast request can therefore wait behind slower completions before user space dispatches its callback.'}"
        "if(['epoll','libuv','libevent'].includes(reportMode)){const runtimeName=reportMode==='epoll'?'epoll':reportMode;"
        "$('reportSubtitle').textContent='Captured readiness, pre-callback dispatch, and callback or I/O execution phases.';"
        "$('selectedQueueLabel').textContent=reportMode==='libevent'?'Selected pre-callback':'Selected wait/delay';"
        "$('selectedWorkLabel').textContent='Selected execution';"
        "$('sequenceTitle').textContent=runtimeName+' event lifecycle';"
        "$('sequenceNote').textContent=reportMode==='libevent'?"
        "'Violet shows time before the callback: producer-to-ready latency plus ready-to-callback dispatch. Blue shows execution inside the named callback. Only observed threads receive lanes.':"
        "'Only observed threads receive lanes. epoll waiting, readiness-to-function dispatch, and callback or I/O execution are vertical phases on the event-loop thread; a producer lane appears only for a real cross-thread wake.'}"
        "$('asyncDiagnostics').hidden=true}initTabs();renderDiagnostics();renderLatencyStats();if(!chains.length){$('chain').innerHTML='<option>No "
        "captured operations</option>';['timeline','breakdown'].forEach(id=>"
        "$(id).innerHTML='<div class=\"empty\">No matching chain was captured."
        "</div>');$('sequence').innerHTML='<div class=\"empty\">No matching chain was captured.</div>';return}const totals=chains.map(sum).sort((a,b)=>a-b);"
        "$('count').textContent=chains.length;$('average').textContent=exact("
        "totals.reduce((a,b)=>a+b,0)/totals.length);$('p95').textContent="
        "totals.length>=20?exact(percentile(totals,.95)):'n/a (<20 samples)';"
        "$('maximum').textContent=exact(totals[totals.length-1]);"
        "const select=$('chain');"
        "chains.forEach((c,i)=>{const o=document.createElement('option');o.value=i;"
        "const last=c.hops[c.hops.length-1];o.textContent='#'+(i+1)+' · '+"
        "clock(c.timestamp_ms)+' · '+exact(sum(c))+' · '+c.hops.length+' hop(s)'+(c.name?' · '+c.name:'')+"
        "(last?' · key …'+last.key.slice(-6):'');select.appendChild(o)});"
        "let slow=0;chains.forEach((c,i)=>{if(sum(c)>sum(chains[slow]))slow=i});"
        "select.value=slow;select.onchange=()=>render(+select.value);render(slow)}"
        "init();</script></body></html>\n";

    size_t index;

    if (fputs("];\nconst diagnosticReport={\"type\":"
              "\"queue_diagnostics\",\"hops\":[", stream) == EOF)
        return -1;
    for (index = 0; index < count; index++) {
        if (index && fputc(',', stream) == EOF)
            return -1;
        if (write_queue_diagnostic(stream, &diagnostics[index]))
            return -1;
    }
    if (fputs("]}", stream) == EOF)
        return -1;
    return fputs(footer, stream) == EOF ? -1 : 0;
}
