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

    if (fprintf(stream,
                "{\"timestamp_ms\":%" PRIu64
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
                    ",\"pid\":%u,\"tid\":%u,\"target_tid\":%u,"
                    "\"target_arg\":%u,"
                    "\"comm\":",
                    hop->pid, hop->tid, hop->target_tid,
                    hop->target_arg) < 0 ||
            write_json_string(stream, hop->comm) ||
            fprintf(stream,
                    ",\"key\":\"0x%016" PRIx64
                    "\",\"queue_ns\":%" PRIu64
                    ",\"work_ns\":%" PRIu64
                    ",\"offcpu_ns\":%" PRIu64
                    ",\"blocked_ns\":%" PRIu64
                    ",\"runqueue_ns\":%" PRIu64 "}",
                    hop->key, hop->queue_ns, hop->work_ns,
                    hop->offcpu_ns, hop->blocked_ns,
                    hop->runqueue_ns) < 0)
            return -1;
    }
    return fputs("]}", stream) == EOF ? -1 : 0;
}

int cw_html_report_begin(FILE *stream)
{
    static const char header[] =
        "<!doctype html>\n"
        "<html lang=\"en\"><head><meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
        "<title>callweave async latency report</title>\n"
        "<style>\n"
        ":root{color-scheme:dark;--bg:#0b1020;--panel:#121a2d;--line:#27324a;"
        "--text:#e8edf7;--muted:#8f9bb3;--queue:#64748b;--cpu:#22c55e;"
        "--blocked:#ef4444;--runq:#f59e0b;--unknown:#3b82f6}\n"
        "*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle "
        "at top,#17213a 0,var(--bg) 42%);color:var(--text);font:14px/1.45 "
        "Inter,ui-sans-serif,system-ui,sans-serif}main{max-width:1380px;margin:auto;"
        "padding:32px}.eyebrow{color:#7dd3fc;text-transform:uppercase;"
        "letter-spacing:.16em;font-size:11px;font-weight:700}h1{margin:.25rem 0;"
        "font-size:30px}p{color:var(--muted)}.toolbar{display:flex;gap:16px;"
        "align-items:end;flex-wrap:wrap;margin:24px 0}.field{display:grid;gap:6px;"
        "min-width:320px}.field span{color:var(--muted);font-size:12px}select{"
        "background:#0d1528;color:var(--text);border:1px solid var(--line);"
        "border-radius:9px;padding:10px 12px}.cards{display:grid;"
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
        ".axis{margin-left:264px;display:flex;justify-content:space-between;"
        "color:var(--muted);font-size:11px}.empty{padding:36px;text-align:center;"
        "color:var(--muted)}table{width:100%;border-collapse:collapse}"
        "th,td{text-align:left;padding:10px;border-bottom:1px solid var(--line)}"
        "th{color:var(--muted);font-size:11px;text-transform:uppercase;"
        "letter-spacing:.08em}code{color:#bae6fd}footer{color:var(--muted);"
        "text-align:center;padding:12px}@media(max-width:800px){main{padding:18px}"
        ".cards{grid-template-columns:repeat(2,1fr)}.row{grid-template-columns:1fr}"
        ".axis{margin-left:0}.field{min-width:100%}}\n"
        "</style></head><body><main>\n"
        "<div class=\"eyebrow\">eBPF causal tracing</div>\n"
        "<h1>callweave async latency report</h1>\n"
        "<p>Queue and work latency across asynchronous thread handoffs. Work "
        "colors are aggregate scheduler-state attribution, not chronological "
        "sub-intervals.</p>\n"
        "<div class=\"toolbar\"><label class=\"field\"><span>Completed chain</span>"
        "<select id=\"chain\"></select></label><div class=\"legend\">"
        "<span><i class=\"dot queue\"></i>queue</span>"
        "<span><i class=\"dot cpu\"></i>on-CPU</span>"
        "<span><i class=\"dot blocked\"></i>blocked</span>"
        "<span><i class=\"dot runq\"></i>run queue</span>"
        "<span><i class=\"dot unknown\"></i>preempt / unknown</span>"
        "</div></div>\n"
        "<section class=\"cards\">"
        "<div class=\"card\"><span>Captured chains</span><strong id=\"count\">0</strong></div>"
        "<div class=\"card\"><span>Selected total</span><strong id=\"selected\">—</strong></div>"
        "<div class=\"card\"><span>Selected queue</span><strong id=\"selectedQueue\">—</strong></div>"
        "<div class=\"card\"><span>Selected work</span><strong id=\"selectedWork\">—</strong></div>"
        "<div class=\"card\"><span>Average latency</span><strong id=\"average\">—</strong></div>"
        "<div class=\"card\"><span>P95 latency</span><strong id=\"p95\">—</strong></div>"
        "<div class=\"card\"><span>Maximum latency</span><strong id=\"maximum\">—</strong></div>"
        "</section>\n"
        "<section class=\"panel\"><div class=\"panel-head\"><div><h2>Causal "
        "waterfall</h2><p id=\"chainMeta\"></p></div><strong id=\"chainTotal\">"
        "</strong></div><div id=\"axis\" class=\"axis\"></div><div id=\"timeline\" "
        "class=\"timeline\"></div></section>\n"
        "<section class=\"panel\"><div class=\"panel-head\"><div><h2>Per-hop "
        "latency composition</h2><p>Bars share one scale for direct comparison."
        "</p></div></div><div id=\"breakdown\" class=\"breakdown\"></div></section>\n"
        "<section class=\"panel\"><div class=\"panel-head\"><div><h2>Hop details"
        "</h2><p>Raw correlation and scheduler timing for the selected chain."
        "</p></div></div><div style=\"overflow:auto\"><table><thead><tr>"
        "<th>Hop</th><th>Source → target</th><th>Threads</th><th>Key</th>"
        "<th>Queue</th><th>Work</th><th>Dominant</th></tr></thead>"
        "<tbody id=\"details\"></tbody></table></div></section>\n"
        "<footer>Generated locally by callweave. No external scripts or network "
        "requests.</footer></main>\n"
        "<script>const chains=[";

    return fputs(header, stream) == EOF ? -1 : 0;
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

int cw_html_report_end(FILE *stream)
{
    static const char footer[] =
        "];\n"
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
        "const parts=h=>{const cpu=Math.max(0,h.work_ns-h.offcpu_ns);"
        "const unknown=Math.max(0,h.offcpu_ns-h.blocked_ns-h.runqueue_ns);"
        "return[{n:'queue',v:h.queue_ns,c:'queue'},{n:'on-CPU',v:cpu,c:'cpu'},"
        "{n:'blocked',v:h.blocked_ns,c:'blocked'},"
        "{n:'run queue',v:h.runqueue_ns,c:'runq'},"
        "{n:'preempt / unknown',v:unknown,c:'unknown'}]};"
        "const dominant=h=>parts(h).reduce((a,b)=>b.v>a.v?b:a,{n:'none',v:0});"
        "function segment(track,p,left,total){if(!p.v)return;const d=document."
        "createElement('div');d.className='segment '+p.c;d.style.left=(left/"
        "total*100)+'%';d.style.width=(p.v/total*100)+'%';d.title=p.n+': '+"
        "ns(p.v);track.appendChild(d)}"
        "function rowLabel(h){const d=document.createElement('div');d.className="
        "'label';const strong=document.createElement('strong');strong.textContent="
        "='hop '+h.index+' · '+h.source+' → '+h.target+' arg'+h.target_arg;"
        "const span=document."
        "createElement('span');span.textContent='TID '+h.tid+' → '+h.target_tid;"
        "d.append(strong,span);return d}"
        "function render(i){const c=chains[i],total=Math.max(1,sum(c));"
        "const selectedQueue=c.hops.reduce((n,h)=>n+h.queue_ns,0);"
        "const selectedWork=c.hops.reduce((n,h)=>n+h.work_ns,0);"
        "const last=c.hops[c.hops.length-1];$('selected').textContent=exact(total);"
        "$('selectedQueue').textContent=exact(selectedQueue);"
        "$('selectedWork').textContent=exact(selectedWork);"
        "$('chainTotal').textContent=exact(total);$('chainMeta').textContent="
        "'#'+(i+1)+' · '+new Date(c.timestamp_ms).toLocaleString()+'.'+"
        "String(new Date(c.timestamp_ms).getMilliseconds()).padStart(3,'0')+"
        "' · PID '+c.pid+'/TID '+c.tid+(last?' · key '+last.key:'')+"
        "(c.truncated?' · '+c.truncated+' earlier hop(s) truncated':'');"
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
        "const tr=document.createElement('tr');[h.index,h.source+' → '+h.target,"
        "h.pid+'/'+h.tid+' → '+h.target_tid,h.key,exact(h.queue_ns),"
        "exact(h.work_ns),dominant(h).n+' '+exact(dominant(h).v)].forEach(v=>{"
        "const td=document."
        "createElement('td');td.textContent=v;tr.appendChild(td)});details."
        "appendChild(tr)})}"
        "function init(){if(!chains.length){$('chain').innerHTML='<option>No "
        "completed async chains</option>';['timeline','breakdown'].forEach(id=>"
        "$(id).innerHTML='<div class=\"empty\">No matching chain was captured."
        "</div>');return}const totals=chains.map(sum).sort((a,b)=>a-b);"
        "$('count').textContent=chains.length;$('average').textContent=exact("
        "totals.reduce((a,b)=>a+b,0)/totals.length);$('p95').textContent=exact("
        "totals[Math.min(totals.length-1,Math.ceil(totals.length*.95)-1)]);"
        "$('maximum').textContent=exact(totals[totals.length-1]);"
        "const select=$('chain');"
        "chains.forEach((c,i)=>{const o=document.createElement('option');o.value=i;"
        "const last=c.hops[c.hops.length-1];o.textContent='#'+(i+1)+' · '+"
        "clock(c.timestamp_ms)+' · '+exact(sum(c))+' · '+c.hops.length+' hop(s)'+"
        "(last?' · key …'+last.key.slice(-6):'');select.appendChild(o)});"
        "let slow=0;chains.forEach((c,i)=>{if(sum(c)>sum(chains[slow]))slow=i});"
        "select.value=slow;select.onchange=()=>render(+select.value);render(slow)}"
        "init();</script></body></html>\n";

    return fputs(footer, stream) == EOF ? -1 : 0;
}
