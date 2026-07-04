// PhantomLog — Shared frontend utilities

const PL = {
  esc(s) { if(s==null) return ""; return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"); },

  async postJSON(url, body) {
    const r = await fetch(url, { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body||{}) });
    return r.json();
  },
  async postForm(url, formData) {
    const r = await fetch(url, { method:"POST", body:formData });
    return r.json();
  },
  async getJSON(url) {
    const r = await fetch(url);
    return r.json();
  },
  setLoading(loader, btn, on) { if(loader) loader.classList.toggle("active", on); if(btn) btn.disabled = on; },

  toast(msg, type="info", ms=3800) {
    const c = document.getElementById("toast-container"); if(!c) return;
    const el = document.createElement("div"); el.className = `toast ${type}`;
    const icon = type==="success"?"circle-check":type==="error"?"circle-exclamation":"circle-info";
    el.innerHTML = `<i class="fa-solid fa-${icon}"></i><span>${this.esc(msg)}</span>`;
    c.appendChild(el);
    setTimeout(()=>{ el.style.animation="toastOut 0.2s ease forwards"; setTimeout(()=>el.remove(),200); }, ms);
  },

  threatColor(level) {
    return {CRITICAL:"#FF3B5C", HIGH:"#FF9F1C", MEDIUM:"#FFD23F", LOW:"#00F5FF", CLEAN:"#00FF88"}[level] || "#9aa3b8";
  },
  threatIcon(level) {
    return {CRITICAL:"skull-crossbones", HIGH:"triangle-exclamation", MEDIUM:"circle-exclamation",
            LOW:"circle-info", CLEAN:"shield-check"}[level] || "circle-info";
  },

  sevIcon(sev) {
    return {critical:"circle-exclamation", high:"triangle-exclamation",
            medium:"circle-exclamation", low:"circle-info"}[sev] || "circle-info";
  },

  finding(f) {
    const tags = [
      f.source_ip ? `<span class="finding-tag"><i class="fa-solid fa-network-wired"></i> ${this.esc(f.source_ip)}</span>` : '',
      f.path ? `<span class="finding-tag">${this.esc(f.path.slice(0,40))}</span>` : '',
      f.line_number ? `<span class="finding-tag">line ${f.line_number}</span>` : '',
      f.count > 1 ? `<span class="finding-tag">${f.count}x</span>` : '',
    ].filter(Boolean).join("");
    return `
      <div class="finding sev-${f.severity}">
        <div class="finding-icon"><i class="fa-solid fa-${this.sevIcon(f.severity)}" style="color:${this.threatColor(f.severity==='critical'?'CRITICAL':f.severity==='high'?'HIGH':f.severity==='medium'?'MEDIUM':'LOW')}"></i></div>
        <div class="finding-body">
          <strong>${this.esc(f.title)} <span class="sev-badge ${f.severity}">${f.severity}</span></strong>
          <div class="finding-detail">${this.esc(f.detail)}</div>
          <div class="finding-meta">${tags}</div>
        </div>
      </div>`;
  },

  // ── Pure-CSS stacked bar timeline ──
  renderTimeline(findingsTimeline, containerId) {
    const el = document.getElementById(containerId);
    if (!findingsTimeline.length) {
      el.innerHTML = `<div class="empty-state" style="padding:20px"><i class="fa-solid fa-chart-simple"></i><p style="font-size:12px">No timestamped events to chart.</p></div>`;
      return;
    }
    const maxTotal = Math.max(...findingsTimeline.map(b => b.total), 1);
    const bars = findingsTimeline.map(b => {
      const h = (v) => Math.max(0, (v / maxTotal) * 100);
      const time = new Date(b.bucket_start).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
      return `
        <div class="timeline-bar-wrap" title="${time}: ${b.total} finding(s)">
          <div class="timeline-bar stack-critical" style="height:${h(b.critical)}%"></div>
          <div class="timeline-bar stack-high" style="height:${h(b.high)}%"></div>
          <div class="timeline-bar stack-medium" style="height:${h(b.medium)}%"></div>
        </div>`;
    }).join("");
    el.innerHTML = `<div class="timeline-chart">${bars}</div>`;
  },

  // ── Drop zone ──
  initDropZone(zoneId, inputId, labelId) {
    const zone = document.getElementById(zoneId);
    const input = document.getElementById(inputId);
    const label = document.getElementById(labelId);
    if (!zone || !input) return;
    const update = () => {
      const f = input.files[0];
      label.innerHTML = f
        ? `<div class="drop-icon"><i class="fa-solid fa-file-lines"></i></div><div class="drop-label"><strong>${this.esc(f.name)}</strong> (${(f.size/1024).toFixed(1)} KB)</div>`
        : `<div class="drop-icon"><i class="fa-solid fa-upload"></i></div><div class="drop-label"><strong>Drop a log file</strong> or click to browse</div>`;
    };
    input.addEventListener("change", update);
    zone.addEventListener("dragover", e => { e.preventDefault(); zone.classList.add("drag-over"); });
    zone.addEventListener("dragleave", () => zone.classList.remove("drag-over"));
    zone.addEventListener("drop", e => {
      e.preventDefault(); zone.classList.remove("drag-over");
      if (e.dataTransfer.files.length) {
        const dt = new DataTransfer(); dt.items.add(e.dataTransfer.files[0]);
        input.files = dt.files; update();
      }
    });
  },
};
