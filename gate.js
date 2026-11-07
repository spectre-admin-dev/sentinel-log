// Sentinel sign-in gate, shared by index.html and map.html.
// The page stays blank until an allowlisted account (owner or viewer) signs in.
// Real protection is in the database rules (schema.sql); this only keeps the UI tidy.
(function(){
  const css = `
  #sgate{position:fixed;inset:0;z-index:9999;display:grid;place-items:center;padding:16px;background:var(--bg,#0e1517);color:var(--fg,#d9e4e2);font-family:var(--f-body,system-ui,sans-serif)}
  #sgate .box{width:min(380px,100%);background:var(--panel,#141d20);border:1px solid var(--line,#24474a);padding:22px;display:flex;flex-direction:column;gap:12px}
  #sgate h1{font-family:var(--f-display,sans-serif);font-size:1.25rem;letter-spacing:.08em;text-transform:uppercase;margin:0}
  #sgate p{margin:0;color:var(--muted,#83999a);font-size:.85rem;line-height:1.5}
  #sgate input{font:inherit;color:inherit;background:var(--panel-2,#1a2528);border:1px solid var(--line-soft,#1e3134);padding:9px 10px;border-radius:2px;width:100%}
  #sgate input:focus,#sgate button:focus-visible{outline:2px solid var(--accent,#ff8a1f);outline-offset:1px}
  #sgate button{font-family:var(--f-display,sans-serif);letter-spacing:.08em;text-transform:uppercase;font-size:.8rem;font-weight:600;cursor:pointer;border-radius:2px;padding:9px 12px;border:1px solid var(--accent,#ff8a1f);background:var(--accent,#ff8a1f);color:var(--accent-ink,#1a0d00)}
  #sgate button.ghost{background:transparent;border-color:var(--line,#24474a);color:var(--fg,#d9e4e2)}
  #sgate .msg{font-family:var(--f-mono,monospace);font-size:.78rem;min-height:1.2em}
  #sgate .msg.err{color:var(--crit,#ff5a5a)} #sgate .msg.ok{color:var(--ok,#4fd1a1)}
  #sgate form{display:flex;flex-direction:column;gap:10px}`;

  function el(html){ const t=document.createElement("template"); t.innerHTML=html.trim(); return t.content.firstChild; }

  function showGate(sb, state, text){
    let g=document.getElementById("sgate");
    if(!g){
      const st=document.createElement("style"); st.textContent=css; document.head.appendChild(st);
      g=el('<div id="sgate" role="dialog" aria-modal="true" aria-labelledby="sgateH"><div class="box"></div></div>');
      document.body.appendChild(g);
    }
    const box=g.querySelector(".box");
    if(state==="signin"){
      box.innerHTML='<h1 id="sgateH">Sentinel</h1><p>Private. Sign in with an approved email and you\'ll get a one-time link.</p>'+
        '<form id="sgForm"><input id="sgEmail" type="email" autocomplete="email" placeholder="you@example.com" aria-label="Email" required>'+
        '<button type="submit">Send sign-in link</button></form><span class="msg" id="sgMsg" role="status"></span>';
      box.querySelector("#sgForm").addEventListener("submit",async e=>{
        e.preventDefault();
        const m=box.querySelector("#sgMsg"); m.className="msg"; m.textContent="Sending…";
        const { error } = await sb.auth.signInWithOtp({ email: box.querySelector("#sgEmail").value.trim(),
          options:{ emailRedirectTo: location.origin+location.pathname, shouldCreateUser:false } });
        // Same answer whether or not the address exists, so the form can't be used to probe accounts.
        if(error && !/signups not allowed|not found|otp_disabled/i.test(error.message)){ m.className="msg err"; m.textContent=error.message; return; }
        m.className="msg ok"; m.textContent="If that address is approved, a link is on its way.";
      });
    } else {
      box.innerHTML='<h1 id="sgateH">Sentinel</h1><p>'+text+'</p><button type="button" class="ghost" id="sgOut">Sign out</button>';
      box.querySelector("#sgOut").onclick=async()=>{ await sb.auth.signOut(); location.reload(); };
    }
    g.hidden=false;
  }

  function hideGate(){ const g=document.getElementById("sgate"); if(g) g.remove(); }

  // Resolves once an owner or viewer is signed in: { sb, role, email }.
  window.SentinelGate = {
    start(){
      return new Promise(resolve=>{
        const cfg=window.SENTINEL_CONFIG||{};
        if(!window.supabase||!cfg.supabaseUrl||!cfg.supabaseKey){ document.body.textContent="Not configured: add the Supabase URL and key to config.js."; return; }
        const sb=window.supabase.createClient(cfg.supabaseUrl, cfg.supabaseKey);
        let done=false;
        async function check(session){
          if(done) return;
          if(!session){ showGate(sb,"signin"); return; }
          const { data:role, error } = await sb.rpc("my_role");
          if(error){ showGate(sb,"denied","Couldn't check access: "+error.message); return; }
          if(role==="owner"||role==="viewer"){ done=true; hideGate(); resolve({ sb, role, email: session.user.email }); return; }
          showGate(sb,"denied", role==="uploader"
            ? "This is a scanner upload account. It can send detections but can't view them."
            : "Signed in as "+session.user.email+", but this account hasn't been given access.");
        }
        sb.auth.onAuthStateChange((evt,session)=>{ if(evt==="SIGNED_OUT") location.reload(); else if(session) check(session); });
        sb.auth.getSession().then(({data:{session}})=>check(session));
      });
    }
  };
})();
