(function(){
  const c=document.getElementById("matrix-bg");
  if(!c)return;
  const ctx=c.getContext("2d");
  function r(){c.width=window.innerWidth;c.height=window.innerHeight;}
  r();window.addEventListener("resize",r);
  const chars="01LOGSSHAPACHEPHANTOM404500200";
  const fs=14;let cols,drops;
  function s(){cols=Math.floor(c.width/fs);drops=Array.from({length:cols},()=>Math.random()*-50);}
  s();window.addEventListener("resize",s);
  const colors=["#00F5FF","#9B5DE5","#00FF88"];
  function draw(){
    ctx.fillStyle="rgba(6,6,8,0.06)";ctx.fillRect(0,0,c.width,c.height);
    ctx.font=`${fs}px JetBrains Mono,monospace`;
    for(let i=0;i<cols;i++){
      ctx.fillStyle=colors[Math.floor(Math.random()*colors.length)];
      ctx.fillText(chars[Math.floor(Math.random()*chars.length)],i*fs,drops[i]*fs);
      if(drops[i]*fs>c.height&&Math.random()>0.975)drops[i]=0;
      drops[i]++;
    }
  }
  setInterval(draw,45);
})();
