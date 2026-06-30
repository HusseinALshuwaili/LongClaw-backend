// ===== SENTINEL_AGENTS — shared behavior =====
(function(){
  function tick(){
    const el=document.getElementById('clock');
    if(!el) return;
    el.textContent=new Date().toTimeString().slice(0,8);
  }
  tick();setInterval(tick,1000);

  function animateCount(el,dur){
    const target=parseFloat(el.dataset.target);
    const decimals=parseInt(el.dataset.decimals||'0',10);
    const start=performance.now();
    function step(now){
      const p=Math.min((now-start)/dur,1);
      const eased=1-Math.pow(1-p,3);
      const val=target*eased;
      el.textContent=decimals?val.toFixed(decimals):Math.round(val).toLocaleString();
      if(p<1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  const reduceMotion=window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const revealEls=document.querySelectorAll('.reveal');
  const countEls=document.querySelectorAll('.countup');
  const loadBar=document.getElementById('load-bar');

  if(reduceMotion){
    revealEls.forEach(el=>el.classList.add('in'));
    countEls.forEach(el=>{
      el.textContent=el.dataset.decimals?parseFloat(el.dataset.target).toFixed(parseInt(el.dataset.decimals)):Math.round(parseFloat(el.dataset.target)).toLocaleString();
    });
    if(loadBar) loadBar.classList.add('filled');
  } else {
    if('IntersectionObserver' in window){
      const io=new IntersectionObserver((entries)=>{
        entries.forEach(entry=>{
          if(entry.isIntersecting){entry.target.classList.add('in');io.unobserve(entry.target);}
        });
      },{threshold:.15});
      revealEls.forEach(el=>io.observe(el));

      const countIo=new IntersectionObserver((entries)=>{
        entries.forEach(entry=>{
          if(entry.isIntersecting){animateCount(entry.target,1400);countIo.unobserve(entry.target);}
        });
      },{threshold:.6});
      countEls.forEach(el=>countIo.observe(el));

      if(loadBar){
        const barIo=new IntersectionObserver((entries)=>{
          entries.forEach(entry=>{
            if(entry.isIntersecting){entry.target.classList.add('filled');barIo.unobserve(entry.target);}
          });
        },{threshold:.5});
        barIo.observe(loadBar);
      }
    } else {
      revealEls.forEach(el=>el.classList.add('in'));
      countEls.forEach(el=>animateCount(el,1400));
      if(loadBar) loadBar.classList.add('filled');
    }
  }

  // mark active nav link based on current page
  const here=(location.pathname.split('/').pop()||'index.html');
  document.querySelectorAll('.navlinks a').forEach(a=>{
    const href=a.getAttribute('href')||'';
    if(href===here || (here==='' && href==='cybersec-agents-landing.html')){
      a.classList.add('active');
    }
  });
})();
