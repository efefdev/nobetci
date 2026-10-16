// Nöbetçi tanıtım sitesi: kaydırma efektleri, Telegram gösterimi, küçük canlandırmalar.
(() => {
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  // Üst çubuk çizgisi.
  const nav = $("#nav");
  const onScroll = () => nav.classList.toggle("scrolled", window.scrollY > 8);
  addEventListener("scroll", onScroll, { passive: true });
  onScroll();

  // Görünürken belirme.
  const reveals = $$(".statement > *, .numbers > div, .facts li, .wipe-copy, .systems > *, .install > *, .cmd");
  reveals.forEach((el) => el.classList.add("reveal"));
  const io = new IntersectionObserver((entries) => {
    for (const e of entries) if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); }
  }, { rootMargin: "0px 0px -10% 0px" });
  reveals.forEach((el, i) => { el.style.transitionDelay = `${(i % 3) * 90}ms`; io.observe(el); });

  // Telegram konuşması: mesajlar sırayla gelir, "Onayla" basılır.
  const tg = $("#tg");
  if (tg && !reduce) {
    tg.classList.add("play");
    const items = $$(".tg-body > *", tg);
    const pressed = $(".key.is-pressed", tg);
    const gaps = [500, 700, 900, 600, 1300, 900, 500];
    (async () => {
      for (let i = 0; i < items.length; i++) {
        await sleep(gaps[i] ?? 600);
        if (items[i].classList.contains("sys") && pressed) { pressed.classList.add("lit"); await sleep(500); }
        items[i].classList.add("on");
      }
    })();
  }

  // Sayılar: görününce sayarak gelir.
  const countIO = new IntersectionObserver((entries) => {
    for (const e of entries) {
      if (!e.isIntersecting) continue;
      countIO.unobserve(e.target);
      const to = +e.target.dataset.to;
      if (reduce || !to) continue;
      const start = performance.now(), dur = 1400;
      const tick = (t) => {
        const k = Math.min((t - start) / dur, 1), ease = 1 - Math.pow(1 - k, 4);
        e.target.textContent = Math.round(to * ease);
        if (k < 1) requestAnimationFrame(tick);
      };
      e.target.textContent = "0";
      requestAnimationFrame(tick);
    }
  }, { threshold: 0.6 });
  $$(".count").forEach((c) => countIO.observe(c));

  // Log satırı → kural motorunun kararı.
  const llReq = $("#llReq"), llOut = $("#llOut");
  const lines = [
    ["203.0.113.9 GET /wp-admin/ · sqlmap/1.8", "saldırı aracı · banlandı"],
    ["198.51.100.40 GET /urun?id=1+UNION+SELECT+1", "SQL enjeksiyonu · banlandı"],
    ["203.0.113.61 GET /../../etc/passwd", "dizin aşma · banlandı"],
    ["198.51.100.73 sshd Failed password ×5", "SSH kaba kuvvet · banlandı"],
    ["203.0.113.18 POST /uploads/shell.php", "webshell · banlandı"],
    ["198.51.100.12 GET /.env", "tuzak adres · banlandı"],
  ];
  let running = false;
  if (llReq && !reduce) {
    const lineIO = new IntersectionObserver(async ([e]) => {
      if (!e.isIntersecting || running) return;
      running = true;
      let i = 0;
      while (true) {
        const [req, out] = lines[i++ % lines.length];
        llOut.style.opacity = "0";
        llReq.textContent = "";
        for (let c = 1; c <= req.length; c += 2) { llReq.textContent = req.slice(0, c); await sleep(18); }
        llReq.textContent = req;
        await sleep(350);
        llOut.textContent = out;
        llOut.style.transition = "opacity .4s";
        llOut.style.opacity = "1";
        await sleep(2400);
      }
    }, { threshold: 0.5 });
    lineIO.observe(llReq.parentElement);
  }

  // Kopyala.
  $$(".copy").forEach((b) => b.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(b.dataset.copy);
      b.textContent = "Kopyalandı"; b.classList.add("ok");
      setTimeout(() => { b.textContent = "Kopyala"; b.classList.remove("ok"); }, 1600);
    } catch { /* pano izni yoksa sessiz geç */ }
  }));
})();
