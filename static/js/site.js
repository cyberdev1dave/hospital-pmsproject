/* site.js: mobile menu, password toggle and in-page forms.
   Login state is decided by the server (Flask session); this file only
   improves the experience. Every form still works without JavaScript. */
(function () {
  "use strict";

  /* ---------- mobile menu ---------- */
  var bar = document.querySelector(".navbar"), toggle = document.querySelector(".nav-toggle");
  function closeMenu() {
    if (!bar) return;
    bar.classList.remove("open");
    if (toggle) { toggle.setAttribute("aria-expanded", "false"); toggle.setAttribute("aria-label", "Open menu"); }
  }
  if (bar && toggle) {
    toggle.addEventListener("click", function () {
      var open = bar.classList.toggle("open");
      toggle.setAttribute("aria-expanded", String(open));
      toggle.setAttribute("aria-label", open ? "Close menu" : "Open menu");
    });
    bar.addEventListener("click", function (e) { if (e.target.closest("a")) closeMenu(); });
    document.addEventListener("keydown", function (e) { if (e.key === "Escape") closeMenu(); });
    window.addEventListener("resize", function () { if (window.innerWidth > 1150) closeMenu(); });
  }

  /* ---------- password show/hide + confirm check ---------- */
  var pw = document.getElementById("password"), eye = document.getElementById("togglePassword");
  if (pw && eye) eye.addEventListener("click", function () {
    var show = pw.type === "password";
    pw.type = show ? "text" : "password";
    eye.textContent = show ? "Hide" : "Show";
    eye.setAttribute("aria-label", show ? "Hide password" : "Show password");
  });
  var reg = document.getElementById("registerForm");
  if (reg) reg.addEventListener("submit", function (e) {
    var c = document.getElementById("confirm"), err = document.getElementById("confirmError");
    if (c && pw && c.value !== pw.value) {
      e.preventDefault();
      c.classList.add("invalid");
      if (err) err.textContent = "Passwords do not match.";
    }
  });

  /* ---------- booking panel: doctor buttons ---------- */
  var panel = document.getElementById("booking-panel");
  var date = document.getElementById("date");
  if (date) date.min = new Date().toISOString().split("T")[0];
  document.querySelectorAll("[data-doctor]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var form = document.getElementById("booking");
      if (!form) { if (panel && panel.dataset.loginUrl) location.href = panel.dataset.loginUrl; return; }
      form.querySelector('[name="doctor"]').value = btn.dataset.doctor;
      form.querySelector('[name="department"]').value = btn.dataset.dept;
      form.scrollIntoView({ behavior: "smooth", block: "center" });
    });
  });

  /* ---------- forms that send without leaving the page ---------- */
  var csrf = (document.querySelector('meta[name="csrf-token"]') || {}).content || "";
  document.querySelectorAll("form[data-endpoint]").forEach(function (form) {
    var note = form.querySelector(".form-note"), button = form.querySelector('button[type="submit"]');
    function say(text, ok) { if (note) { note.textContent = text; note.className = "form-note " + (ok ? "ok" : "err"); } }
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      if (!form.checkValidity()) { form.reportValidity(); return; }
      button.disabled = true;
      fetch(form.dataset.endpoint, {
        method: "POST", body: new FormData(form), credentials: "same-origin",
        headers: { "Accept": "application/json", "X-CSRF-Token": csrf }
      }).then(function (r) { return r.json().catch(function () { return {}; }).then(function (j) { return { status: r.status, j: j }; }); })
        .then(function (r) {
          if (r.status === 401 && r.j.login) { location.href = r.j.login; return; }
          say(r.j.message || (r.j.ok ? "Done." : "Something went wrong. Please try again."), !!r.j.ok);
          if (r.j.ok) {
            form.reset();
            if (form.id === "booking") setTimeout(function () { location.href = "/appointments"; }, 1200);
          }
        })
        .catch(function () { say("Could not reach the hospital system. Please call +234 703 612 0895.", false); })
        .then(function () { button.disabled = false; });
    });
  });
})();
