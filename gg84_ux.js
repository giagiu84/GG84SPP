/* GG84UX aligned - GG84_V.2_15.04.2026 */
(function () {

  const GG84UX = {

    toastTimer: null,

    ensureToastRoot() {
      let root = document.getElementById("gg84-toast-root");

      if (!root) {
        root = document.createElement("div");
        root.id = "gg84-toast-root";
        root.className = "gg84-toast-root";
        document.body.appendChild(root);
      }

      return root;
    },

    async haptic(type = "light") {
      try {
        const Haptics =
          window.Capacitor &&
          window.Capacitor.Plugins &&
          window.Capacitor.Plugins.Haptics;

        const isNative =
          window.Capacitor &&
          typeof window.Capacitor.isNativePlatform === "function" &&
          window.Capacitor.isNativePlatform();

        if (isNative && Haptics) {

          if (type === "success" && Haptics.notification) {
            await Haptics.notification({ type: "SUCCESS" });
            return;
          }

          if (type === "error" && Haptics.notification) {
            await Haptics.notification({ type: "ERROR" });
            return;
          }

          if (type === "scan" && Haptics.impact) {
            await Haptics.impact({ style: "LIGHT" });
            return;
          }

          if (Haptics.impact) {
            const map = {
              light: "LIGHT",
              medium: "MEDIUM",
              heavy: "HEAVY"
            };
            await Haptics.impact({ style: map[type] || "LIGHT" });
            return;
          }
        }

      } catch (e) {}

      // fallback browser
      try {
        if (navigator.vibrate) {
          const patterns = {
            light: 15,
            medium: 25,
            heavy: 40,
            success: [15, 25, 15],
            error: [40, 30, 40],
            scan: 10
          };
          navigator.vibrate(patterns[type] || 15);
        }
      } catch (e) {}
    },

    toast(message, variant = "ok", duration = 1800) {

      const root = this.ensureToastRoot();
      root.innerHTML = "";

      const toast = document.createElement("div");
      toast.className = `gg84-toast gg84-toast-${variant}`;

      const icon = document.createElement("span");
      icon.className = "gg84-toast-icon";

      icon.textContent =
        variant === "ok" ? "✓" :
        variant === "warn" ? "!" :
        variant === "error" ? "×" :
        variant === "scan" ? "⌁" :
        "•";

      const text = document.createElement("span");
      text.className = "gg84-toast-text";
      text.textContent = String(message || "");

      toast.appendChild(icon);
      toast.appendChild(text);
      root.appendChild(toast);

      requestAnimationFrame(() => toast.classList.add("show"));

      clearTimeout(this.toastTimer);

      this.toastTimer = setTimeout(() => {
        toast.classList.remove("show");
        setTimeout(() => {
          if (toast.parentNode) toast.remove();
        }, 200);
      }, Math.max(900, duration));
    },

    glowBox(target, variant = "ok", duration = 1200) {

      const el = typeof target === "string"
        ? document.getElementById(target)
        : target;

      if (!el) return;

      el.classList.remove(
        "gg84-glow-ok",
        "gg84-glow-warn",
        "gg84-glow-error"
      );

      void el.offsetWidth;

      el.classList.add(`gg84-glow-${variant}`);

      setTimeout(() => {
        el.classList.remove(
          "gg84-glow-ok",
          "gg84-glow-warn",
          "gg84-glow-error"
        );
      }, duration);
    },

    pulse(target, duration = 1000) {
      const el = typeof target === "string"
        ? document.getElementById(target)
        : target;

      if (!el) return;

      el.classList.add("gg84-pulse");

      setTimeout(() => {
        el.classList.remove("gg84-pulse");
      }, duration);
    },

    async feedback({
      message = "",
      variant = "ok",
      box = null,
      haptic = "light",
      duration = 1800
    } = {}) {

      if (box) this.glowBox(box, variant);
      if (message) this.toast(message, variant, duration);
      if (haptic) await this.haptic(haptic);
    },

    async success(message, box = null) {
      await this.feedback({
        message,
        variant: "ok",
        box,
        haptic: "success"
      });
    },

    async warning(message, box = null) {
      await this.feedback({
        message,
        variant: "warn",
        box,
        haptic: "medium"
      });
    },

    async error(message, box = null) {
      await this.feedback({
        message,
        variant: "error",
        box,
        haptic: "error"
      });
    },

    async scan(message = "QR acquisito") {
      await this.feedback({
        message,
        variant: "scan",
        haptic: "scan"
      });
    }

  };

  window.GG84UX = GG84UX;

})();