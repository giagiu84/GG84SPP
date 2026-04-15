/* GG84 UX helpers - GG84_V.2_15.04.2026 */
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
        const HapticsPlugin =
          window.Capacitor &&
          window.Capacitor.Plugins &&
          window.Capacitor.Plugins.Haptics;

        const isNative =
          window.Capacitor &&
          typeof window.Capacitor.isNativePlatform === "function" &&
          window.Capacitor.isNativePlatform();

        if (isNative && HapticsPlugin) {
          if (type === "success" && HapticsPlugin.notification) {
            await HapticsPlugin.notification({ type: "SUCCESS" });
            return;
          }

          if (type === "error" && HapticsPlugin.notification) {
            await HapticsPlugin.notification({ type: "ERROR" });
            return;
          }

          if (HapticsPlugin.impact) {
            const styleMap = {
              light: "LIGHT",
              medium: "MEDIUM",
              heavy: "HEAVY",
              success: "MEDIUM",
              error: "HEAVY"
            };
            await HapticsPlugin.impact({ style: styleMap[type] || "LIGHT" });
            return;
          }
        }
      } catch (error) {
        console.warn("GG84UX haptic native fallback:", error);
      }

      try {
        if (navigator.vibrate) {
          const patternMap = {
            light: 18,
            medium: 28,
            heavy: 40,
            success: [18, 30, 18],
            error: [45, 30, 45]
          };
          navigator.vibrate(patternMap[type] || 18);
        }
      } catch (error) {
        console.warn("GG84UX haptic vibrate fallback:", error);
      }
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
        variant === "error" ? "×" : "•";

      const text = document.createElement("span");
      text.className = "gg84-toast-text";
      text.textContent = String(message || "");

      toast.appendChild(icon);
      toast.appendChild(text);
      root.appendChild(toast);

      requestAnimationFrame(() => {
        toast.classList.add("show");
      });

      clearTimeout(this.toastTimer);
      this.toastTimer = setTimeout(() => {
        toast.classList.remove("show");
        setTimeout(() => {
          if (toast.parentNode) toast.parentNode.removeChild(toast);
        }, 220);
      }, Math.max(900, duration));
    },

    glowBox(target, variant = "ok", duration = 1200) {
      const el = typeof target === "string" ? document.getElementById(target) : target;
      if (!el) return;

      el.classList.remove("gg84-glow-ok", "gg84-glow-warn", "gg84-glow-error");
      void el.offsetWidth;
      el.classList.add(`gg84-glow-${variant}`);

      setTimeout(() => {
        el.classList.remove("gg84-glow-ok", "gg84-glow-warn", "gg84-glow-error");
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
    }
  };

  window.GG84UX = GG84UX;
})();