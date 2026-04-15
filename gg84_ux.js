<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>gg84_ux.js aligned - GG84_V.2_15.04.2026</title>
<style>
body { margin:0; font-family: Arial, sans-serif; background:#f4f4f2; color:#111; }
header { padding:14px 16px; background:#111; color:#fff; font-weight:700; }
main { padding:16px; }
pre { white-space: pre-wrap; word-break: break-word; background:#fff; border:1px solid #ddd; border-radius:12px; padding:14px; font-size:12px; line-height:1.45; }
</style>
</head>
<body>
<header>gg84_ux.js aligned - GG84_V.2_15.04.2026</header>
<main><pre>/* GG84 UX helper aligned – GG84_V.2_15.04.2026 */
(function () {
  const GG84UX = {
    toastTimer: null,

    ensureToastRoot() {
      let root = document.getElementById(&quot;gg84-toast-root&quot;);
      if (!root) {
        root = document.createElement(&quot;div&quot;);
        root.id = &quot;gg84-toast-root&quot;;
        root.className = &quot;gg84-toast-root&quot;;
        document.body.appendChild(root);
      }
      return root;
    },

    async haptic(type = &quot;light&quot;) {
      try {
        const HapticsPlugin =
          window.Capacitor &amp;&amp;
          window.Capacitor.Plugins &amp;&amp;
          window.Capacitor.Plugins.Haptics;

        const isNative =
          window.Capacitor &amp;&amp;
          typeof window.Capacitor.isNativePlatform === &quot;function&quot; &amp;&amp;
          window.Capacitor.isNativePlatform();

        if (isNative &amp;&amp; HapticsPlugin) {
          if (type === &quot;success&quot; &amp;&amp; HapticsPlugin.notification) {
            await HapticsPlugin.notification({ type: &quot;SUCCESS&quot; });
            return;
          }

          if (type === &quot;error&quot; &amp;&amp; HapticsPlugin.notification) {
            await HapticsPlugin.notification({ type: &quot;ERROR&quot; });
            return;
          }

          if (HapticsPlugin.impact) {
            const styleMap = {
              light: &quot;LIGHT&quot;,
              medium: &quot;MEDIUM&quot;,
              heavy: &quot;HEAVY&quot;,
              success: &quot;MEDIUM&quot;,
              error: &quot;HEAVY&quot;
            };
            await HapticsPlugin.impact({ style: styleMap[type] || &quot;LIGHT&quot; });
            return;
          }
        }
      } catch (error) {
        console.warn(&quot;GG84UX haptic native fallback:&quot;, error);
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
        console.warn(&quot;GG84UX haptic vibrate fallback:&quot;, error);
      }
    },

    toast(message, variant = &quot;ok&quot;, duration = 1800) {
      const root = this.ensureToastRoot();
      root.innerHTML = &quot;&quot;;

      const toast = document.createElement(&quot;div&quot;);
      toast.className = `gg84-toast gg84-toast-${variant}`;

      const icon = document.createElement(&quot;span&quot;);
      icon.className = &quot;gg84-toast-icon&quot;;
      icon.textContent =
        variant === &quot;ok&quot; ? &quot;✓&quot; :
        variant === &quot;warn&quot; ? &quot;!&quot; :
        variant === &quot;error&quot; ? &quot;×&quot; : &quot;•&quot;;

      const text = document.createElement(&quot;span&quot;);
      text.className = &quot;gg84-toast-text&quot;;
      text.textContent = String(message || &quot;&quot;);

      toast.appendChild(icon);
      toast.appendChild(text);
      root.appendChild(toast);

      requestAnimationFrame(() =&gt; {
        toast.classList.add(&quot;show&quot;);
      });

      clearTimeout(this.toastTimer);
      this.toastTimer = setTimeout(() =&gt; {
        toast.classList.remove(&quot;show&quot;);
        setTimeout(() =&gt; {
          if (toast.parentNode) toast.parentNode.removeChild(toast);
        }, 220);
      }, Math.max(900, duration));
    },

    glowBox(target, variant = &quot;ok&quot;, duration = 1200) {
      const el = typeof target === &quot;string&quot; ? document.getElementById(target) : target;
      if (!el) return;

      el.classList.remove(&quot;gg84-glow-ok&quot;, &quot;gg84-glow-warn&quot;, &quot;gg84-glow-error&quot;);
      void el.offsetWidth;
      el.classList.add(`gg84-glow-${variant}`);

      setTimeout(() =&gt; {
        el.classList.remove(&quot;gg84-glow-ok&quot;, &quot;gg84-glow-warn&quot;, &quot;gg84-glow-error&quot;);
      }, duration);
    },

    async feedback({
      message = &quot;&quot;,
      variant = &quot;ok&quot;,
      box = null,
      haptic = &quot;light&quot;,
      duration = 1800
    } = {}) {
      if (box) this.glowBox(box, variant);
      if (message) this.toast(message, variant, duration);
      if (haptic) await this.haptic(haptic);
    },

    async success(message, box = null) {
      await this.feedback({
        message,
        variant: &quot;ok&quot;,
        box,
        haptic: &quot;success&quot;
      });
    },

    async warning(message, box = null) {
      await this.feedback({
        message,
        variant: &quot;warn&quot;,
        box,
        haptic: &quot;medium&quot;
      });
    },

    async error(message, box = null) {
      await this.feedback({
        message,
        variant: &quot;error&quot;,
        box,
        haptic: &quot;error&quot;
      });
    }
  };

  window.GG84UX = GG84UX;
})();</pre></main>
</body>
</html>