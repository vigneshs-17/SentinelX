import { ApiError, request, session } from "../api.js";
import { clear, h } from "../dom.js";

export function renderLogin(main, { onSuccess }) {
  const username = h("input", { id: "username", name: "username", type: "text", autocomplete: "username", required: true, maxlength: "64", autocapitalize: "none", spellcheck: "false" });
  const password = h("input", { id: "password", name: "password", type: "password", autocomplete: "current-password", required: true, maxlength: "1024" });
  const error = h("p", { class: "error", id: "login-error", role: "alert" });
  const submit = h("button", { class: "btn btn-primary", type: "submit" }, "Sign in");
  let timer = null;

  function lockout(seconds) {
    let left = seconds;
    submit.disabled = true;
    const tick = () => {
      if (left <= 0) {
        submit.disabled = false;
        error.textContent = "";
        return;
      }
      error.textContent = `Too many attempts. Try again in ${left} second${left === 1 ? "" : "s"}.`;
      left -= 1;
      timer = setTimeout(tick, 1000);
    };
    tick();
  }

  const form = h(
    "form",
    {
      novalidate: true,
      onSubmit: async (event) => {
        event.preventDefault();
        error.textContent = "";
        if (!username.value || !password.value) {
          error.textContent = "Enter your username and password.";
          return;
        }
        submit.disabled = true;
        try {
          const { data } = await request("POST", "/login", { body: { username: username.value, password: password.value } });
          session.user = data.user.username;
          session.role = data.user.role;
          session.csrf = data.csrf_token;
          password.value = "";
          onSuccess();
        } catch (e) {
          password.value = "";
          if (e instanceof ApiError && e.status === 429) lockout(e.retryAfter || 30);
          else {
            error.textContent = e instanceof ApiError && e.status === 401 ? e.message : "Sign-in failed. Try again.";
            submit.disabled = false;
            password.focus();
          }
        }
      },
    },
    h("div", null, h("label", { for: "username" }, "Username"), username),
    h("div", null, h("label", { for: "password" }, "Password"), password),
    error,
    submit,
  );

  clear(main).append(
    h("div", { class: "panel login" }, h("h1", null, "SentinelX"), h("p", { class: "muted" }, "Sign in to the analyst console."), form),
  );
  username.focus();
  return () => clearTimeout(timer);
}
