# Loading, busy and connection states

Every wait in the console, the coordinator setup wizard and the node join window says that something is happening,
keeps the page stable while it happens, and ends: in the result, or in an error that says what failed and offers a
retry. This note records the rules, the guidance they come from, and which pattern each interaction uses.

## Rules

1. **Acknowledge at once, indicate after a short delay.** Under about 0.1 s a response feels instant; up to about 1 s
   the user's flow holds, and past 10 s attention goes elsewhere (Nielsen, *Response Times: The 3 Important Limits*,
   NN/g). A clicked button changes at once (disabled, busy label: the 0.1 s acknowledgement); spinners and the top
   progress bar appear only after 300 ms, so a fast response never flickers an indicator.
2. **Past 10 s, show how long.** NN/g (*Progress Indicators Make a Slow System Less Insufferable*) asks for percent-done
   when the work is measurable and at least a sign of progress otherwise. Uploads show a percentage (bytes sent); the
   console's operations are not measurable, so the busy button adds the elapsed time after 10 s and announces once
   that the work continues.
3. **One submission per click.** The clicked button is disabled until the page is replaced; a second submit of the same
   form is dropped (the form's idempotency key is still the guarantee on the server). A page restored from the
   back/forward cache (`pageshow` with `persisted`) gets its buttons back, and so does a stopped navigation (Escape).
4. **Background refreshes stay quiet.** Fragments refreshed by the live stream (`sse:tick`, `sse:resync`) or a poll
   (`every 3s`) never show a spinner, never set `aria-busy` and never move focus. What the user sees is the header's
   connection state (Live, Reconnecting, Offline) and, when updates stop, the stale banner with the age of the data.
   A refresh never replaces a field the user is typing in, and never runs while the page is navigating away (an
   in-flight operation's button would otherwise come back enabled, with a new idempotency key).
5. **User-started requests show progress where they act.** A request the user started (typing in the protection
   editor, a click) sets `aria-busy="true"` on the region being replaced (WAI-ARIA 1.2: assistive technology waits for
   the update to finish instead of reading it half-done), dims the old content and says "Updating…" after the delay,
   and drives the top progress bar.
6. **Errors are visible, near the cause, with Retry.** `htmx:responseError`, `htmx:sendError` and `htmx:timeout` put a
   short inline message with a Retry button at the top of the region that failed to update; the next successful swap
   removes it. Every htmx request has a 30 s timeout (`htmx.config.timeout`), so nothing spins forever. Full-page
   operations already return to their page with a flash message; a failed one is announced as an alert.
7. **Announce transitions, not polls.** Status text uses one polite live region (`role="status"`, WCAG 2.2 SC 4.1.3
   Status Messages). It speaks when something changes state (an operation started, still running at 10 s, an upload
   finished, live updates lost and resumed), never on each heartbeat, tick or percentage step.
8. **No layout shift.** Busy buttons keep at least their width (`min-width` from the measured width); placeholders
   reserve the height of what they stand for. Skeletons only where real content will appear; elsewhere a sentence
   and a spinner.
9. **Reduced motion.** Under `prefers-reduced-motion: reduce` (WCAG 2.2 SC 2.3.3) the spinner stops turning and the
   progress bar stops trickling; both stay visible, static, beside visible text. Indicators are never the only signal:
   a busy button always says what it is doing in words.
10. **Central, attribute-driven, CSP-clean.** Behaviour lives in `static/app.js` and `static/app.css` and binds to
    existing markup (forms, `hx-*` attributes, `data-` attributes); there is no inline script. Templates opt out
    (`data-no-busy`, `data-no-progress`) rather than opt in.

Sources: NN/g, *Response Times: The 3 Important Limits* and *Progress Indicators Make a Slow System Less Insufferable*;
NN/g, *Skeleton Screens 101*; WAI-ARIA 1.2 (`aria-busy`, `role="status"`); WCAG 2.2 SC 4.1.3, 2.2.2, 2.3.3; the htmx 2
reference (`htmx-request`, `hx-indicator`, `hx-disabled-elt`, `htmx:beforeRequest`/`afterRequest`/`responseError`/
`sendError`/`timeout`, `htmx.config.timeout`) and its SSE extension (`htmx:sseOpen`, `htmx:sseError`); web.dev on the
back/forward cache (`pageshow`) and Cumulative Layout Shift.

## Inventory

| Surface | Wait | Pattern |
|---|---|---|
| Console, any page | link navigation | top progress bar after 300 ms (trickles, completes on the next page); hidden again after 20 s or on `pageshow` (downloads carry `download` and are skipped) |
| Console, every `op_form` (T0/T1 direct, T2/T3 to the plan page) | POST, often seconds (coordinator admin API, module IPC, builds, sign, promote) | busy button: spinner after 300 ms, label "Preparing review…" (T2/T3) or the verb in -ing ("Revoking…"), width kept, disabled, same form not re-sent, elapsed time after 10 s with one announcement; top bar; restored on `pageshow` |
| Plan page, Apply | POST `/apply/<op>` | same busy button ("Applying…") |
| Header Sign out, login Sign in, Fleet pause | POST | same busy button |
| Forms opening a new tab (`newtab`, Approve/Decline on the one-time join code page) | new tab | no busy state (the page stays); the button is held for 1.5 s against a double click |
| GET filter forms (Jobs, Events, Audit, Datasets, Campaigns) | navigation | busy button and top bar |
| Module bundle, agent binary, coordinator build uploads | multipart POST of large files | the file goes first to `POST /stage/<op>` by XHR with a progress bar, percentage and Cancel; then the form posts only the SHA-256 (the coordinator's staging routes, as before). Without script the form posts the file as before |
| Vendor TUF metadata upload | small multipart POST | busy button |
| Dataset folder upload (`upload.js`) | hash and chunked upload per file | overall progress bar with percentage and file count, busy start button, error with Retry (resumes where it stopped), focus moves to Register when done |
| Fleet, campaign, join-code fragments (`sse:tick`, `sse:resync`, `every 3s`) | background GET | quiet: no spinner; a failed refresh leaves the old content with a small "not refreshed" note and Retry; refresh skipped while a field inside is being edited or a navigation is pending; focus kept on the same control across the swap |
| Protection rules preview (`input changed delay:400ms`, `load`) | user GET | placeholder reserving space at first load; `aria-busy`, dimmed content and top bar while it recomputes; `hx-sync` replaces a stale request; inline error with Retry |
| Live stream (`/sse`) | connect, reconnect, drop | header indicator: Connecting (shown only after 1 s), Live, Reconnecting (after 2 s without the stream, or 15 s without a heartbeat), Offline (`navigator.onLine` false or 30 s reconnecting); stale banner with the data's age and Reload; transitions announced once |
| New server build (`server_boot_id`), tab hidden over a minute | full reload | top bar before the reload |
| Copy buttons | clipboard (instant) | "Copied" on the button plus one announcement |
| Passkey sign-in and registration | WebAuthn ceremony | busy button until the ceremony ends, status line (existing) |
| Setup wizard: saved state | POST `/state` | status line with a delayed spinner; error with Retry (existing); 30 s timeout |
| Setup wizard: Install and set up | POST `/start`, up to about a minute (services start, readiness) | busy button "Installing…", `aria-busy` form, progress line with elapsed time after 10 s and a note past 90 s; never aborted from the page (the server has its own readiness timeout) |
| Setup wizard: Verify and finish | POST `/finish` | busy button "Verifying…", 30 s timeout with an error |
| Join window: load | POST `/state` | spinner beside "Loading…" |
| Join window: checks, join, leave, following progress | `/check`, `/join`, `/leave`, `/progress` polls | the progress line carries a spinner and the rows list is `aria-busy` while work runs; elapsed time after 10 s (container installs and administrator prompts take minutes); both stop on failure, ready or waiting |
| Join window: waiting for approval | polls `/state` every 3 s | a quiet "checking" marker, no spinner |
