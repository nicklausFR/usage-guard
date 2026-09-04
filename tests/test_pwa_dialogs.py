from html.parser import HTMLParser
import json
from pathlib import Path
import subprocess
import unittest


class _ButtonParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.buttons = []

    def handle_starttag(self, tag, attrs):
        if tag == "button":
            self.buttons.append(dict(attrs))


class PwaDialogTest(unittest.TestCase):
    def test_local_limit_editor_targets_the_mapped_limited_user_not_admin(self):
        script = (
            Path(__file__).parents[1] / "pwa" / "app.js"
        ).read_text(encoding="utf-8")
        start = script.index("function limitedPersonUsername")
        end = script.index("function renderCompleteLimitScope", start)
        function = script[start:end]
        source = f"""
let remoteMode=false;
let selectedPolicyUsername="";
let localWindowsUsername="windows-login";
let state={{runtime:{{windows_identity:{{usage_guard_username:"nicklaus"}}}}}};
function selectedPersonScope(){{return null}}
{function}
console.log(limitedPersonUsername());
"""
        completed = subprocess.run(
            ["node", "-e", source], check=True, capture_output=True, text=True
        )

        self.assertEqual(completed.stdout.strip(), "nicklaus")
        scope_renderer = script.split(
            "function renderCompleteLimitScope", 1
        )[1].split("function refreshCompleteLimitEditor", 1)[0]
        self.assertNotIn("authState?.username", scope_renderer)

    def test_today_requests_include_the_browser_calendar_day(self):
        script = (
            Path(__file__).parents[1] / "pwa" / "app.js"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'day=${encodeURIComponent(localDay(new Date()))}', script,
        )
        self.assertIn('scope=(?:today|session)', script)

    def _markup(self):
        return (Path(__file__).parents[1] / "pwa" / "index.html").read_text(
            encoding="utf-8"
        )

    def test_cancel_buttons_never_trigger_form_validation(self):
        parser = _ButtonParser()
        parser.feed(self._markup())
        cancel_buttons = [
            attributes
            for attributes in parser.buttons
            if attributes.get("value") == "cancel"
        ]

        self.assertTrue(cancel_buttons)
        for attributes in cancel_buttons:
            self.assertIn("formnovalidate", attributes)

    def test_login_shows_a_busy_indicator_during_slow_requests(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")
        style = (root / "style.css").read_text(encoding="utf-8")
        self.assertIn('id="login-progress"', markup)
        self.assertIn("function setLoginBusy", script)
        self.assertIn("setLoginBusy(formElement,true)", script)
        self.assertIn("setLoginBusy(formElement,false)", script)
        self.assertIn("aria-busy", script)
        self.assertIn("@keyframes auth-spinner", style)

    def test_remote_limit_mutation_blocks_until_the_pc_applies_it(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")
        style = (root / "style.css").read_text(encoding="utf-8")

        self.assertIn('id="remote-mutation-dialog"', markup)
        self.assertIn('id="remote-mutation-progress"', markup)
        self.assertIn('id="remote-mutation-cancel"', markup)
        self.assertIn('id="remote-mutation-retry"', markup)
        self.assertIn("dialog.showModal()", script)
        self.assertIn("idempotency_key:mutation.operationId", script)
        self.assertIn("status.applied", script)
        self.assertIn("cancelRemoteMutation", script)
        self.assertIn("Une modification est déjà en cours", script)
        self.assertIn("#remote-mutation-progress", style)

    def test_pending_limit_cards_are_not_rendered_below_active_limits(self):
        script = (
            Path(__file__).parents[1] / "pwa" / "app.js"
        ).read_text(encoding="utf-8")
        self.assertNotIn("pendingLimitCards", script)
        self.assertNotIn("En attente de récupération par le PC", script)

    def test_remote_limits_are_person_scoped_and_have_real_rollback(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")

        self.assertIn('id="limit-person-choice"', markup)
        self.assertNotIn('id="limit-policy-mode"', markup)
        self.assertIn("function personalPolicyOverview", script)
        self.assertIn("/api/v1/policies/${encodeURIComponent", script)
        self.assertIn("/operations/${encodeURIComponent", script)
        self.assertIn("/cancel", script)
        self.assertIn("politique précédente restaurée", script)
        self.assertNotIn('reset=remoteMode?""', script)
        self.assertIn('>Modifier</button><button data-limit-remove=', script)
        self.assertIn('class="danger">Supprimer</button>', script)

    def test_remote_personal_policy_closes_after_server_persistence(self):
        script = (
            Path(__file__).parents[1] / "pwa" / "app.js"
        ).read_text(encoding="utf-8")
        personal = script.split(
            "async function executePersonalPolicyMutation", 1
        )[1].split("async function cancelRemoteMutation", 1)[0]

        self.assertNotIn("while(remoteMutation===mutation)", personal)
        self.assertIn("l’appliqueront à leur connexion", personal)
        self.assertIn("ordinateur(s) en attente", script)
        self.assertNotIn("Appliquer sur tous ses ordinateurs", script)
        self.assertNotIn("set_enforcement_mode", script)

    def test_redundant_organize_tab_is_absent(self):
        markup = self._markup()
        self.assertNotIn('data-tab="organize"', markup)
        self.assertNotIn('id="organize"', markup)

    def test_manifest_uses_installable_png_icons(self):
        pwa = Path(__file__).parents[1] / "pwa"
        manifest = json.loads((pwa / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(
            {(icon["sizes"], icon["type"]) for icon in manifest["icons"]},
            {("192x192", "image/png"), ("512x512", "image/png")},
        )
        for icon in manifest["icons"]:
            self.assertTrue((pwa / icon["src"].lstrip("/")).exists())

    def test_service_worker_revalidates_assets_during_local_testing(self):
        worker = (
            Path(__file__).parents[1] / "pwa" / "service-worker.js"
        ).read_text(encoding="utf-8")
        self.assertIn('fetch(event.request,{cache:"no-store"})', worker)

    def test_live_measurements_refresh_each_second_and_show_seconds(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        self.assertIn('min ${String(s).padStart(2,"0")} s', script)
        self.assertIn('$("#today").classList.contains("active"))load("scope=today",{live:true})', script)
        self.assertIn('$("#limits").classList.contains("active"))load("scope=limits",{live:true})', script)
        self.assertIn('$("#analysis").classList.contains("active"))refreshAnalysisActivity()', script)
        self.assertIn("function refreshTreeValues", script)
        self.assertIn('renderRunTimeline(view,"#today-sessions")', script)
        self.assertIn('if(!$("#analysis-sessions").hidden)renderSelectedAnalysis()', script)
        self.assertIn("analysisHistory=history;state=history", script)
        self.assertIn("deviceHistories={...entry.deviceHistories}", script)
        self.assertNotIn("renderSelectedAnalysis({...analysisHistory,current:latest.current", script)
        self.assertIn("selectedTodaySessionKey", script)

    def test_open_windows_session_remains_visible_after_midnight(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        self.assertIn("function todayWindowsSessions", script)
        self.assertIn("opened<end&&(!closed||closed>start)", script)
        self.assertIn("dayStart(nextDay(today))", script)

    def test_today_session_timeline_is_clipped_to_the_selected_day(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        start = script.index("function localDay")
        end = script.index("function metadataForTarget", start)
        functions = script[start:end]
        bounds_start = functions.index("function todaySessionBounds")
        date_functions = functions[:functions.index("function daysBetween")]
        bounds_function = functions[bounds_start:]
        overview_function = next(
            line for line in script.splitlines()
            if line.startswith("function overviewDay(")
        )
        absence_start = script.index("function timelineAbsencePeriods")
        absence_end = script.index("function timelineSystemPeriods", absence_start)
        absence_function = script[absence_start:absence_end]
        source = date_functions + "\nconst remoteMode=false;\nconst centralizedMode=()=>false;\n" + overview_function + "\n" + bounds_function + absence_function + """
const data = {
  date: '2026-08-21',
  timeline_now: '2026-08-22T02:12:53+02:00'
};
const selected = {started_at:'2026-08-21T08:12:53+02:00',ended_at:null};
const bounds = todaySessionBounds(data, selected);
const entries = [
  {item:{kind:'active'},opened:new Date('2026-08-21T08:12:53+02:00'),closed:new Date('2026-08-21T12:00:00+02:00')},
  {item:{kind:'active'},opened:bounds.start,closed:new Date('2026-08-22T01:00:00+02:00')},
  {item:{kind:'active'},opened:new Date('2026-08-22T01:30:00+02:00'),closed:bounds.end}
];
console.log(JSON.stringify({
  start: localDay(bounds.start),
  hour: bounds.start.getHours(),
  elapsed: (bounds.end - bounds.start) / 1000,
  continued: bounds.continued,
  inactive: timelineAbsencePeriods(entries, bounds.start, bounds.end)
    .reduce((sum, period) => sum + (period.end - period.start) / 1000, 0)
}));
"""
        completed = subprocess.run(
            ["node", "-e", source], check=True, capture_output=True, text=True
        )

        result = json.loads(completed.stdout)
        self.assertEqual(result["start"], "2026-08-22")
        self.assertEqual(result["hour"], 0)
        self.assertEqual(result["elapsed"], 2 * 3600 + 12 * 60 + 53)
        self.assertTrue(result["continued"])
        self.assertEqual(result["inactive"], 30 * 60)
        self.assertIn("function overviewDay", script)
        self.assertIn("function dataForInlineTimelineDay", script)
        self.assertIn(
            "preparedTimeline(dataForInlineTimelineDay(data),timelineSelection)",
            script,
        )
        self.assertIn("start=new Date(Math.max(dayBegin,sourceStart))", script)
        self.assertIn("end=new Date(Math.min(dayEnd,sourceEnd))", script)
        self.assertIn('timeline_clipped_start:bounds.continued', script)
        self.assertIn('timeline_continues_next_day:bounds.continues', script)
        self.assertIn("timeline_session_started_at:selected.started_at", script)
        self.assertIn("shortClock(origin)", script)

    def test_kona_today_view_keeps_only_activity_after_midnight(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        lines = script.splitlines()

        def declaration(prefix):
            return next(line for line in lines if line.startswith(prefix))

        source = "\n".join([
            declaration("const total ="),
            "const remoteMode=false,accessibleDevices=[],selectedDeviceId='';",
            "const centralizedMode=()=>false;",
            declaration("function localDay("),
            declaration("function dayStart("),
            declaration("function nextDay("),
            declaration("function overviewDay("),
            declaration("function sessionLimitedUser("),
            declaration("function sessionDeviceName("),
            declaration("function todaySessionBounds("),
            declaration("function metadataForTarget("),
            declaration("function dataForTodaySession("),
            declaration("function sessionsInWindowsSession("),
            r"""
const selected={
  started_at:'2026-08-28T07:11:08+02:00',
  ended_at:'2026-08-29T01:33:35+02:00'
};
const data={
  timeline_now:'2026-08-29T08:17:00+02:00',
  sessions:[
    {kind:'active',key:'app:kona',label:'Kona',started_at:'2026-08-28T22:09:55+02:00',ended_at:'2026-08-28T22:35:46+02:00'},
    {kind:'active',key:'app:kona',label:'Kona',started_at:'2026-08-29T00:05:00+02:00',ended_at:'2026-08-29T00:15:00+02:00'},
    {kind:'active',key:'app:outside',label:'Outside',started_at:'2026-08-29T08:18:00+02:00',ended_at:'2026-08-29T08:19:00+02:00'}
  ],
  merge_candidates:[{key:'app:kona',label:'Kona'}],
  runtime:{windows_identity:{usage_guard_username:'nicklaus'},device:{display_name:'NUC11PHKi7'}}
};
const view=dataForTodaySession(data,selected);
console.log(JSON.stringify({
  seconds:view.usage.find(item=>item.key==='app:kona')?.seconds,
  keys:view.usage.map(item=>item.key),
  dates:[...new Set(view.sessions.map(item=>localDay(item.started_at)))],
  sessionSeconds:view.system.on,
  start:view.session_recording.started_at,
  end:view.timeline_now
}));
""",
        ])
        completed = subprocess.run(
            ["node", "-e", source], check=True, capture_output=True, text=True
        )

        result = json.loads(completed.stdout)
        self.assertEqual(result["seconds"], 600)
        self.assertEqual(result["keys"], ["app:kona"])
        self.assertEqual(result["dates"], ["2026-08-29"])
        self.assertEqual(result["sessionSeconds"], 1 * 3600 + 33 * 60 + 35)
        self.assertTrue(result["start"].startswith("2026-08-28T22:00:00"))
        self.assertTrue(result["end"].startswith("2026-08-28T23:33:35"))

    def test_limit_extension_preserves_the_selected_unit(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        self.assertIn('extension_unit:"minutes"', script)
        self.assertIn("limitDraft.extension_unit=unit", script)
        self.assertIn("extension_unit:limitDraft.extension_unit", script)
        self.assertIn('policy.get("extension_unit", "seconds")', (
            Path(__file__).parents[1] / "app_limiter.py"
        ).read_text(encoding="utf-8"))

    def test_login_and_timeline_omit_redundant_status_banners(self):
        markup = self._markup()
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("Accès administrateur sécurisé", markup)
        self.assertNotIn('id="session-recording"', markup)
        self.assertNotIn("Enregistrement horaire actif", script)
        self.assertNotIn("sessions ouvertes", script)
        self.assertIn('data-tab="today">Activités du jour</button>', markup)
        self.assertNotIn("Dernière session Windows", markup)

    def test_stable_version_is_visible_in_the_header_and_document_title(self):
        markup = self._markup()
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        manifest = (Path(__file__).parents[1] / "pwa" / "manifest.json").read_text(
            encoding="utf-8"
        )
        self.assertEqual(markup.count('class="brand-version">v1.0</span>'), 2)
        self.assertIn("<title>Usage Guard v1.0</title>", markup)
        self.assertIn('document.title=development?`Usage Guard v1.0 ·', script)
        self.assertIn('"name":"Usage Guard v1.0"', manifest)

    def test_today_timeline_uses_usage_guard_start_as_zero(self):
        markup = (Path(__file__).parents[1] / "pwa" / "index.html").read_text(
            encoding="utf-8"
        )
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        style = (Path(__file__).parents[1] / "pwa" / "style.css").read_text(
            encoding="utf-8"
        )
        self.assertIn("function renderRunTimeline", script)
        self.assertIn("Usage Guard démarre", script)
        self.assertIn("ouvert à 0 s", script)
        self.assertIn("absence-share", markup)

        self.assertIn("session-total-legend", markup)
        self.assertIn('id="active-share"></i>', markup)
        self.assertIn('$("#absence-share").title', script)
        self.assertIn("absenceWidth", script)
        self.assertIn("Inactif", script)
        self.assertIn("run-open", script)
        self.assertIn("run-present", script)
        self.assertNotIn("run-inactivity", script)
        self.assertIn('timeline-legend"><span><i class="presence"', script)
        self.assertIn('spans[1].lastChild.textContent="Activité utilisateur"', script)
        self.assertNotIn('class="absence"', script)
        self.assertIn("function timelineAbsencePeriods", script)
        self.assertIn("function timelinePresencePeriods", script)
        self.assertNotIn("function timelinePresenceRow", script)
        self.assertNotIn(".presence-row", style)
        self.assertNotIn(".presence-track", style)
        self.assertIn("function intersectTimelinePeriods", script)
        self.assertIn("openBars=timelinePeriodBars(row.periods", script)
        self.assertIn(
            "rowActivity=timelineTargetActivityPeriods(entries,item.key)", script
        )
        self.assertNotIn(
            "presentWhileOpen=intersectTimelinePeriods(row.periods,presencePeriods)",
            script,
        )
        self.assertIn("${openBars}${presentBars}", script)
        self.assertIn('visibleStart.toLocaleTimeString(pwaLocale(),{hour:"2-digit",minute:"2-digit"})', script)
        self.assertIn('"run-open",`${itemLabel} ouvert`,origin,span,"opened"', script)
        self.assertIn(
            '"run-present",`${itemLabel} · activité utilisateur`,origin,span,"timing"',
            script,
        )
        self.assertIn('tooltipMode==="opened"?opened:title', script)
        self.assertIn('startedBefore?`Déjà ouvert avant ${originTime}`:`Ouvert à ${startedAt}`', script)
        self.assertNotIn("background: var(--presence-color)", style)
        self.assertIn("background: var(--activity-color)", style)
        self.assertNotIn("timeline-inactivity-layer", style)
        self.assertNotIn("timeline-inactivity-band", script)
        self.assertIn('$("#sleep-share").style.width', script)
        self.assertIn('$("#offline-share").style.width', script)
        self.assertIn('data-tree-item="${timelineItemData(item)}"', script)
        self.assertIn("function timelineCategoryPath", script)
        self.assertIn("function decorateTimelineClassification", script)
        self.assertIn("function compactTimelineDuration", script)
        self.assertIn(
            "Ouvert dans cette session : ${duration(openSeconds)} · Activité utilisateur : ${duration(activitySeconds)}",
            script,
        )
        self.assertIn(
            "details.textContent=compactTimelineDuration(activitySeconds)", script
        )
        self.assertIn("details.title=tooltip", script)
        self.assertIn("element.title=tooltip", script)
        self.assertIn(".run-category-row", style)
        self.assertIn("Application ou site ouvert", script)
        self.assertIn('spans[0].lastChild.textContent="Application ouverte, sans activité détectée"', script)
        self.assertIn(".run-open { position: absolute; z-index: 1; top: 7px; height: 12px;", style)
        self.assertIn("background: var(--accent-soft); opacity: .55;", style)
        self.assertIn("Fermé, veille et arrêt : zones sans couleur", script)
        self.assertNotIn("Ouvert, non actif", script)
        self.assertIn('item.kind==="active"', script)
        self.assertIn(
            ".filter(group=>activity.has(group.item.key))", script
        )

    def test_timeline_never_assigns_another_app_activity_to_open_codex(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        start = script.index("function timelineTargetActivityPeriods")
        end = script.index("function renderHistoricalSessions", start)
        source = script[start:end] + """
const entries = [
  {item:{kind:'program',key:'app:chatgpt'},opened:new Date('2026-08-27T08:00:00Z'),closed:new Date('2026-08-27T13:00:00Z')},
  {item:{kind:'active',key:'app:chatgpt'},opened:new Date('2026-08-27T08:00:00Z'),closed:new Date('2026-08-27T09:00:00Z')},
  {item:{kind:'active',key:'app:browser'},opened:new Date('2026-08-27T09:00:00Z'),closed:new Date('2026-08-27T12:00:00Z')}
];
console.log(JSON.stringify(timelineTargetActivityPeriods(entries,'app:chatgpt').map(
  period => [period.item.kind,period.opened.toISOString(),period.closed.toISOString()]
)));
"""
        completed = subprocess.run(
            ["node", "-e", source], check=True, capture_output=True, text=True
        )

        self.assertEqual(
            json.loads(completed.stdout),
            [[
                "active",
                "2026-08-27T08:00:00.000Z",
                "2026-08-27T09:00:00.000Z",
            ]],
        )

    def test_timeline_keeps_activity_when_open_inventory_is_missing(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        start = script.index("function unionTimelineEntries")
        end = script.index("function renderHistoricalSessions", start)
        source = script[start:end] + """
function sessionEntries(sessions,now){return sessions.map(item=>({item,opened:new Date(item.started_at),closed:item.ended_at?new Date(item.ended_at):now}))}
const now = new Date('2026-08-26T14:00:00Z');
const sessions = [
  {kind:'active',key:'app:chatgpt',label:'Codex',started_at:'2026-08-26T08:00:00Z',ended_at:'2026-08-26T08:02:00Z'},
  {kind:'active',key:'app:chatgpt',label:'Codex',started_at:'2026-08-26T10:00:00Z',ended_at:'2026-08-26T10:03:00Z'},
  {kind:'program',key:'app:chatgpt',label:'Codex',started_at:'2026-08-26T13:00:00Z',ended_at:null},
  {kind:'active',key:'app:chatgpt',label:'Codex',started_at:'2026-08-26T13:10:00Z',ended_at:'2026-08-26T13:12:00Z'}
];
const rows=groupedSessionRows(sessionEntries(sessions,now));
console.log(JSON.stringify({
  rows:rows.length,
  periods:rows[0].periods.map(period=>[
    period.opened.toISOString(),period.closed.toISOString()
  ])
}));
"""
        completed = subprocess.run(
            ["node", "-e", source], check=True, capture_output=True, text=True
        )

        result = json.loads(completed.stdout)
        self.assertEqual(result["rows"], 1)
        self.assertEqual(
            result["periods"],
            [
                ["2026-08-26T08:00:00.000Z", "2026-08-26T08:02:00.000Z"],
                ["2026-08-26T10:00:00.000Z", "2026-08-26T10:03:00.000Z"],
                ["2026-08-26T13:00:00.000Z", "2026-08-26T14:00:00.000Z"],
            ],
        )

    def test_timeline_finds_three_hour_absence_while_program_stays_open(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        start = script.index("function timelineAbsencePeriods")
        end = script.index("function timelineSystemPeriods", start)
        source = script[start:end] + """
const origin = new Date('2026-08-21T08:00:00Z');
const end = new Date('2026-08-21T13:00:00Z');
const entries = [
  {item:{kind:'program'},opened:origin,closed:end},
  {item:{kind:'active'},opened:origin,closed:new Date('2026-08-21T09:00:00Z')},
  {item:{kind:'active'},opened:new Date('2026-08-21T12:00:00Z'),closed:end}
];
const absence=timelineAbsencePeriods(entries, origin, end);
console.log(JSON.stringify({
  absence:absence.map(period => (period.end - period.start) / 1000),
  presence:timelinePresencePeriods(absence,origin,end).map(
    period => (period.end - period.start) / 1000
  )
}));
"""
        completed = subprocess.run(
            ["node", "-e", source], check=True, capture_output=True, text=True
        )

        result = json.loads(completed.stdout)
        self.assertEqual(result["absence"], [3 * 60 * 60])
        self.assertEqual(result["presence"], [60 * 60, 60 * 60])

    def test_timeline_highlights_only_presence_inside_application_opening(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        start = script.index("function intersectTimelinePeriods")
        end = script.index("function timelineSystemPeriods", start)
        source = script[start:end] + """
const opened = [{opened:new Date('2026-08-24T08:00:00Z'),closed:new Date('2026-08-24T13:00:00Z')}];
const presence = [
  {start:new Date('2026-08-24T09:00:00Z'),end:new Date('2026-08-24T10:00:00Z')},
  {start:new Date('2026-08-24T12:00:00Z'),end:new Date('2026-08-24T14:00:00Z')}
];
console.log(JSON.stringify(intersectTimelinePeriods(opened,presence).map(
  period => [(period.start-opened[0].opened)/1000,(period.end-period.start)/1000]
)));
"""
        completed = subprocess.run(
            ["node", "-e", source], check=True, capture_output=True, text=True
        )

        self.assertEqual(json.loads(completed.stdout), [[3600, 3600], [14400, 3600]])

    def test_timeline_inactivity_is_shared_across_current_and_analysis_views(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")
        style = (root / "style.css").read_text(encoding="utf-8")

        self.assertNotIn('id="current-activity-state"', markup)
        self.assertIn('id="session-total-track"', markup)
        self.assertIn('data-current-state="Inactif"', markup)
        self.assertIn('data-analysis-type="timeline"', markup)
        self.assertIn('type==="timeline"', script)
        self.assertIn('renderRunTimeline(data,`#analysis-day-timeline-${index}`)', script)
        self.assertNotIn('class="run-row presence-row"', script)
        self.assertIn("${openBars}${presentBars}", script)
        self.assertIn(".run-open", style)
        self.assertIn(".run-present", style)
        self.assertNotIn(".run-inactivity", style)
        self.assertNotIn("timeline-inactivity-layer", script)
        self.assertNotIn(".timeline-inactivity-band", style)
        self.assertIn("percentLabel", script)

    def test_session_chronology_is_below_summary_and_activity_tree_has_own_tab(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")
        style = (root / "style.css").read_text(encoding="utf-8")

        summary_start = markup.index('<div id="session-summary" class="session-summary" hidden aria-hidden="true">')
        summary_end = markup.index("        </div>", summary_start)
        chronology_start = markup.index('<section id="session-chronology" class="session-chronology"')
        self.assertIn('aria-label="Frise chronologique de la session"', markup)
        self.assertNotIn('id="session-chronology-label"', markup)
        self.assertGreater(chronology_start, summary_end)
        self.assertIn(
            '        </div>\n      </div>\n      <section id="session-chronology" class="session-chronology"',
            markup,
        )
        self.assertIn('id="today-sessions"', markup[chronology_start:])
        self.assertNotIn('id="today-sessions"', markup[summary_start:summary_end])
        self.assertNotIn('id="session-chronology-details"', markup)
        self.assertIn(
            'id="today-session-list" class="session-picker" role="listbox" aria-label="Sessions du jour"></div>\n        <div id="session-summary" class="session-summary" hidden aria-hidden="true">',
            markup,
        )
        self.assertIn('<button data-tab="activity-details">Classement</button>', markup)
        details_panel = markup.index('<section id="activity-details" class="panel">')
        usage_tree = markup.index('<div id="today-usage" class="usage-tree"></div>')
        self.assertGreater(usage_tree, details_panel)
        self.assertIn(
            ".session-summary { margin: 2px 0 0;", style
        )
        self.assertIn(".session-chronology { display: grid;", style)
        self.assertIn(".session-chronology .run-timeline { padding: 6px 0 0; border: 0;", style)
        self.assertIn(".session-chronology .run-origin { margin-bottom: 8px; }", style)
        self.assertIn(".run-session-metrics { display: flex;", style)
        self.assertIn(".run-track { position: relative; height: 26px; border-left: 1px solid var(--line);", style)
        self.assertNotIn("box-shadow: inset 4px 0 var(--progress-color)", style)
        self.assertNotIn('id="inline-timeline"', markup)
        self.assertIn("function renderInlineTimeline", script)
        self.assertIn('id="inline-timeline" class="inline-timeline"', script)
        self.assertIn(".inline-timeline", style)
        self.assertIn("if(selector===\"#today-usage\"&&timelineSelection)renderInlineTimeline(state||data)", script)
        self.assertIn('renderTree(catalogState||state,"#today-usage",{catalog:true})', script)
        self.assertIn('renderRunTimeline(view,"#today-sessions")', script)
        self.assertIn("itemLabel=displayLabel(item.key,item.label)", script)
        self.assertIn('tab.dataset.tab==="today")load("scope=today")', script)
        self.assertIn('tab.dataset.tab==="activity-details")loadClassification()', script)

    def test_settings_tab_exposes_language_choice(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")
        style = (root / "style.css").read_text(encoding="utf-8")
        self.assertIn('data-tab="settings"', markup)
        self.assertIn('id="language-choice"', markup)
        self.assertIn('value="auto"', markup)
        self.assertIn('value="fr"', markup)
        self.assertIn('value="en"', markup)
        self.assertIn('action:"set_language"', script)
        self.assertIn('id="theme-choice"', markup)
        self.assertIn('value="dark"', markup)
        self.assertIn('value="light"', markup)
        self.assertIn('usage-guard-theme', script)
        self.assertIn('localStorage.getItem(themeKey)||"light"', script)
        self.assertIn('localStorage.getItem("usage-guard-theme")||"light"', markup)
        self.assertIn('applyTheme(savedTheme)', script)
        self.assertIn('if(systemTheme.addEventListener)', script)
        self.assertIn('else if(systemTheme.addListener)', script)
        self.assertIn('id="color-progress"', markup)
        self.assertNotIn('id="color-absence"', markup)
        self.assertIn('id="color-inactive"', markup)
        self.assertIn('id="color-warning"', markup)
        self.assertIn('usage-guard-ui-colors', script)
        self.assertIn('function applyUiColors', script)
        self.assertIn("--progress-color", style)
        self.assertNotIn("--absence-color", style)
        self.assertIn("--inactive-color", style)
        self.assertIn("--warning-color", style)

    def test_email_configuration_is_in_settings_and_recipient_is_per_rule(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")
        style = (root / "style.css").read_text(encoding="utf-8")

        notifications = markup[markup.index('<section id="notifications"'):markup.index('<section id="settings"')]
        settings = markup[markup.index('<section id="settings"'):]
        self.assertNotIn('id="email-settings-form"', notifications)
        self.assertIn('id="notification-delivery-form"', notifications)
        self.assertIn('value="windows"', notifications)
        self.assertIn('value="email"', notifications)
        self.assertNotIn('value="both"', notifications)
        self.assertIn('getAll("delivery")', script)
        self.assertIn('name="email_recipient"', notifications)
        self.assertNotIn('id="notification-custom-title"', notifications)
        self.assertNotIn('id="notification-custom-message"', notifications)
        self.assertNotIn('data-notification-message=', script)
        self.assertNotIn('messageOnly=false', script)
        self.assertIn('id="email-settings-form"', settings)
        self.assertIn('id="email-message-settings-form"', settings)
        self.assertIn('id="email-message-templates"', settings)
        self.assertIn('Personnalisation des messages', settings)
        self.assertIn('{titre}', settings)
        self.assertIn('{message}', settings)
        self.assertNotIn('id="email-enabled"', settings)
        self.assertNotIn('name="enabled"', settings)
        self.assertIn('id="test-email-settings"', settings)
        self.assertIn('name="smtp_host"', settings)
        smtp_start = settings.index('id="email-settings-form"')
        smtp_form = settings[smtp_start:settings.index('</form>', smtp_start)]
        self.assertNotIn('name="recipient"', smtp_form)
        self.assertNotIn('id="email-message-templates"', smtp_form)
        self.assertIn('id="test-email-settings"', smtp_form)
        message_form = settings[settings.index('id="email-message-settings-form"'):]
        message_form = message_form[:message_form.index('</form>')]
        self.assertIn('id="email-message-templates"', message_form)
        self.assertNotIn('id="test-email-settings"', message_form)
        self.assertIn('function testEmailSettings(recipient)', script)
        self.assertIn('const emailTemplateKinds=', script)
        self.assertIn('function emailMessageSettingsPayload()', script)
        self.assertIn('function saveEmailMessageSettings()', script)
        self.assertIn(
            'renderEmailTemplates(emailSettings?.message_templates||{});loadEmailSettings()',
            script,
        )
        self.assertIn('$("#test-email-settings").onclick', script)
        self.assertIn('channels:[...(current?.channels||["windows"])]', script)
        self.assertIn(
            ".settings-card.email-settings-card { display: grid; grid-template-columns: minmax(0,1fr)",
            style,
        )

    def test_computer_state_and_tampering_notification_choices_are_available(self):
        markup = (Path(__file__).parents[1] / "pwa" / "index.html").read_text(encoding="utf-8")
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(encoding="utf-8")
        self.assertIn('data-notification-type="computer_state"', markup)
        self.assertNotIn('data-notification-type="client_connected"', markup)
        self.assertNotIn('data-notification-type="client_disconnected"', markup)
        self.assertIn('"client_connected","client_disconnected"', script)
        self.assertIn('data-notification-type="protection_interrupted"', markup)
        self.assertIn('"client_disconnected","computer_state","protection_interrupted"', script)
        self.assertNotIn('id="protection-status"', markup)
        self.assertNotIn("function renderProtectionStatus", script)
        self.assertNotIn("Incidents récents", script)

    def test_analysis_exposes_daily_pc_session_hours(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")
        self.assertIn('data-analysis-type="hours"', markup)
        self.assertIn('id="analysis-hours-summary"', markup)
        self.assertIn('id="analysis-hours-list"', markup)
        self.assertIn("function sessionHoursDays", script)
        self.assertIn("function renderSessionHours", script)

    def test_today_sessions_are_one_compact_multidevice_list(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")
        self.assertIn('id="session-summary" class="session-summary" hidden', markup)
        self.assertNotIn('id="today-session-date"', markup)
        self.assertIn('id="today-session-list"', markup)
        self.assertIn('aria-label="Sessions du jour"', markup)
        self.assertIn("function renderTodaySessionPicker", script)
        self.assertIn("function usedTodayWindowsSessions", script)
        self.assertIn("function loadRemoteTodaySessionRows", script)
        self.assertIn("function cachedRemoteTodaySessionData", script)
        self.assertIn("devices.map(async device", script)
        self.assertIn("function groupSessionRowsByUser", script)
        self.assertIn("function todaySessionListEntries", script)
        self.assertIn("function todayDeviceIds", script)
        self.assertIn('identity=`${entry.username} > ${deviceName}`', script)
        self.assertNotIn("entry.username.toLocaleLowerCase()===selectedPolicyUsername", script)
        self.assertNotIn("function todaySessionLanes", script)
        self.assertNotIn('class="session-lane"', script)
        self.assertIn('class="session-list-row', script)
        self.assertIn('class="session-state', script)
        self.assertNotIn('class="session-metrics"', script)
        self.assertNotIn('class="session-identity"', script)
        self.assertIn('status=item.ended_at?"Terminée":"En cours"', script)
        self.assertIn('<span>Début : <b>${esc(timeRange)}</b></span>', script)
        self.assertIn('todaySeconds:Math.max(0,(todayEnd-todayStart)/1000)', script)
        self.assertIn('crossesTodayBoundary=metrics.todaySeconds+1<metrics.seconds', script)
        self.assertIn('timeRange=crossesTodayBoundary?`→ ${item.ended_at?clock(item.ended_at):"maintenant"}`', script)
        self.assertIn('Temps actif : <b>${activeDuration}</b>', script)
        self.assertIn('activeDuration=duration(metrics.presence)', script)
        self.assertIn('function todaySessionCardMetrics', script)
        self.assertIn('measured:sessions.length>0', script)
        style = (root / "style.css").read_text(encoding="utf-8")
        self.assertIn(".session-picker { display: grid; max-height: 240px; overflow: auto", style)
        self.assertIn(".session-picker.device-session-picker { grid-template-columns: minmax(0,1fr); }", style)
        self.assertIn(".session-list-row { display: grid; grid-template-columns:", style)
        self.assertIn("grid-template-columns: 70px minmax(110px,1fr) minmax(125px,.8fr) minmax(105px,.65fr)", style)
        self.assertIn(".session-list-row { grid-template-columns: auto minmax(0,1fr);", style)
        self.assertNotIn(".run-origin { min-width: 600px;", style)
        self.assertIn(".session-list-row .session-duration small", style)
        self.assertIn(".session-state.running", style)
        self.assertIn("function selectedSessionContext", script)
        self.assertIn("sessionLimitedUser(data,selected)", script)
        self.assertIn("sessionDeviceName(data,device)", script)
        self.assertIn("sessionPeriodLabel(selected", script)
        self.assertIn("timeline_person:sessionLimitedUser(data,selected)", script)
        self.assertIn("timeline_device_name:sessionDeviceName(data,device)", script)
        self.assertIn('class="run-session-context"', script)
        self.assertIn('range=sessionStart<origin?`→ ${data.timeline_now?shortClock(end):"maintenant"}`', script)
        self.assertIn("timeline_session_started_at:selected.started_at", script)
        self.assertIn("Temps actif : <b>${duration(activeSeconds)}", script)
        self.assertNotIn("Durée totale <b>", script)
        self.assertNotIn("Passif <b>", script)
        self.assertNotIn("Session Windows démarrée", script)
        self.assertIn('data-today-device=', script)

        self.assertIn("renderOverview(cached,{live:true})", script)
        self.assertIn('load("scope=today",{userInitiated:true})', script)
        self.assertIn("if(options.userInitiated)pendingTodayLoad={query,options}", script)
        self.assertIn("rememberRemoteTodaySessionData(data,requestedDeviceId)", script)
        self.assertIn("if(requestedDeviceId!==selectedDeviceId)return", script)
        self.assertIn('id="today-loading"', markup)
        self.assertIn('id="limits-loading"', markup)
        self.assertIn('Chargement des limites…', markup)
        self.assertIn('limitsProgress=!options.live&&String(query).includes("scope=limits")', script)
        self.assertIn('.panel-loading.compact-loading', style)
        self.assertIn("function completeRemoteTodaySessionRows", script)
        self.assertIn("void completeRemoteTodaySessionRows(data,requestedDeviceId)", script)
        self.assertNotIn("await loadRemoteTodaySessionRows(!remoteTodaySessionRowsAt)", script)
        self.assertIn("centralizedMode()?10000:1000", script)
        self.assertIn('$("#activity-details").classList.contains("active")', script)
        self.assertIn(".panel-loading { display: flex;", style)
        self.assertIn('Aucun usage aujourd’hui.', script)
        self.assertNotIn('`Session ${index+1}`', script)
        self.assertNotIn('id="device-choice"', markup)
        self.assertNotIn('id="device-choice-wrap"', markup)
        self.assertNotIn('$("#device-choice")', script)
        self.assertNotIn('>Session en cours</strong>', markup)
        self.assertIn('id="local-device-name-form"', markup)
        general_start = markup.index('id="general-settings-section"')
        users_start = markup.index('id="users-settings-section"')
        name_form = markup.index('id="local-device-name-form"')
        self.assertGreater(name_form, users_start)
        self.assertNotIn(
            'id="local-device-name-form"', markup[general_start:users_start]
        )
        self.assertIn('function renameLocalDevice', script)
        self.assertIn('/api/v1/backend/device/rename', script)
        self.assertIn('const suggested=deviceDisplayName(device)', script)
        self.assertNotIn('Nom réseau', markup)
        self.assertIn('.today-session-strip { display: grid; grid-template-columns: minmax(0,1fr)', style)
        self.assertIn("multiDay=localDay(start)!==", script)
        self.assertIn("dateTime(start)", script)
        self.assertIn('year:"2-digit"', script)
        self.assertIn("function dataForTodaySession", script)
        self.assertIn('data-today-session', script)
        self.assertNotIn('class="session-measure', markup)
        self.assertIn('id="today-date" hidden', markup)
        self.assertIn('class="session-summary-head"', markup)
        self.assertIn('id="session-end"', markup)
        self.assertIn('moment(started)', script)
        self.assertIn('moment(ended)', script)
        self.assertIn('data-manage-user=', script)
        self.assertIn('/access`', script)
        self.assertIn('Frise chronologique ·', script)

    def test_person_and_computer_scope_matches_each_tab(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")
        style = (root / "style.css").read_text(encoding="utf-8")

        today = markup.split('<section id="today"', 1)[1].split("</section>", 1)[0]
        classification = markup.split('<section id="activity-details"', 1)[1].split("</section>", 1)[0]
        analysis_controls = markup.split('id="analysis-catalog-controls"', 1)[1].split("</form>", 1)[0]

        self.assertNotIn('id="limit-person-choice"', today)
        self.assertNotIn('id="person-device-menu"', today)
        self.assertIn("Catalogue des activités de", classification)
        self.assertIn('id="catalog-person-choice"', classification)
        self.assertNotIn("Toutes les catégories, applications", classification)
        self.assertIn('id="analysis-person-scope-slot"', analysis_controls)
        self.assertLess(
            analysis_controls.index('id="analysis-person-scope-slot"'),
            analysis_controls.index('id="analysis-catalog-start"'),
        )
        self.assertNotIn('id="analysis-history-pagination"', markup)
        self.assertNotIn('id="analysis-load-older"', markup)
        self.assertNotIn('id="remote-local-limit-note"', markup)
        self.assertNotIn('id="limit-person-scope-anchor"', markup)
        self.assertNotIn("Portée des limitations", markup)
        self.assertIn('wrap.hidden=!accessiblePolicyUsers.length||!analysis', script)
        self.assertNotIn('!["analysis","limits"].includes(tabName)', script)
        self.assertIn("analysisSlot?.append(wrap)", script)
        self.assertIn(".analysis-catalog-controls .limit-person-scope{display:contents}", style)
        self.assertIn(".analysis-catalog-controls .person-scope-control>span", style)
        self.assertIn(".analysis-catalog-controls .scope-control-label{display:none}", style)
        self.assertNotIn(".person-view-scope .person-scope-control>span", style)
        self.assertIn(".limit-person-scope { display: grid", style)
        self.assertIn("grid-template-columns: minmax(180px, .7fr) minmax(260px, 1.3fr)", style)
        self.assertIn("summary.textContent=selectedDevices.map(deviceDisplayName).join", script)
        self.assertIn(".person-scope-control { width: 100%; }", style)
        self.assertIn("font-size: 11px; font-weight: 700; line-height: 1.35", style)
        self.assertIn(".analysis-catalog-controls .scope-checklist>summary{font-size:10px;font-weight:800}", style)
        person_device_renderer = script.split(
            "function renderPersonDeviceScope", 1
        )[1].split("function syncSelectedPersonDevice", 1)[0]
        self.assertNotIn("`${count}/${devices.length} ordinateur", person_device_renderer)

    def test_remote_session_rows_scale_and_hide_devices_without_usage(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        start = script.index("function sessionHasUsage")
        end = script.index("function rememberRemoteTodaySessionData", start)
        functions = script[start:end]
        source = """
function todayWindowsSessions(data){return data.windows_sessions||[]}
function sessionsInWindowsSession(data,selected,_choice,now){
  const start=new Date(selected.started_at),end=selected.ended_at?new Date(selected.ended_at):now;
  return (data.sessions||[]).filter(item=>{
    const opened=new Date(item.started_at),closed=item.ended_at?new Date(item.ended_at):now;
    return closed>start&&opened<end;
  });
}
""" + functions + """
const windowSessions=[
  {started_at:"2026-08-24T08:00:00Z",ended_at:"2026-08-24T09:00:00Z",usage_guard_username:"eva"},
  {started_at:"2026-08-24T10:00:00Z",ended_at:"2026-08-24T11:00:00Z",usage_guard_username:"eva"},
  {started_at:"2026-08-24T11:15:00Z",ended_at:"2026-08-24T11:30:00Z",usage_guard_username:"eva"}
];
const active={kind:"active",started_at:"2026-08-24T08:15:00Z",ended_at:"2026-08-24T08:30:00Z"};
const devices=["pc-1","pc-2","pc-3","pc-4"].map(device_id=>({device_id}));
const rows=devices.map((device,index)=>remoteTodaySessionRow(device,{
  timeline_now:"2026-08-24T12:00:00Z",
  windows_sessions:index===0?windowSessions:[{...windowSessions[0],usage_guard_username:index===2?"bob":"eva"}],
  sessions:index===3?[]:index===0?[active,{...active,started_at:"2026-08-24T10:10:00Z",ended_at:"2026-08-24T10:20:00Z"}]:[active]
})).filter(Boolean);
const groups=groupSessionRowsByUser(rows);
console.log(JSON.stringify({
  devices:rows.map(row=>row.device.device_id),
  firstSessions:rows[0].sessions.length,
  users:groups.map(group=>group.username),
  userDevices:groups.map(group=>group.rows.map(row=>row.device.device_id))
}));
"""
        completed = subprocess.run(
            ["node", "-e", source], check=True, capture_output=True, text=True
        )
        result = json.loads(completed.stdout)
        self.assertEqual(result["devices"], ["pc-1", "pc-2", "pc-3"])
        self.assertEqual(result["firstSessions"], 3)
        self.assertEqual(result["users"], ["eva", "bob"])
        self.assertEqual(result["userDevices"], [["pc-1", "pc-2"], ["pc-3"]])

    def test_remote_session_cache_uses_the_device_captured_by_the_request(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        start = script.index("function rememberRemoteTodaySessionData")
        end = script.index("async function loadRemoteTodaySessionRows", start)
        functions = script[start:end]
        source = """
const remoteMode=true;
const centralizedMode=()=>true;
let selectedDeviceId="pc-selected-after-click";
const accessibleDevices=[
  {device_id:"pc-requested",label:"Requested"},
  {device_id:"pc-selected-after-click",label:"Selected"}
];
const remoteTodaySessionRows=[];
function todayDeviceIds(){return accessibleDevices.map(device=>device.device_id)}
function remoteTodaySessionRow(device,data){return {device,data,sessions:data.sessions}}
""" + functions + """
const requestedData={sessions:[{started_at:"2026-08-24T08:00:00Z"}]};
rememberRemoteTodaySessionData(requestedData,"pc-requested");
console.log(JSON.stringify({
  storedDevice:remoteTodaySessionRows[0].device.device_id,
  requestedIsCached:cachedRemoteTodaySessionData("pc-requested")===requestedData,
  selectedIsEmpty:cachedRemoteTodaySessionData("pc-selected-after-click")===null
}));
"""
        completed = subprocess.run(
            ["node", "-e", source], check=True, capture_output=True, text=True
        )
        result = json.loads(completed.stdout)
        self.assertEqual(result["storedDevice"], "pc-requested")
        self.assertTrue(result["requestedIsCached"])
        self.assertTrue(result["selectedIsEmpty"])

    def test_pending_limit_commands_are_shown_only_in_the_sync_dialog(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        style = (Path(__file__).parents[1] / "pwa" / "style.css").read_text(
            encoding="utf-8"
        )

        self.assertNotIn("pending_limit_commands", script)
        self.assertNotIn("En attente de récupération par le PC", script)
        self.assertIn("Serveur confirmé, attente des PC", script)
        self.assertIn("Commande récupérée, application en cours", script)
        self.assertNotIn("pending-sync", style)

    def test_session_list_is_compact_and_reconciles_stale_offline_rows(self):
        root = Path(__file__).parents[1]
        script = (root / "pwa" / "app.js").read_text(encoding="utf-8")
        style = (root / "pwa" / "style.css").read_text(encoding="utf-8")

        self.assertNotIn(".session-lane { display: grid;", style)
        self.assertIn("max-height: 240px; overflow: auto", style)
        self.assertIn("min-height: 38px; padding: 5px 9px", style)
        self.assertIn("data.offline&&!item.ended_at", script)
        self.assertIn(
            "!sessions.some(item=>item.started_at===fallback.started_at)",
            script,
        )
        self.assertNotIn(
            "item.started_at===fallback.started_at&&!item.ended_at", script,
        )
        self.assertIn("sameSid=item.windows_sid", script)
        self.assertIn("accessibleDevices.find(candidate=>candidate.device_id===deviceId)||row.device", script)

    def test_device_cards_show_only_limited_user_assignments(self):
        script = (
            Path(__file__).parents[1] / "pwa" / "app.js"
        ).read_text(encoding="utf-8")

        self.assertIn(
            'remoteUsers.filter(user=>userRole(user)==="limited"', script,
        )
        self.assertIn('owner=assigned.length?assigned.join(", "):"non affecté"', script)
        self.assertIn('class="device-owner-path"', script)
        devices_start = script.index("function renderAdminDevices")
        devices_end = script.index("async function loadAdminUsers", devices_start)
        devices = script[devices_start:devices_end]
        self.assertNotIn('device.online', devices)

    def test_analysis_timeline_selects_a_day_then_uses_the_shared_target_picker(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")
        self.assertIn('id="analysis-day-menu"', markup)
        self.assertIn('id="analysis-timeline-target-menu"', markup)
        self.assertNotIn('id="analysis-session-menu"', markup)
        self.assertNotIn('id="analysis-classification-menu"', markup)
        self.assertIn("function analysisTimelineDays", script)
        self.assertIn("function windowsSessionsForDay", script)
        self.assertIn('startTargetSelector("analysis-timeline")', script)
        self.assertIn('targetSelectorOwner==="analysis-timeline"', script)
        self.assertIn('data-analysis-day="${day}"', script)
        self.assertNotIn("data-analysis-session-index", script)
        self.assertNotIn("data-analysis-choice-index", script)
        self.assertIn("renderSelectedAnalysis", script)

    def test_current_state_segment_pulses_while_the_edge_label_stays_fixed(self):
        style = (Path(__file__).parents[1] / "pwa" / "style.css").read_text(
            encoding="utf-8"
        )
        self.assertIn('.session-total-track.active::before { left: 4px;', style)
        self.assertIn('.session-total-track.inactive::before { right: 4px;', style)
        self.assertIn('.session-total-track.active > #active-share { animation: active-segment-pulse', style)
        self.assertNotIn('.session-total-track.inactive > #absence-share { animation:', style)
        self.assertIn('@keyframes active-segment-pulse', style)
        self.assertNotIn('@keyframes inactive-segment-pulse', style)
        self.assertNotIn('animation: current-state-pulse', style)
        self.assertNotIn('border: 1px solid rgba(255,255,255,.85)', style)
        self.assertIn('content: "●  " attr(data-current-state)', style)

    def test_finished_sessions_never_pulse_and_offline_details_require_a_click(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")
        self.assertIn('id="session-summary"', markup)
        self.assertIn('id="session-chronology"', markup)
        self.assertIn('currentActive=selectedCurrent&&isActive', script)
        self.assertIn('currentState=selectedCurrent?', script)
        self.assertIn(':"Terminée"', script)
        self.assertIn('todaySessionExplicitlySelected=true', script)
        self.assertIn('function activeRemoteTodaySessionEntry', script)
        self.assertIn('if(!todaySessionExplicitlySelected){const active=activeRemoteTodaySessionEntry(rows)', script)
        self.assertIn('todaySessionExplicitlySelected?sessions.find', script)
        self.assertIn('todaySessionExplicitlySelected=false;selectedTodaySessionKey=""', script)
        self.assertIn('$("#session-summary").hidden=true', script)
        self.assertIn('$("#session-chronology").hidden=!visible', script)
        self.assertIn('visibleRemoteTodaySessionRows().some(row=>!row.data?.offline)', script)
        self.assertIn('if(state?.offline||!state?.current?.is_counted)return false', script)

    def test_timeline_distinguishes_inactivity_sleep_and_offline_periods(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")
        style = (root / "style.css").read_text(encoding="utf-8")
        self.assertIn('id="sleep-share"', markup)
        self.assertIn('id="offline-share"', markup)
        self.assertIn("function timelineSystemPeriods", script)
        self.assertIn('event.type==="sleep"', script)
        self.assertIn('event.type==="shutdown"', script)
        self.assertIn('event.type==="tracking_gap"', script)
        self.assertNotIn(".run-system-state.sleep", style)
        self.assertNotIn(".run-system-state.offline", style)
        self.assertIn(".run-open", style)
        self.assertIn(".run-present", style)

    def test_power_periods_keep_sleep_shutdown_and_tracking_gap_distinct(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        start = script.index("function timelineSystemPeriods")
        end = script.index("function periodsMilliseconds", start)
        source = script[start:end] + """
const origin = new Date('2026-08-21T08:00:00Z');
const end = new Date('2026-08-21T14:00:00Z');
const events = [
  {type:'sleep',at:'2026-08-21T09:00:00Z'},
  {type:'resume',at:'2026-08-21T10:00:00Z'},
  {type:'shutdown',at:'2026-08-21T11:00:00Z'},
  {type:'guard_start',at:'2026-08-21T12:00:00Z'},
  {type:'tracking_gap',at:'2026-08-21T13:00:00Z',ended_at:'2026-08-21T13:30:00Z'}
];
console.log(JSON.stringify(timelineSystemPeriods(events, origin, end).map(
  period => [period.kind, (period.end - period.start) / 1000]
)));
"""
        completed = subprocess.run(
            ["node", "-e", source], check=True, capture_output=True, text=True
        )

        self.assertEqual(json.loads(completed.stdout), [
            ["sleep", 3600], ["offline", 3600], ["unavailable", 1800]
        ])

    def test_analysis_offers_period_statistics_for_apps_and_categories(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")

        self.assertIn('id="analysis-stats-target-menu"', markup)
        self.assertIn('data-stats-period="today"', markup)
        self.assertIn('id="analysis-stats-start" type="date"', markup)
        self.assertIn('id="analysis-stats-end" type="date"', markup)
        self.assertIn('id="analysis-stats-summary"', markup)
        self.assertIn('id="analysis-stats-chart"', markup)
        self.assertIn("function buildStatsChoices", script)
        self.assertIn("function computerStatsChoice", script)
        self.assertIn("function statsChoiceAt", script)
        self.assertIn('targetKey==="computer:all"?-1', script)
        self.assertNotIn('return [{kind:"computer",key:"computer:all",label:"Tout l’ordinateur"', script)
        self.assertIn("function categoryLineage", script)
        self.assertIn("data.top_level_categories||[]", script)
        self.assertIn("categoryLineage(analysisHistory||{},category)", script)
        self.assertNotIn(".filter(used)", script)
        self.assertIn("function renderAnalysisStats", script)
        self.assertIn("Moyenne par jour", script)

    def test_zero_usage_items_are_available_in_a_collapsed_inactive_group(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )

        self.assertIn("function displayedTreeChildren", script)
        self.assertIn("function orderTreeByUsage(nodes,data)", script)
        self.assertIn("return positionClassificationRoots(orderTreeByUsage(roots,data),data)", script)
        self.assertIn('reorderSlots(ordered,"category",data.category_order)', script)
        self.assertIn('if(data.site_category_order_manual)', script)
        self.assertIn("reorderTargetSlots(ordered,data.target_order)", script)
        self.assertIn('`Inactifs (${inactive.length})`', script)
        self.assertIn('otherSites=String(parentId).startsWith("other-sites:")', script)
        self.assertIn('node.kind==="inactive"?!collapsedTreeNodes.has(node.id)', script)
        self.assertIn('const structuralTreeKinds=new Set(["category"', script)

    def test_remote_settings_are_reserved_for_administrators(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")

        self.assertIn('id="general-settings-section"', markup)
        self.assertIn('id="users-settings-section"', markup)
        self.assertIn('id="defaults-settings-section"', markup)
        self.assertIn('id="settings-menu"', markup)
        self.assertIn('data-settings-page="users"', markup)
        self.assertIn('function openSettingsPage(page)', script)
        self.assertIn(
            'visible={general:true,defaults:isAdmin,users:isAdmin', script,
        )
        self.assertIn('return Boolean(authState?.permissions?.[permission])', script)
        self.assertIn('if(!hasAccess("manage_activity"))return', script)
        self.assertIn('load("scope=limits")', script)
        self.assertNotIn('id="remote-account"', markup)
        self.assertNotIn('id="account-email-form"', markup)
        self.assertNotIn('id="password-form"', markup)
        self.assertIn('id="first-email-form"', markup)
        self.assertIn('authState?.must_set_email', script)
        self.assertIn('loadAdminToken()', script)
        self.assertIn('Number(saved.expires_at)*1000>Date.now()', script)
        self.assertIn('headers["X-Usage-Guard-Admin"]=adminToken', script)
        self.assertIn('if(!adminToken){showLogin();return false}', script)
        self.assertIn('localWindowsUsername=String(bootstrap.windows_username||"")', script)
        self.assertIn('loginPassword.required=!windowsLogin', script)
        self.assertIn('<label>Mot de passe<input name="password"', markup)
        self.assertNotIn('Mot de passe Usage Guard', markup)

    def test_web_targets_use_a_badge_instead_of_a_duplicate_browser_category(self):
        root = Path(__file__).parents[1] / "pwa"
        script = (root / "app.js").read_text(encoding="utf-8")
        style = (root / "style.css").read_text(encoding="utf-8")

        self.assertIn('web:item.web||String(item.key||"").startsWith("site:")', script)
        self.assertIn('<span class="web-badge">Web</span>', script)
        self.assertIn("function displayLabel", script)
        self.assertIn('value.startsWith("site:")', script)
        self.assertIn('return host||raw||value', script)
        self.assertIn('label:"Navigation Internet"', script)
        self.assertIn("function isBareBrowserApplication(item,data)", script)
        self.assertIn("function isLegacyBrowserSiteCategory(item,data)", script)
        self.assertIn("function browserApplicationUsageItem(item,data)", script)
        self.assertIn("function timelineDisplayEntries(entries,data)", script)
        self.assertIn("legacyBrowserCategory?\"\":item.category", script)
        self.assertIn(".web-badge", style)

        helpers_start = script.index("function isBrowserEntry")
        helpers_end = script.index("function siteTreeCategory", helpers_start)
        timeline_start = script.index("function subtractTimelineEntries")
        timeline_end = script.index("function unionTimelineEntries", timeline_start)
        functions = script[helpers_start:helpers_end] + script[timeline_start:timeline_end]
        source = f"""
{functions}
const site={{key:"site:brave.exe:youtube.com",label:"youtube.com",seconds:600,category:"Brave",category_scope:"site"}};
const app={{key:"app:brave.exe",label:"Brave",seconds:600,category:"Brave"}};
const data={{browsers:[{{browser:"brave.exe",label:"Brave"}}],usage:[app,site]}};
const at=value=>new Date(`2026-08-27T10:${{value}}:00Z`);
const entry=(key,kind,from,to)=>({{item:{{key,kind,label:key}},opened:at(from),closed:at(to)}});
const covered=timelineDisplayEntries([entry("app:brave.exe","active","00","10"),entry("site:brave.exe:youtube.com","active","00","10")],data);
const partial=timelineDisplayEntries([entry("app:brave.exe","active","00","10"),entry("site:brave.exe:youtube.com","active","00","08")],data);
console.log(JSON.stringify({{
  legacyIsNavigation:isBrowserEntry(site,data),
  explicitCategoryIsNavigation:isBrowserEntry({{...site,category:"Recherche"}},data),
  coveredUsage:browserApplicationUsageItem(app,data),
  residualUsage:browserApplicationUsageItem({{...app,seconds:900}},{{...data,usage:[{{...app,seconds:900}},site]}})?.seconds,
  coveredBrowserRows:covered.filter(item=>item.item.key==="app:brave.exe").length,
  residualSeconds:partial.filter(item=>item.item.key==="app:brave.exe").reduce((sum,item)=>sum+(item.closed-item.opened)/1000,0),
}}));
"""
        completed = subprocess.run(
            ["node", "-e", source], check=True, capture_output=True, text=True
        )
        result = json.loads(completed.stdout)
        self.assertTrue(result["legacyIsNavigation"])
        self.assertFalse(result["explicitCategoryIsNavigation"])
        self.assertIsNone(result["coveredUsage"])
        self.assertEqual(result["residualUsage"], 300)
        self.assertEqual(result["coveredBrowserRows"], 0)
        self.assertEqual(result["residualSeconds"], 120)

    def test_live_activity_highlight_pulses_apps_and_parent_categories(self):
        root = Path(__file__).parents[1] / "pwa"
        style = (root / "style.css").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")
        self.assertIn(".tree-row.current-activity", style)
        self.assertIn("current-activity-pulse", style)
        self.assertIn("function nodeHasCurrentActivity(node)", script)
        self.assertIn(".some(nodeHasCurrentActivity)", script)

    def test_create_user_dialog_offers_the_three_account_roles(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")
        self.assertIn('limited:"Utilisateur à limiter"', script)
        self.assertIn('user:"Utilisateur"', script)
        self.assertIn('admin:"Administrateur"', script)
        self.assertNotIn('managerAssignmentFields', script)
        self.assertNotIn('managed_usernames', script)
        self.assertNotIn('Droits du responsable', script)
        self.assertNotIn('limitedDeniedAccessKeys', script)
        self.assertNotIn('data-limited-denied-permission', script)
        self.assertIn('manage_limits:"Créer et modifier des limitations"', script)

        self.assertIn('manage_other_limits:"Modifier/désactiver les limitations demandées par d’autres"', script)
        self.assertIn('name="${key}"', script)
        self.assertIn('Toutes les personnes, tous les ordinateurs et tous les droits sont accordés automatiquement.', script)
        self.assertIn('name="person_username"', script)
        self.assertIn('person_usernames:form.getAll("person_username")', script)
        self.assertIn('data-admin-manage-user', script)
        self.assertIn('name="role"', script)
        self.assertIn('is_admin:wantsAdmin', script)
        self.assertIn('toast(`${roleLabels[role]||"Utilisateur"} créé`)', script)
        self.assertIn("wantsAdmin&&!created?.user?.is_admin", script)
        self.assertIn("Le serveur n’a pas confirmé les droits administrateur.", script)

    def test_user_access_editor_uses_two_compact_checkbox_lists(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")
        style = (root / "style.css").read_text(encoding="utf-8")

        fields_start = script.index("function personAssignmentFields")
        fields_end = script.index("function accessPermissionFields", fields_start)
        fields = script[fields_start:fields_end]
        people = fields.index("Utilisateurs à limiter")
        computers = fields.index("Ordinateurs")
        self.assertLess(people, computers)
        self.assertIn('class="person-option-list scope-checklist-options"', script)
        self.assertIn('class="device-option-list scope-checklist-options"', script)
        self.assertIn('class="access-scope-lists limit-person-scope"', script)
        self.assertIn('<details class="scope-checklist">', fields)
        self.assertIn('saved.length?saved:people.map(person=>person.username)', fields)
        self.assertIn('saved.length?saved:remoteDevices.map(device=>device.device_id)', fields)
        permissions_start = script.index("function userAccessEditor")
        permissions_end = script.index("function refreshAccessCounts", permissions_start)
        permissions = script[permissions_start:permissions_end]
        self.assertLess(permissions.index("Autorisations"), permissions.index("access-scope-lists"))
        self.assertLess(permissions.index("access-scope-lists"), permissions.index("access-grid"))
        self.assertIn(".scope-checklist-options", style)
        self.assertIn("max-height: 240px", style)
        self.assertIn("overflow-y: auto", style)
        self.assertIn("function closeScopeChecklists", script)
        self.assertIn('event.target.closest(".scope-checklist")', script)
        self.assertIn('menu.removeAttribute("open")', script)
        self.assertIn('class="admin-management"', markup)
        admin_start = markup.index('<div id="admin-user-management"')
        admin_end = markup.index('<div id="local-user-management"', admin_start)
        admin = markup[admin_start:admin_end]
        self.assertLess(markup.index('<h2 id="users-settings-title">Utilisateurs</h2>'), admin_start)
        self.assertNotIn("Administration", admin)
        self.assertEqual(admin.count("Utilisateurs"), 0)
        self.assertEqual(admin.count("Ordinateurs"), 1)
        self.assertIn('<h2 class="admin-section-title">Ordinateurs</h2>', admin)
        self.assertIn('id="admin-users"', admin)
        self.assertIn('id="admin-devices"', admin)
        self.assertLess(admin.index("Ordinateurs"), admin.index("Installer ou réinstaller un ordinateur"))
        self.assertNotIn('id="admin-user-choice"', admin)
        self.assertNotIn('id="admin-device-choice"', admin)
        self.assertNotIn("personne", admin.lower())
        admin_function_start = script.index("function renderAdminUsers")
        admin_function_end = script.index("function renderAdminDevices", admin_function_start)
        admin_function = script[admin_function_start:admin_function_end]
        self.assertNotIn("personCount", admin_function)
        self.assertNotIn("permissionCount", admin_function)
        self.assertNotIn("user.email", admin_function)
        self.assertIn("roleLabel(user)", admin_function)
        self.assertIn(".admin-management { display: grid; gap: 0; width: min(100%,720px)", style)
        self.assertIn(".admin-section-title { margin: 18px 0 9px; font-size: 16px; }", style)
        self.assertIn(".device-owner-path", style)
        self.assertIn("function mergedClassificationCatalog", script)
        self.assertIn("function overviewWithClassificationCatalog", script)
        self.assertIn("const sharedCatalog=await mergedClassificationCatalog();data=overviewWithClassificationCatalog(data,sharedCatalog)", script)
        self.assertIn("_classification_catalog:catalog", script)
        self.assertIn("function timelineClassificationData(data)", script)
        self.assertIn("const classificationData=timelineClassificationData(data)", script)
        self.assertIn("targetRanks=timelineTargetRanks(classificationData)", script)
        self.assertIn("timelineCategoryPath(classificationData,row.item)", script)
        self.assertIn("timelineClassificationOrder(classificationData", script)

    def test_analysis_keeps_apps_inside_their_windows_session(self):
        root = Path(__file__).parents[1] / "pwa"
        script = (root / "app.js").read_text(encoding="utf-8")
        style = (root / "style.css").read_text(encoding="utf-8")
        self.assertIn("sessionsInWindowsSession", script)
        self.assertIn("opened<start", script)
        self.assertIn("opened>=end", script)
        self.assertIn("closed>end", script)
        self.assertIn("group.periods=unionTimelineEntries", script)
        self.assertNotIn("renderEventTimeline", script)
        self.assertIn("renderAllRunTimeline(prepared.data,selector)", script)
        self.assertNotIn("renderEventTimeline", script)
        self.assertIn("current-activity", script)
        self.assertIn("currentActivityMatches(item.key,item.label)", script)
        self.assertIn("state.current.site_host||state.current.url", script)
        self.assertIn("targetSiteHost(targetKey)", script)
        self.assertIn("refreshAnalysisActivity()", script)
        self.assertIn("function historyDayMarkup", script)
        self.assertIn("const historyBarMaxHeight = 58", script)
        self.assertIn("*historyBarMaxHeight", script)
        self.assertIn("height: 132px; min-height: 0; max-height: 132px", style)
        self.assertIn("padding: 7px 12px 18px 8px", style)
        self.assertIn("scrollbar-gutter: stable", style)
        self.assertIn("flex: 0 0 104px; min-width: 104px", style)
        self.assertIn("grid-template-rows: auto 64px auto", style)
        self.assertRegex(script, r'service-worker\.js\?v=\d+\.\d{3}')
        self.assertIn('scopeDuplicateIds(node,parentId)', script)
        self.assertIn('Sites spécifiques inactifs', script)
        self.assertIn('refreshBrowserTotals(node)', script)
        self.assertIn('function updateDragScroll(clientY)', script)
        self.assertIn('requestAnimationFrame(dragScrollStep)', script)
        self.assertIn('updateDragScroll(event.clientY)', script)
        self.assertIn('item.kind==="other-sites"&&item.target_keys', script)
        self.assertIn('target_keys:[...other.map(item=>item.key),...direct.map', script)
        self.assertIn('action:"reorder_category"', script)
        self.assertIn('draggedCategoryBefore', script)
        self.assertIn('drop-before', script)
        self.assertIn('data-category-position=', script)
        self.assertIn('data-site-category-position=', script)
        self.assertIn('data-target-position=', script)
        self.assertIn('data-navigation-position', script)
        self.assertIn('data-unclassified-position', script)
        self.assertIn('Déplacer la catégorie', script)
        self.assertIn('function categoryPositionDialog(category)', script)
        self.assertIn('function siteCategoryPositionDialog(category)', script)
        self.assertIn('function targetPositionDialog(targetKey)', script)
        self.assertIn('action:"reorder_site_category"', script)
        self.assertIn('action:"reorder_target"', script)
        self.assertIn('action:"reorder_navigation"', script)
        self.assertIn('action:"reorder_unclassified"', script)
        self.assertIn('function navigationPositionDialog()', script)
        self.assertIn('function unclassifiedPositionDialog()', script)
        self.assertIn('"reorder_site_category"', (
            Path(__file__).parents[1] / "usage_guard_backend" / "server.py"
        ).read_text(encoding="utf-8"))
        self.assertIn('Choisir la position…', script)
        self.assertIn('Avant « ${destination} »', script)
        self.assertIn('Après « ${destination} »', script)
        self.assertIn("function timelineTargetRanks(data)", script)
        self.assertIn("targetRanks.get(row.item.key)", script)
        self.assertIn("details.textContent=compactTimelineDuration(activitySeconds)", script)
        self.assertIn(".tree-row.branch { grid-template-columns: 22px 22px", style)
        self.assertIn("font-variant-numeric: tabular-nums; white-space: nowrap", style)
        self.assertIn(
            ".analysis-catalog-row:not(.header) > span:not(.catalog-identity) { font-size: 12px; }",
            style,
        )
        self.assertIn('Monter dans l’affichage', script)
        self.assertIn('Descendre dans l’affichage', script)
        self.assertNotIn('function categoryMoveDialog', script)
        self.assertIn('translateY(${localDelta}px)', script)
        self.assertIn('style="height:${height}px"', script)
        self.assertIn('style="left:${left}%;width:${width}%"', script)

    def test_root_ordering_accepts_special_branches_and_keeps_classification(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        lines = script.splitlines()
        functions = "\n".join(
            next(line for line in lines if line.startswith(f"function {name}"))
            for name in (
                "rootOrderKey", "rootAnchor", "rootOrderCommands",
                "displayMoveActions", "treeOrderingDropKind",
            )
        )
        source = f"""
const orderingData=()=>({{}});
const targetSiblingItems=()=>[];
{functions}
const data={{category_parents:{{}}}};
const items=[
  {{key:"navigation",kind:"browser",category:"",label:"Navigation Internet"}},
  {{key:"unclassified",kind:"category",category:"Applications non classées",label:"Applications non classées"}},
  {{key:"category:Programmation+ChatGPT",kind:"category",category:"Programmation+ChatGPT",label:"Programmation+ChatGPT"}},
  {{key:"category:Divertissement",kind:"category",category:"Divertissement",label:"Divertissement"}},
];
const commands=rootOrderCommands(
  data,items,"category:Programmation+ChatGPT","navigation",true
);
const keys={{"Programmation+ChatGPT":"category:Programmation+ChatGPT","Divertissement":"category:Divertissement","Applications non classées":"unclassified"}};
const rendered=["category:Programmation+ChatGPT","category:Divertissement","unclassified","navigation"];
for(const command of commands){{
  const source=command.action==="reorder_navigation"?"navigation":"unclassified";
  const sourceIndex=rendered.indexOf(source);
  if(sourceIndex>=0)rendered.splice(sourceIndex,1);
  const destination=rendered.indexOf(keys[command.destination]);
  rendered.splice(destination+(command.before?0:1),0,source);
}}
const moves=displayMoveActions(2,4,()=>{{}}).map(item=>item.label);
console.log(JSON.stringify({{
  commands,rendered,moves,
  navigationDrop:treeOrderingDropKind(
    {{kind:"category",category:"Programmation+ChatGPT"}},
    {{kind:"browser"}},data
  ),
  unclassifiedDrop:treeOrderingDropKind(
    {{kind:"category",category:"Programmation+ChatGPT"}},
    {{kind:"category",category:"Applications non classées"}},data
  ),
  nestedDrop:treeOrderingDropKind(
    {{kind:"category",category:"Programmation+ChatGPT"}},
    {{kind:"category",category:"Enfant"}},
    {{category_parents:{{Enfant:"Divertissement"}}}}
  )
}}));
"""
        completed = subprocess.run(
            ["node", "-e", source], capture_output=True, text=True,
            encoding="utf-8", check=True
        )
        result = json.loads(completed.stdout)

        self.assertEqual(
            [command["action"] for command in result["commands"]],
            ["reorder_unclassified", "reorder_navigation"],
        )
        self.assertNotIn("reorder_category", {
            command["action"] for command in result["commands"]
        })
        self.assertEqual(result["rendered"], [
            "category:Programmation+ChatGPT", "navigation", "unclassified",
            "category:Divertissement",
        ])
        self.assertEqual(result["moves"], [
            "Monter dans l’affichage", "Descendre dans l’affichage",
        ])
        self.assertEqual(result["navigationDrop"], "root")
        self.assertEqual(result["unclassifiedDrop"], "root")
        self.assertEqual(result["nestedDrop"], "")
        self.assertIn('draggable:true,children', script)
        self.assertIn(
            "if(centralizedMode()){await wait(1400);try{await loadPolicyScope()}",
            script,
        )
        self.assertNotIn(
            'confirm("Fusionner ces deux activités et déplacer tout l’historique ?")',
            script,
        )

    def test_analysis_summary_defaults_to_the_classification_order(self):
        root = Path(__file__).parents[1] / "pwa"
        script = (root / "app.js").read_text(encoding="utf-8")
        style = (root / "style.css").read_text(encoding="utf-8")

        self.assertIn('summary: {key:"classification", direction:1}', script)
        self.assertIn("function analysisClassificationRanks", script)
        self.assertIn('data-analysis-sort-key="classification"', script)
        self.assertIn("Ordre du classement", script)
        self.assertIn("usage-guard-analysis-catalog-v2:", script)
        self.assertIn(".analysis-classification-order", style)

    def test_notification_center_offers_the_requested_events(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")
        style = (root / "style.css").read_text(encoding="utf-8")
        self.assertIn('data-tab="notifications"', markup)
        self.assertIn('id="notifications-list"', markup)
        requested = (
            ("limit_change", "Limite ajoutée ou modifiée"),
            ("limit_warning", "Préavis avant limite"),
            ("limit_reached", "Limite atteinte"),
            ("pwa_login", "Connexion à l’interface de gestion"),
            ("access_change", "Changement de droits d’un utilisateur"),
            ("computer_state", "Ordinateur allumé, éteint ou en veille"),
            ("usage_threshold", "Programme, site ou catégorie utilisé"),
            ("protection_interrupted", "Tentative de bidouille"),
        )
        positions = []
        for kind, label in requested:
            marker = f'data-notification-type="{kind}"'
            self.assertIn(marker, markup)
            self.assertIn(f"<strong>{label}</strong>", markup)
            positions.append(markup.index(marker))
        self.assertEqual(positions, sorted(positions))
        for legacy_kind in (
            "limited_app_start", "limit_extension", "computer_block_change",
            "client_connected", "client_disconnected", "startup_reminder",
        ):
            self.assertNotIn(f'data-notification-type="{legacy_kind}"', markup)
        self.assertNotIn('data-notification-type="computer_block_warning"', markup)
        self.assertNotIn('id="notification-status-menu"', markup)
        self.assertNotIn('data-notification-status=', markup)
        self.assertIn('notificationDraft.target_key="";saveNotificationDraft(true)', script)
        self.assertIn('set_notification_warning', script)
        self.assertIn('manage_notifications', script)
        self.assertNotIn('id="notification-device-scope"', markup)
        self.assertNotIn('name="notification_device_id"', script)
        self.assertIn('function loadNotificationScope()', script)
        self.assertIn('function notificationTargetDeviceIds()', script)
        self.assertIn('function synchronizedNotificationAction(command', script)
        self.assertIn('targets.map((deviceId,index)=>api("/api/v1/actions"', script)
        self.assertIn('owner:selectedNotificationOwner||authState?.username||""', script)
        self.assertIn('selectedNotificationOwner="";showApp()', script)
        self.assertNotIn(
            'localStorage.getItem("usage-guard-notification-owner")', script,
        )
        self.assertIn(
            '!hasAccess("manage_notifications")', script,
        )
        self.assertNotIn('function notificationDeviceAssignment', script)
        self.assertIn('Promise.allSettled(targets.map(deviceId=>api(`/api/v1/overview?scope=notifications', script)
        self.assertIn('id="notifications-loading"', markup)
        self.assertIn("Chargement des notifications…", markup)
        self.assertIn("const revision=++notificationLoadRevision", script)
        self.assertIn("if(progress)progress.hidden=false", script)
        self.assertIn("if(revision===notificationLoadRevision&&progress)progress.hidden=true", script)
        self.assertIn('id="notification-login-role-menu"', markup)
        self.assertIn('data-notification-login-role="users"', markup)
        self.assertIn('data-notification-login-role="admins"', markup)
        self.assertIn('data-notification-login-role="both"', markup)
        self.assertIn('login_role_scope:current?.login_role_scope||"both"', script)
        self.assertIn('showNotificationLoginRoles()', script)

        self.assertIn('rule.kind==="access_change"', script)
        self.assertNotIn('name="warning"', script)
        self.assertIn('id="limit-target-menu"', markup)
        self.assertIn('startTargetSelector("limit")', script)
        self.assertIn('function targetHierarchy()', script)
        self.assertIn('data-target-select="computer:all"', script)
        self.assertIn('Catégories / applications / Internet / multimédia', script)
        self.assertIn('key.endsWith(":other-sites")', script)
        self.assertIn('Rechercher et choisir un usage précis', script)
        self.assertIn('data-limit-basis="duration"', script)
        self.assertIn('data-limit-basis="date"', script)
        self.assertIn('data-limit-periodicity="one-time"', script)
        self.assertIn('data-limit-periodicity="permanent"', script)
        self.assertIn('<strong>Ponctuelle</strong>', script)
        self.assertIn('<strong>Permanente</strong>', script)
        self.assertIn('<strong>Durée</strong>', script)
        self.assertIn('<strong>Créneau date/heure</strong>', script)
        self.assertIn('<strong>Tout l’ordinateur</strong><small>Cible globale</small>', script)
        self.assertIn('<strong>Catégories / applications / Internet / multimédia</strong><small>Rechercher et choisir un usage précis</small>', script)
        self.assertIn('function rootCategoryTags', script)
        self.assertIn('class="target-tags"', script)
        self.assertIn('class="target-entry"', script)

    def test_notifications_aggregate_every_device_for_the_selected_person(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        lines = script.splitlines()
        functions = "\n".join(
            next(line for line in lines if line.startswith(f"function {name}"))
            for name in (
                "notificationDeviceCandidates",
                "notificationTargetDeviceIds",
                "notificationRuleMergeKey",
                "mergeNotificationScopes",
            )
        )
        source = f"""
let selectedNotificationOwner="nicklaus";
const authState={{username:"admin"}};
const notificationScopeUsers=[{{username:"nicklaus",device_ids:["pc-1","pc-2"]}}];
const notificationScopeDevices=[{{device_id:"pc-1"}},{{device_id:"pc-2"}}];
{functions}
const merged=mergeNotificationScopes([
  {{notification_rules:[]}},
  {{notification_rules:[{{id:"rule-1",owner:"nicklaus"}}]}},
],["pc-1","pc-2"]);
console.log(JSON.stringify({{devices:notificationTargetDeviceIds(),rules:merged.notification_rules}}));
"""
        completed = subprocess.run(
            ["node", "-e", source], check=True, capture_output=True, text=True
        )
        result = json.loads(completed.stdout)
        self.assertEqual(result["devices"], ["pc-1", "pc-2"])
        self.assertEqual([rule["id"] for rule in result["rules"]], ["rule-1"])

    def test_remote_shell_is_hidden_until_authentication_is_resolved(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")
        style = (root / "style.css").read_text(encoding="utf-8")
        self.assertIn('<body class="auth-required auth-pending">', markup)
        self.assertIn('id="auth-session-check"', markup)
        self.assertIn('id="login-form" hidden', markup)
        self.assertIn('classList.remove("auth-required","auth-pending")', script)
        self.assertIn('.auth-pending .topbar', style)
        self.assertIn('width: min(100%,720px)', style)
        self.assertIn('class="target-scroll-list"', script)
        self.assertIn('data-target-search', script)
        self.assertIn("function targetSearchScore", script)

        self.assertIn("label.startsWith(query)", script)
        self.assertIn("meta.includes(query)", script)
        self.assertNotIn("Blocage ponctuel · durée", script)
        self.assertNotIn("Blocage ponctuel · date", script)
        self.assertNotIn("Blocage permanent · durée", script)
        self.assertNotIn("Blocage permanent · date", script)
        self.assertIn('id="computer-duration-form"', markup)
        self.assertIn('mode:"duration"', script)
        self.assertIn('delay_seconds:0', script)
        self.assertIn('mode:"daily_duration"', script)
        self.assertIn('mode:"absolute_range"', script)
        self.assertIn('saveOneTimeTargetQuota', script)
        self.assertIn('limitDraft.block_during_validity=false', script)
        self.assertIn('limitDraft.limit_seconds=duration_seconds', script)
        self.assertIn('limitDraft.valid_until_time="23:59"', script)
        self.assertNotIn('saveTimedTargetDurationLimit', script)
        self.assertIn("create_new:!limitDraft.editing", script)
        self.assertIn("target_key:limitDraft.editing?limitDraft.limit_key:limitDraft.target_key", script)
        self.assertIn("limitKey=item.key||item.target_key", script)
        self.assertIn("function isLimitTimeAlert", script)
        self.assertIn("limit-alert", script)
        self.assertIn("Temps additionnel actif", script)
        self.assertIn(".bar.warning i", style)
        self.assertIn("@keyframes limitPulse", style)
        self.assertNotIn('data-limit-validity="period"', markup)
        self.assertIn('id="limit-valid-from"', markup)
        self.assertIn('id="limit-valid-from-time"', markup)
        self.assertIn('id="limit-valid-until"', markup)
        self.assertIn('id="limit-valid-until-time"', markup)
        self.assertIn('id="computer-range-start-time"', markup)
        self.assertIn('id="computer-range-end-time"', markup)
        self.assertIn('mode:"schedule"', script)
        self.assertIn('valid_from:limitDraft.valid_from', script)
        self.assertIn('valid_from_time:limitDraft.valid_from_time', script)
        self.assertIn('valid_until:limitDraft.valid_until', script)
        self.assertIn('valid_until_time:limitDraft.valid_until_time', script)
        self.assertIn('id="notification-warning-form"', markup)
        self.assertIn('id="notification-warning-menu"', markup)
        self.assertIn('id="notification-warning-submit"', markup)
        for unit_select in ("limit-custom-unit", "notification-warning-unit", "default-limit-warning-unit"):
            self.assertIn(f'id="{unit_select}"', markup)
        self.assertIn('value="minutes">Minutes', markup)
        self.assertIn('value="hours">Heures', markup)
        self.assertIn("durationFieldsSeconds", script)
        self.assertIn('function stateToggle(kind,id,enabled,canManage)', script)

        self.assertIn(
            'stateToggle("computer-block",key,enabled,canManage&&canManageBlock&&!block.expired)',
            script,
        )
        self.assertIn('action:"set_computer_block_enabled",...(block_id?{block_id}:{})', script)
        self.assertIn('button.dataset.computerBlockToggle', script)
        self.assertIn('set_computer_block_enabled', script)
        self.assertIn('button.dataset.notificationToggle', script)
        self.assertIn('.state-toggle.enabled', style)
        self.assertIn('.state-toggle.disabled', style)
        self.assertIn('data-notification-warning-add', script)
        self.assertIn('+ Ajouter une durée', script)
        self.assertIn('data-notification-warning-manage', script)
        self.assertIn('Préavis enregistrés : ${warningValues}', script)
        self.assertIn('data-notification-warning-group-remove', script)
        self.assertIn('updateNotificationWarningGroup', script)
        self.assertIn('showNotificationWarningManager()', script)
        self.assertIn('Le joker doit durer au moins 5 min', script)

    def test_usage_analysis_search_includes_categories_web_and_multimedia(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")

        self.assertIn('<strong>Par usage</strong>', markup)
        self.assertIn('Catégories, applications, Internet et multimédia', markup)
        self.assertIn('const applications=new Map(),categories=new Map(),multimedia=new Map()', script)
        self.assertIn('for(const entry of day.passive||[])', script)
        self.assertIn('choice.kind==="multimedia"', script)
        self.assertIn('item.kind==="multimedia"', script)
        self.assertIn('Taper une catégorie, application, site ou média', script)
        self.assertIn('"application","site","multimedia"', script)

    def test_secondary_tab_actions_are_progressive_and_stay_at_the_top(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")

        analysis = markup.index('<section id="analysis"')
        analysis_action = markup.index('id="new-analysis"', analysis)
        history = markup.index('id="history-chart"', analysis)
        self.assertLess(analysis_action, history)
        self.assertIn('id="analysis-stats-panel" class="analysis-section stats-section progressive-panel" hidden', markup)
        self.assertIn('id="analysis-timeline-panel" class="analysis-section progressive-panel" hidden', markup)
        self.assertIn('<strong>Par usage</strong>', markup)
        self.assertIn('data-analysis-type="timeline"', markup)
        self.assertNotIn('<strong>Session Windows</strong><small>Frise chronologique détaillée</small>', markup)
        self.assertIn('id="new-limit" class="primary"', markup)
        self.assertIn('id="limit-type-menu" class="choice-list analysis-choice-list" hidden', markup)
        self.assertNotIn('id="new-computer-block"', markup)
        self.assertIn('id="limit-workflow"', markup)
        self.assertIn('id="notification-workflow"', markup)
        self.assertNotIn('id="analysis-stats-form"', markup)
        self.assertNotIn('id="period-form"', markup)
        self.assertNotIn('.filter(rule=>!rule.mandatory)', script)
        self.assertIn("function toggleChoiceMenu", script)

    def test_requested_settings_sections_analysis_order_and_limit_warning(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")

        self.assertNotIn("Glissez une catégorie avant ou après", markup)
        for heading in ("Options générales", "Utilisateurs", "Valeurs par défaut"):
            self.assertIn(f">{heading}<", markup)
        self.assertIn('id="default-limit-warning"', markup)
        self.assertIn('id="limit-custom-form"', markup)
        self.assertLess(markup.index('id="analysis-stats-panel"'), markup.index('id="history-chart"'))
        self.assertLess(markup.index('id="analysis-timeline-panel"'), markup.index('id="history-chart"'))
        self.assertIn("showLimitWarningStep", script)
        self.assertIn('action:"set_default_limit_warning"', script)

    def test_limit_scope_and_workflow_cancellation_are_explicit(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")

        self.assertNotIn('id="limit-scope-menu"', markup)
        self.assertNotIn('data-limit-target-type=', markup)
        for workflow in ("analysis", "notification"):
            self.assertIn(f'data-workflow-cancel="{workflow}"', markup)
        self.assertIn("function cancelWorkflow", script)
        self.assertIn("function targetHierarchy()", script)
        self.assertIn('target_key:`category:${name}`', script)
        self.assertIn('startTargetSelector("limit")', script)
        self.assertIn('startTargetSelector("notification")', script)
        self.assertIn('event.key!=="Escape"', script)
        limit_workflow = markup[
            markup.index('id="limit-workflow"'):
            markup.index('id="limits-list"')
        ]
        self.assertNotIn("Annuler", limit_workflow)
        self.assertIn(
            '<button id="remote-mutation-cancel" type="button">Annuler</button>',
            markup,
        )
        self.assertGreaterEqual(markup.count("Retour"), 10)
        self.assertNotIn('class="workflow-toolbar"', markup)
        self.assertIn('data-target-tree-back', script)

    def test_duration_inputs_are_direct_and_internal_root_is_hidden(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")

        self.assertIn("Tout l’ordinateur", script)
        self.assertIn("Catégories / applications / Internet / multimédia", script)
        self.assertIn("Permanente", script)
        self.assertIn("Quota quotidien avant blocage", script)
        self.assertIn("Créneau horaire récurrent", script)
        self.assertIn("Heure de début", markup)
        self.assertIn("Heure de fin", markup)
        self.assertNotIn('id="computer-block-duration"', markup)
        self.assertNotIn('data-limit-duration="30"', markup + script)
        self.assertNotIn('data-limit-extension="5"', markup + script)
        self.assertNotIn('data-limit-warning="5"', markup + script)
        self.assertIn('filter(category=>category!=="__root__")', script)
        self.assertIn('id="limit-cutoff-time"', markup)
        self.assertIn('blocked_after:limitDraft.block_during_validity?"":limitDraft.blocked_after', script)
        self.assertNotIn('id="limit-schedule-date"', markup)
        self.assertIn('id="limit-valid-from"', markup)
        self.assertIn('id="limit-valid-until"', markup)
        self.assertIn('id="limit-schedule-start"', markup)
        self.assertIn('if(start&&start===end)', script)
        self.assertIn('if(start_time===end_time)', script)
        self.assertNotIn('start&&start>=end', script)
        self.assertNotIn('start_time>=end_time', script)
        self.assertIn('permanentDaily=["schedule","daily_duration"].includes(block.mode)&&!block.valid_from&&!block.valid_until', script)
        self.assertIn('"Blocage quotidien récurrent"', script)
        self.assertIn('class="limit-details"', script)
        self.assertIn('limitDetail("Concerne",limitAffectedScope(item,data))', script)
        self.assertIn('limitDetail("Concerne",limitAffectedScope(block))', script)
        self.assertIn("function limitAffectedScope", script)
        self.assertIn('limitDetail("Demande"', script)
        self.assertIn("function limitAuthor", script)
        author = script.split("function limitAuthor", 1)[1].split(
            "function policyDeviceName", 1
        )[0]
        self.assertNotIn("personal_policy", author)
        self.assertNotIn("policy.updated_at", author)
        self.assertIn("item.requested_by||item.actor", author)
        self.assertIn("item.requested_at||item.updated_at", author)
        self.assertIn("function visibleLimitActor", script)
        self.assertNotIn("Politique enregistrée par", script)
        self.assertIn("function limitStateControls", script)
        self.assertIn('class="limit-state-badge"', script)
        self.assertIn('label:"Planifiée"', script)
        self.assertNotIn('En attente de sa période', script)

    def test_list_back_buttons_are_rendered_first_and_distinct(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")
        style = (root / "style.css").read_text(encoding="utf-8")

        analysis_menu = markup.split('id="analysis-type-menu"', 1)[1].split("</div>", 1)[0]
        self.assertLess(analysis_menu.index("choice-back"), analysis_menu.index("data-analysis-type"))
        self.assertIn("function limitPeriodicityChoices", script)
        self.assertIn("data-limit-basis", script)
        self.assertIn("startTargetSelector(\"analysis\")", script)
        self.assertIn("...(data.categories||[])", script)
        self.assertIn("data.daily_stats?.length?data.daily_stats:[{usage:data.usage||[],passive:data.passive||[]}]", script)
        self.assertIn("if(!analysisHistory)await loadAnalysis()", script)
        self.assertIn("startLimitForKnownTarget", script)
        self.assertIn('activateTab("limits")', script)
        self.assertIn('innerHTML=`<button class="choice-back" data-target-tree-back>', script)
        self.assertIn(".choice-list .choice-back", style)
        self.assertIn(".workflow-input-form button[data-limit-back]", style)
        self.assertIn("order: -1", style)
        self.assertIn('id="limit-schedule-end"', markup)
        self.assertIn('valid_from:limitDraft.valid_from', script)
        self.assertIn('valid_until:limitDraft.valid_until', script)
        self.assertIn('block_during_validity:!!limitDraft.block_during_validity', script)
        self.assertIn('if(limitDraft.block_during_validity&&limitTargetType!=="computer")saveLimitDraft()', script)
        self.assertIn('id:"folder:unclassified",label:"Applications non classées"', script)
        self.assertIn('(root?root.children:unclassified.children).push(leaf)', script)
        self.assertIn('Durée quotidienne', markup + script)
        self.assertIn('Temps autorisé par jour', markup + script)
        self.assertIn('id="limit-custom-unit"', markup)
        self.assertNotIn('Aucune limite. Ajoutez-en une pour commencer.', script)

    def test_client_update_requires_an_explicit_visible_action(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")
        style = (root / "style.css").read_text(encoding="utf-8")

        self.assertIn("Mise à jour téléchargée uniquement après votre confirmation", markup)
        self.assertIn("Version et mise à jour", markup)
        self.assertIn('id="client-version-current"', markup)
        self.assertIn('id="client-version-available"', markup)
        self.assertIn("Télécharger et mettre à jour", markup)
        self.assertIn('id="client-update-progress"', markup)
        self.assertIn('id="client-update-notes"', markup)
        self.assertIn('update_available:"Mise à jour disponible"', script)
        self.assertIn('data.manifest?.notes', script)
        self.assertIn('Notes de version : ${releaseNotes}', script)
        self.assertIn('current.textContent=data.current_version||"inconnue"', script)
        self.assertIn('available.textContent=data.available_version||"Aucune"', script)
        self.assertIn(
            'section=$(page==="backend"?"#backend-traffic-section"', script
        )
        self.assertIn('button.hidden=!actionable', script)
        self.assertIn('if(!remoteMode)await loadClientUpdate()', script)
        self.assertIn('if(appReady&&!remoteMode)loadClientUpdate()', script)
        self.assertIn('confirm("La mise à jour va fermer la PWA locale', script)
        self.assertIn('alert("La mise à jour a démarré.', script)
        self.assertIn("window.close()", script)
        self.assertNotIn('button.hidden=data.state!=="ready"||data.mandatory', script)
        self.assertEqual(markup.count('class="settings-card-intro"'), 4)
        self.assertIn(
            ".settings-card-intro { display: grid; gap: 2px; min-width: 0; }",
            style,
        )

    def test_limits_and_notifications_use_single_complete_editors(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")
        style = (root / "style.css").read_text(encoding="utf-8")

        for editor in ("limit", "notification"):
            self.assertIn(f'id="{editor}-editor-dialog"', markup)
            self.assertIn(f'id="{editor}-editor-form"', markup)
            self.assertIn(f'id="{editor}-editor-summary"', markup)
            self.assertIn(f'id="{editor}-editor-cancel" type="button"', markup)
            self.assertIn(
                f'$("#{editor}-editor-form").onsubmit=submitComplete', script
            )

        self.assertIn('$("#new-limit").onclick=()=>openCompleteLimit()', script)
        self.assertIn(
            '$("#new-notification").onclick=()=>openCompleteNotification()',
            script,
        )
        self.assertIn('openLimit=openCompleteLimit', script)
        self.assertIn('openNotification=openCompleteNotification', script)
        self.assertIn('startLimitForKnownTarget=targetKey=>', script)
        self.assertIn('showNotificationWarningManager=()=>', script)

        for field in (
            "person", "scope-summary", "scope-devices", "delete-after",
            "target", "periodicity", "basis", "enabled", "enforcement-action",
            "duration-value", "extension-value", "joker-section", "joker-help",
            "valid-from", "valid-until", "schedule-start", "schedule-end", "cutoff",
        ):
            self.assertIn(f'id="limit-editor-{field}"', markup)
        self.assertIn('<label>Action<select id="limit-editor-enforcement-action">', markup)
        self.assertIn('<input id="limit-editor-enabled" type="hidden"', markup)
        self.assertNotIn('LIMITATION ACTIVE', markup.upper())
        self.assertIn("function renderCompleteLimitScope()", script)
        self.assertIn('id="limit-editor-device-menu" class="scope-checklist limit-editor-scope-checklist"', markup)
        self.assertIn('selectedDevices.map(deviceDisplayName).join', script)
        self.assertIn("function selectedLimitEditorDeviceIds()", script)
        self.assertIn("_policy_username:username,_device_ids:deviceIds", script)
        self.assertNotIn(
            "une limitation créée depuis une PWA locale ne concerne que son ordinateur",
            markup,
        )
        self.assertNotIn(
            "Le même périmètre est disponible depuis cette PWA, "
            "qu’elle soit ouverte localement ou à distance",
            markup,
        )
        self.assertEqual(markup.count('data-limit-editor-reset="'), 5)
        for section in ("target", "duration", "joker", "validity", "schedule"):
            self.assertIn(
                f'data-limit-editor-reset="{section}">Reset</button>', markup,
            )
        self.assertIn("function resetLimitEditorSection(section)", script)
        self.assertIn("button?.dataset.limitEditorReset", script)
        self.assertIn(".complete-editor-section-head", style)
        self.assertIn(".complete-editor-reset", style)
        for mode in ("duration", "daily_duration", "absolute_range", "schedule"):
            self.assertIn(f'"{mode}"', script)
        self.assertIn('action:"set_limit"', script)
        self.assertIn('action:"set_computer_block"', script)
        self.assertIn('data-limit-edit="${encodeURIComponent(key)}"', script)
        self.assertIn('return blockId?`computer:${blockId}`', script)

        for field in (
            "kind", "warning-rule", "description", "enabled",
            "target", "threshold-mode", "duration-value", "after-time",
            "percent", "warning-value", "subject-roles-row", "weekdays-row",
            "custom-message-enabled", "custom-message-row",
            "validity-enabled", "email",
        ):
            self.assertIn(f'id="notification-editor-{field}"', markup)
        for kind in (
            "limited_app_start", "limit_change", "limit_warning",
            "limit_reached", "limit_extension", "pwa_login", "access_change",
            "client_connected", "client_disconnected", "computer_state",
            "protection_interrupted", "usage_threshold", "startup_reminder",
        ):
            self.assertIn(f'["{kind}"', script)
        notification_kinds = script.split(
            "const completeNotificationKinds=[", 1
        )[1].split("];", 1)[0]
        self.assertNotIn('computer_block_warning', notification_kinds)
        self.assertNotIn('computer_block_change', notification_kinds)
        self.assertIn("function normalizedNotificationRules(rules)", script)
        self.assertIn('action:"set_notification_rule"', script)
        self.assertNotIn('id="limit-editor-warning-row"', markup)
        self.assertNotIn('id="notification-editor-label"', markup)
        self.assertNotIn('id="notification-editor-login-role"', markup)
        self.assertIn('subject_roles:subjectRoles', script)
        self.assertIn('if(button.dataset.limitEdit)openLimit(', script)
        self.assertIn('if(button.dataset.notificationEdit)openNotification(', script)
        self.assertIn('class="complete-editor-dialog"', markup)
        self.assertIn('.complete-editor-grid', style)
        self.assertIn('@media (max-width: 680px)', style)

        self.assertIn('id="remote-mutation-dialog"', markup)
        self.assertIn('id="remote-mutation-progress"', markup)
        self.assertIn('id="remote-mutation-cancel"', markup)
        self.assertIn('$("#remote-mutation-cancel").onclick=cancelRemoteMutation', script)

    def test_remote_admin_can_download_a_transactional_database_backup(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")

        self.assertIn('data-settings-page="backup"', markup)
        self.assertIn('id="backup-settings-section"', markup)
        self.assertIn('id="download-database-backup"', markup)
        self.assertIn("créée transactionnellement par SQLite", markup)
        self.assertIn("backup:remoteMode&&isAdmin", script)
        self.assertIn("async function downloadDatabaseBackup", script)
        self.assertIn('"X-CSRF-Token":authState.csrf_token', script)
        self.assertIn('/api/v1/admin/database/backup', script)
        self.assertIn("URL.revokeObjectURL", script)

    def test_remote_limits_show_person_and_per_device_link_state(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")
        style = (root / "style.css").read_text(encoding="utf-8")

        self.assertNotIn('id="limits-person-title"', markup)
        self.assertNotIn('`Limitations de ${selectedPolicyUsername}`', script)
        self.assertIn('id="limit-person-scope"', markup)
        self.assertIn('function updatePersonScopeVisibility', script)
        self.assertIn('showQueuedPersonalPolicy(queued.policy)', script)
        self.assertIn('Maillon fermé — synchronisé', script)
        self.assertIn('Maillon ouvert — en attente de synchronisation', script)
        self.assertIn('async function executeDeferredDeviceMutation', script)
        self.assertIn('mutation.kind==="deferred"?executeDeferredDeviceMutation', script)
        self.assertIn('Limitation enregistrée · application en arrière-plan', script)
        self.assertIn('saved.computer_block_policy', script)
        self.assertIn('showQueuedComputerBlockPolicy', script)
        self.assertNotIn('computer_block_policy_devices', script)
        self.assertIn('function policyDeviceLinks', script)
        self.assertIn('function linkStateIcon', script)
        self.assertIn('function renderLimitDeviceLinks', script)
        self.assertIn('function refreshLimitDeviceLinksSoon', script)
        self.assertIn('refreshLimitDeviceLinksSoon();', script)
        self.assertIn('policy_devices:policyDeviceLinks(policy,source)', script)
        self.assertIn('${renderLimitDeviceLinks(block)}${controls}', script)
        self.assertIn('label:"Périmée"', script)
        self.assertIn('La période est périmée. Utilisez Modifier', script)
        self.assertIn('function limitExpired', script)
        self.assertIn('Number(limitExpired(left))-Number(limitExpired(right))', script)
        self.assertIn('${expired?"expired":""}', script)
        self.assertIn('canManageItem&&!expired', script)
        self.assertIn('status=block.expired?{label:"Périmée"', script)

    def test_local_and_remote_pwa_use_the_same_accessible_device_scope(self):
        root = Path(__file__).parents[1] / "pwa"
        script = (root / "app.js").read_text(encoding="utf-8")
        markup = (root / "index.html").read_text(encoding="utf-8")
        style = (root / "style.css").read_text(encoding="utf-8")

        self.assertIn("const centralizedMode = () => remoteMode || federatedBackend", script)
        self.assertIn("async function loadDeviceScope(){let data;try", script)
        self.assertIn("data=await api(\"/api/v1/devices\")", script)
        self.assertIn("async function loadPolicyScope(){", script)
        self.assertIn("data=await api(\"/api/v1/policies\")", script)
        self.assertNotIn("if(!remoteMode)return renderLocalDeviceScope()", script)
        self.assertNotIn("if(!remoteMode)return [localDeviceId]", script)
        self.assertNotIn("Ordinateurs concernés 1/1", markup)
        self.assertIn(
            "_policy_username:username,_device_ids:deviceIds", script,
        )
        self.assertIn("personSelectedDeviceIds()", script)
        self.assertIn("notificationTargetDeviceIds()", script)
        self.assertIn("federatedBackendOnline=false", script)
        self.assertIn(
            "Serveur central indisponible · ce PC reste pilotable", script,
        )
        self.assertIn("deviceInventoryKey", script)
        self.assertIn(".slice(0,64)", script)
        self.assertNotIn("device_token", script.split(
            "function cacheDeviceInventory", 1,
        )[1].split("function cachePolicyInventory", 1)[0])
        self.assertIn('class="limit-card computer-block-card ${enabled?"":"disabled"} ${block.expired?"expired":""}"', script)
        self.assertIn('.limit-device-sync', style)
        self.assertIn('.link-state-icon', style)
        self.assertIn('.limit-card.expired', style)
        self.assertIn('.limit-card.disabled:not(.expired)', style)
        self.assertIn('.limit-card.expired .limit-actions button', style)
        self.assertNotIn('function limitScopeLock()', script)
        self.assertNotIn('🔒', script)
        self.assertNotIn('.limit-scope-lock', style)

    def test_today_timeline_uses_person_policy_for_every_selected_computer(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        self.assertIn("function personalPolicyTimelineOverview", script)
        self.assertIn("personalPolicyTimelineOverview(await api", script)
        self.assertIn("data=await personalPolicyOverview(data)", script)

    def test_timeline_limit_uses_measured_target_and_active_schedule(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        start = script.index("function timelineItemLimited")
        end = script.index("function renderRunTimeline", start)
        function = script[start:end]
        source = f"""
function metadataForTarget(){{return {{category:"Programmation"}}}}
function categoryLineage(){{return ["Programmation"]}}
{function}
const item={{key:"app:codex",label:"Codex"}};
const hashed={{limits:[{{key:"category:Programmation#copie",target_key:"category:Programmation",enabled:true,schedule_active:true}}]}};
const inactive={{limits:[{{key:"category:Programmation#copie",target_key:"category:Programmation",enabled:true,schedule_active:false}}]}};
const computer={{computer_block:{{enabled:true,active:true}},limits:[]}};
console.log(JSON.stringify([
  timelineItemLimited(hashed,item),
  timelineItemLimited(inactive,item),
  timelineItemLimited(computer,item),
]));
"""
        completed = subprocess.run(
            ["node", "-e", source], check=True, capture_output=True, text=True
        )

        self.assertEqual(json.loads(completed.stdout), [True, False, True])

    def test_limit_list_does_not_repeat_notification_warning_duration(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        renderer = script.split("function renderLimits(data)", 1)[1].split(
            "const renderApplicationLimits", 1
        )[0]
        self.assertNotIn("Préavis", renderer)

    def test_expired_computer_block_keeps_device_links_and_can_be_edited(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        start = script.index("function computerBlockFromPolicy")
        end = script.index("function showQueuedPersonalPolicy", start)
        function = script[start:end]
        source = f"""
function policyDeviceLinks(policy){{return (policy.devices||[]).map(device=>({{name:device.device_id,linked:device.applied_revision>=policy.revision}}))}}
{function}
const policy={{revision:2,updated_at:"2020-01-01T08:00:00Z",actor:"admin",devices:[{{device_id:"pc-1",applied_revision:2}},{{device_id:"pc-2",applied_revision:1}}],block:{{mode:"absolute_range",enabled:true,device_ids:["pc-1","pc-2"],valid_from:"2020-01-01",valid_from_time:"10:00",valid_until:"2020-01-01",valid_until_time:"11:00"}}}};
console.log(JSON.stringify(computerBlockFromPolicy(policy,new Date("2020-01-01T12:00:00"))));
"""
        completed = subprocess.run(
            ["node", "-e", source], capture_output=True, text=True, check=True
        )
        block = json.loads(completed.stdout)
        self.assertTrue(block["expired"])
        self.assertFalse(block["active"])
        self.assertFalse(block["pending"])
        self.assertEqual(
            block["policy_devices"],
            [
                {"name": "pc-1", "linked": True},
                {"name": "pc-2", "linked": False},
            ],
        )

    def test_classification_is_a_complete_catalog_with_manual_creation(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")

        self.assertIn('id="catalog-add"', markup)
        self.assertIn('id="catalog-search-form"', markup)
        self.assertIn('list="catalog-search-options"', markup)
        self.assertNotIn('id="catalog-trace-filter"', markup)
        self.assertNotIn("Toutes les traces", markup)
        self.assertIn('id="classification-loading"', markup)
        self.assertIn("function classificationCatalog", script)
        self.assertIn('data-dismiss-program=', script)
        self.assertIn('action:"dismiss_target"', script)
        self.assertIn("Son historique et ses limites seront conservés", script)
        self.assertIn("catalogMutation?classificationDeviceIds():personSelectedDeviceIds()", script)
        self.assertIn("const deviceIds=classificationDeviceIds()", script)
        excluded_start = script.index('if(item.kind==="excluded-target")')
        self.assertIn(
            'action:"delete_target"', script[excluded_start:excluded_start + 700],
        )
        self.assertIn("dismissed_targets||{}", script)
        self.assertIn("function isBrowserEntry", script)
        self.assertIn("site&&!generalCategory", script)
        self.assertIn("function siteTreeCategory", script)
        self.assertIn('function classificationDeviceIds()', script)
        self.assertIn('const deviceIds=classificationDeviceIds()', script)
        self.assertIn('Promise.all(deviceIds.map', script)
        self.assertIn('mergeClassificationCatalogs(results.map', script)
        self.assertIn("classificationCache = new Map()", script)
        self.assertNotIn("const history=await loadAnalysis({force})", script)
        self.assertIn("data.merge_candidates||[]", script)
        self.assertIn('{catalog:true}', script)
        self.assertIn("function openCatalogAddDialog", script)
        self.assertIn('action:"add_catalog_item"', script)
        self.assertIn('placeholder="exemple.exe"', script)
        self.assertIn("Aucun temps d’usage n’est ajouté", script)
        self.assertIn('time=catalog?""', script)
        self.assertIn('time.textContent=catalog?""', script)
        self.assertIn('$("#catalog-add").hidden=!hasAccess("manage_activity")', script)
        self.assertIn("function classificationSearchEntries", script)
        self.assertIn("function showClassificationSearchResult", script)
        self.assertIn('row.scrollIntoView({behavior:"smooth",block:"center"})', script)

    def test_today_timeline_metrics_use_interval_unions(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        self.assertIn('catalogIntervalUnionSeconds(measuredIntervals("active"))', script)
        self.assertIn('Math.min(todaySeconds,catalogIntervalUnionSeconds', script)

    def test_classification_unifies_computers_without_browser_category_winning(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        browser_start = script.index("function browserApplicationNames")
        browser_end = script.index("function browserNameForItem", browser_start)
        merge_start = script.index("function classificationCatalogScore")
        merge_end = script.index("function applyClassificationCatalog", merge_start)
        category_start = script.index("function classificationCategoryNames")
        category_end = script.index("function categoryOptions", category_start)
        functions = (
            script[browser_start:browser_end]
            + script[merge_start:merge_end]
            + script[category_start:category_end]
        )
        source = f"""
let catalogState=null,state=null;
function analysisFirstValues(histories,field,key=value=>String(value)){{const values=new Map();for(const history of histories){{for(const value of history[field]||[]){{const identity=key(value);if(identity&&!values.has(identity))values.set(identity,value)}}}}return [...values.values()]}}
{functions}
const x20w={{categories:["Programmation+ChatGPT","Divertissement","Jeux"],top_level_categories:["Divertissement","Programmation+ChatGPT"],category_order:["Divertissement"],target_order:[],category_parents:{{Jeux:"Divertissement"}},browsers:[{{browser:"brave.exe",label:"Brave"}}],merge_candidates:[{{key:"app:chat.exe",label:"Chat",category:"Divertissement"}}]}};
const ordi1={{categories:["Programmation+ChatGPT","Divertissement","Jeux"],top_level_categories:["Programmation+ChatGPT","Divertissement"],category_order:["Programmation+ChatGPT","Divertissement","Jeux"],target_order:["app:chat.exe","app:game.exe"],category_parents:{{Jeux:"Divertissement"}},browsers:[{{browser:"brave.exe",label:"Brave"}}],merge_candidates:[{{key:"app:chat.exe",label:"Chat",category:"Programmation+ChatGPT"}},{{key:"app:game.exe",label:"Jeu",category:"Jeux"}}]}};
const merged=mergeClassificationCatalogs([x20w,ordi1],["x20w","ordi1"]);
console.log(JSON.stringify({{categories:classificationCategoryNames(merged),order:merged.category_order,targets:merged.target_order,chat:merged.merge_candidates.find(item=>item.key==="app:chat.exe").category,devices:merged.catalog_device_ids}}));
"""
        completed = subprocess.run(
            ["node", "-e", source], capture_output=True, text=True, check=True
        )
        result = json.loads(completed.stdout)
        self.assertEqual(
            result["categories"],
            ["Programmation+ChatGPT", "Divertissement", "Jeux"],
        )
        self.assertEqual(result["chat"], "Programmation+ChatGPT")
        self.assertEqual(
            result["order"],
            ["Programmation+ChatGPT", "Divertissement", "Jeux"],
        )
        self.assertEqual(result["targets"], ["app:chat.exe", "app:game.exe"])
        self.assertEqual(result["devices"], ["x20w", "ordi1"])

    def test_classification_always_loads_every_computer_for_the_person(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        line = next(
            item for item in script.splitlines()
            if item.startswith("function classificationDeviceIds")
        )
        source = f"""
const remoteMode=true;
const personDeviceCandidates=()=>[{{device_id:"pc-rich"}},{{device_id:"pc-new"}}];
const personSelectedDeviceIds=()=>["pc-new"];
{line}
console.log(JSON.stringify(classificationDeviceIds()));
"""
        completed = subprocess.run(
            ["node", "-e", source], capture_output=True, text=True, check=True
        )

        self.assertEqual(json.loads(completed.stdout), ["pc-rich", "pc-new"])

    def test_classification_prioritizes_the_person_canonical_computer(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        line = next(
            item for item in script.splitlines()
            if item.startswith("function prioritizedClassificationDeviceIds")
        )
        source = f"""
const classificationDeviceIds=()=>["pc-old","pc-canonical","pc-third"];
const selectedPersonScope=()=>({{catalog_device_id:"pc-canonical"}});
{line}
console.log(JSON.stringify(prioritizedClassificationDeviceIds()));
"""
        completed = subprocess.run(
            ["node", "-e", source], capture_output=True, text=True, check=True
        )

        self.assertEqual(json.loads(completed.stdout), [
            "pc-canonical", "pc-old", "pc-third",
        ])
        loader = script.split(
            "async function mergedClassificationCatalog", 1
        )[1].split("function overviewWithClassificationCatalog", 1)[0]
        self.assertIn("prioritizedClassificationDeviceIds()", loader)

    def test_today_timeline_keeps_the_unified_catalog_as_its_order_source(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        lines = script.splitlines()
        functions = "\n".join(
            next(line for line in lines if line.startswith(f"function {name}"))
            for name in (
                "overviewWithClassificationCatalog",
                "timelineClassificationData",
            )
        )
        source = f"""
{functions}
const catalog={{category_order:["First","Second"],merge_candidates:[{{key:"app:first",category:"First"}},{{key:"app:late",category:"Second"}}],usage:[{{key:"app:first",category:"First",seconds:1}},{{key:"app:late",category:"Second",seconds:1}}]}};
const session={{usage:[{{key:"app:late",category:"Second",seconds:1000}},{{key:"app:first",category:"First",seconds:1}}]}};
const combined=overviewWithClassificationCatalog(session,catalog);
console.log(JSON.stringify({{usesCatalog:timelineClassificationData(combined)===catalog,categoryOrder:timelineClassificationData(combined).category_order,sessionOrder:combined.usage.map(item=>item.key),firstCategory:combined.usage.find(item=>item.key==="app:first").category}}));
"""
        completed = subprocess.run(
            ["node", "-e", source], capture_output=True, text=True, check=True
        )
        result = json.loads(completed.stdout)
        self.assertTrue(result["usesCatalog"])
        self.assertEqual(result["categoryOrder"], ["First", "Second"])
        self.assertEqual(result["sessionOrder"], ["app:late", "app:first"])
        self.assertEqual(result["firstCategory"], "First")

    def test_analysis_defaults_to_person_scope_and_unions_selected_computers(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")
        style = (root / "style.css").read_text(encoding="utf-8")

        self.assertIn('id="person-device-scope"', markup)
        self.assertIn('id="person-device-list"', markup)
        self.assertIn('id="person-device-menu"', markup)
        self.assertIn('id="person-device-summary"', markup)
        self.assertIn('role="group"', markup)
        self.assertIn("personDeviceCandidates().map", script)
        self.assertIn("selectedPersonDeviceIds=new Set(ids.filter", script)
        self.assertIn("personSelectedDeviceIds().slice().sort().join", script)
        self.assertIn("function analysisHistoryMatchesDevices", script)
        self.assertIn("person-v7:", script)
        self.assertIn("if(tagged.length===1)", script)
        self.assertNotIn('id="analysis-device-scope"', markup)
        self.assertNotIn("Ordinateurs analysés", markup)
        self.assertIn("Promise.all(deviceIds.map", script)
        self.assertIn("mergeAnalysisHistories(deviceHistories,deviceIds)", script)
        self.assertIn("item.analysis_device_id!==deviceId", script)
        self.assertIn(".person-device-scope", style)
        self.assertIn(".scope-checklist > summary", style)
        self.assertIn(".scope-checklist-options", style)
        self.assertIn("max-height: 240px", style)
        self.assertIn("function visibleRemoteTodaySessionRows", script)
        self.assertIn("visibleRemoteTodaySessionRows(rows).flatMap", script)
        self.assertIn("remoteTodaySessionRowsScopeKey===scopeKey", script)
        self.assertIn("data?.current?.is_counted", script)

        start = script.index("function analysisDeviceName")
        end = script.index("function analysisHistoryCacheKey", start)
        functions = script[start:end]
        source = f"""
const localDay=value=>{{const date=new Date(value),year=date.getFullYear(),month=String(date.getMonth()+1).padStart(2,"0"),day=String(date.getDate()).padStart(2,"0");return `${{year}}-${{month}}-${{day}}`}};
const accessibleDevices=[{{device_id:"pc-1",display_name:"Bureau"}},{{device_id:"pc-2",display_name:"Portable"}}];
const deviceDisplayName=device=>device.display_name||device.device_id;
function catalogIntervalUnionSeconds(intervals){{
  const ordered=intervals.slice().sort((a,b)=>a.start-b.start);
  let total=0,start=null,end=null;
  for(const interval of ordered){{
    if(start===null){{start=interval.start;end=interval.end;continue}}
    if(interval.start<=end){{if(interval.end>end)end=interval.end;continue}}
    total+=(end-start)/1000;start=interval.start;end=interval.end;
  }}
  return total+(start===null?0:(end-start)/1000);
}}
{functions}
const histories=[
  {{daily_stats:[{{date:"2026-08-03",active:600,usage:[{{key:"app:codex",label:"Codex",seconds:600}}]}},{{date:"2026-08-27",active:1800,usage:[{{key:"app:codex",label:"Codex",seconds:1800}}]}}],merge_candidates:[{{key:"app:codex",label:"Codex"}}],sessions:[{{kind:"active",key:"app:codex",label:"Codex",started_at:"2026-08-03T10:00:00",ended_at:"2026-08-03T10:10:00"}},{{kind:"active",key:"app:codex",label:"Codex",started_at:"2026-08-27T10:00:00",ended_at:"2026-08-27T10:30:00"}}]}},
  {{daily_stats:[{{date:"2026-08-27",active:1800,usage:[{{key:"app:codex",label:"Codex",seconds:1800}}]}}],merge_candidates:[{{key:"app:codex",label:"Codex"}}],current:{{is_counted:true}},sessions:[{{kind:"active",key:"app:codex",label:"Codex",started_at:"2026-08-27T10:15:00",ended_at:"2026-08-27T10:45:00"}}]}}
];
const merged=mergeAnalysisHistories({{"pc-1":histories[0],"pc-2":histories[1]}},["pc-1","pc-2"]);
const single=mergeAnalysisHistories({{"pc-1":histories[0],"pc-2":histories[1]}},["pc-2"]);
console.log(JSON.stringify({{days:merged.daily_stats,deviceIds:merged.analysis_device_ids,sessionDevices:merged.sessions.map(item=>item.analysis_device_id),current:merged.current,single:{{days:single.daily_stats,deviceIds:single.analysis_device_ids,sessionDevices:single.sessions.map(item=>item.analysis_device_id),personAggregate:single.person_aggregate}}}}));
"""
        completed = subprocess.run(
            ["node", "-e", source], check=True, capture_output=True, text=True
        )
        result = json.loads(completed.stdout)
        self.assertEqual([item["date"] for item in result["days"]], [
            "2026-08-03", "2026-08-27",
        ])
        day = result["days"][0]
        self.assertEqual(day["active"], 600)
        self.assertEqual(day["usage"][0]["seconds"], 600)
        self.assertTrue(day["person_aggregate"])
        # The overlapping 27 August intervals are still unioned to 45 minutes.
        day = result["days"][1]
        self.assertEqual(day["active"], 2700)
        self.assertEqual(day["usage"][0]["seconds"], 2700)
        self.assertTrue(day["person_aggregate"])
        self.assertEqual(result["deviceIds"], ["pc-1", "pc-2"])
        self.assertEqual(set(result["sessionDevices"]), {"pc-1", "pc-2"})
        self.assertTrue(result["current"]["is_counted"])
        self.assertEqual(result["single"]["deviceIds"], ["pc-2"])
        self.assertEqual(result["single"]["sessionDevices"], ["pc-2"])
        self.assertFalse(result["single"]["personAggregate"])
        self.assertEqual(
            [item["date"] for item in result["single"]["days"]],
            ["2026-08-27"],
        )

    def test_analysis_history_refresh_never_drains_older_pages(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        start = script.index("function analysisClippedIntervals")
        end = script.index("async function loadAnalysis(", start)
        functions = script[start:end]
        source = f"""
const remoteMode=true;
const encodeURIComponent=globalThis.encodeURIComponent;
const wait=()=>Promise.resolve();
const $=()=>null;
const localDay=value=>new Date(value).toISOString().slice(0,10);
function catalogIntervalUnionSeconds(intervals){{const ordered=intervals.map(item=>[new Date(item.start).getTime(),new Date(item.end).getTime()]).filter(item=>item[1]>item[0]).sort((a,b)=>a[0]-b[0]);let total=0,start=0,end=0;for(const item of ordered){{if(!end||item[0]>end){{total+=Math.max(0,end-start);[start,end]=item}}else end=Math.max(end,item[1])}}return (total+Math.max(0,end-start))/1000}}
const calls=[];
async function api(path){{
  calls.push(path);
  if(path.includes("before="))return {{
    sessions:[{{record_id:"old",kind:"active",key:"app:kona",started_at:"2026-06-01T10:00:00+02:00",ended_at:"2026-06-01T10:10:00+02:00"}}],
    daily_stats:[{{date:"2026-06-01",active:600}}],
    timeline:{{start:"2026-06-01",end:"2026-06-01"}},
    history_page:{{has_more:false,next_before:"",since:"",complete:true}}
  }};
  return {{
    sessions:[{{record_id:"new",kind:"active",key:"app:kona",started_at:"2026-08-29T10:00:00+02:00",ended_at:"2026-08-29T10:10:00+02:00"}}],
    daily_stats:[{{date:"2026-08-29",active:600}}],
    timeline:{{start:"2026-08-29",end:"2026-08-29"}},
    history_page:{{has_more:true,next_before:"older-cursor",since:"",complete:false}}
  }};
}}
{functions}
(async()=>{{const history=await loadAnalysisPage("pc-1");console.log(JSON.stringify({{calls,ids:history.sessions.map(item=>item.record_id),days:history.daily_stats.map(item=>item.date),page:history.history_page}}))}})();
"""
        completed = subprocess.run(
            ["node", "-e", source], capture_output=True, text=True, check=True
        )
        result = json.loads(completed.stdout)

        self.assertEqual(len(result["calls"]), 1)
        self.assertIn("device_id=pc-1", result["calls"][0])
        self.assertNotIn("before=", result["calls"][0])
        self.assertEqual(result["ids"], ["new"])
        self.assertEqual(result["days"], ["2026-08-29"])
        self.assertTrue(result["page"]["has_more"])
        self.assertEqual(result["page"]["next_before"], "older-cursor")

    def test_analysis_catalog_merges_daily_and_raw_multimedia(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        start = script.index("function catalogIntervalUnionSeconds")
        end = script.index("function analysisApplicationIsUnclassified", start)
        functions = script[start:end]
        source = f"""
const classificationCatalog=()=>({{usage:[]}});
const categoryLineage=()=>[];
const localDay=value=>{{
  const date=new Date(value),year=date.getFullYear(),
    month=String(date.getMonth()+1).padStart(2,"0"),
    day=String(date.getDate()).padStart(2,"0");
  return `${{year}}-${{month}}-${{day}}`;
}};
{functions}
const history={{
  sessions:[{{
    kind:"multimedia",label:"Kona soundtrack",
    started_at:"2026-08-29T10:00:00+02:00",
    ended_at:"2026-08-29T10:10:00+02:00"
  }}],
  daily_stats:[{{
    date:"2026-08-29",
    passive:[{{
      label:"Kona soundtrack",seconds:600,
      open_seconds:700,launches:1
    }}]
  }}],
  category_parents:{{}}
}};
const row=analysisCatalogRows(
  history,"2026-08-29","2026-08-29"
).find(item=>item.kind==="multimedia");
console.log(JSON.stringify({{
  active:row.active,open:row.open,launches:row.launches,
  days:[...row.days]
}}));
"""
        completed = subprocess.run(
            ["node", "-e", source], capture_output=True, text=True, check=True
        )
        self.assertEqual(json.loads(completed.stdout), {
            "active": 600, "open": 700, "launches": 1,
            "days": ["2026-08-29"],
        })

    def test_analysis_catalog_unites_paginated_raw_and_daily_usage_days(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        start = script.index("function catalogIntervalUnionSeconds")
        end = script.index("function analysisApplicationIsUnclassified", start)
        functions = script[start:end]
        source = f"""
const classificationCatalog=history=>({{usage:history.usage}});
const categoryLineage=(history,category)=>category?[category]:[];
const displayLabel=(key,label)=>label||key;
const isBareBrowserApplication=()=>false;
const browserNameForItem=()=>"";
const siteMatchesBrowser=()=>false;
const isLegacyBrowserSiteCategory=()=>false;
const localDay=value=>new Date(value).toISOString().slice(0,10);
{functions}
const dates=Array.from({{length:31}},(_,index)=>
  new Date(Date.UTC(2026,7,3+index)).toISOString().slice(0,10)
);
const missingCodexDay=dates[10];
const category="Programmation+ChatGPT";
const daily_stats=dates.map((date,index)=>({{
  date,
  usage:[
    {{key:"app:chatgpt classic",label:"ChatGPT Classic",category,seconds:120}},
    ...(index===10?[]:[{{key:"app:chatgpt",label:"Codex",category,seconds:60}}])
  ],
  passive:[]
}}));
const history={{
  usage:[
    {{key:"app:chatgpt",label:"Codex",category,seconds:1800}},
    {{key:"app:chatgpt classic",label:"ChatGPT Classic",category,seconds:3720}}
  ],
  sessions:[
    {{kind:"active",key:"app:chatgpt",label:"Codex",started_at:"2026-09-01T10:00:00Z",ended_at:"2026-09-01T10:01:00Z"}},
    {{kind:"active",key:"app:chatgpt",label:"Codex",started_at:"2026-09-02T10:00:00Z",ended_at:"2026-09-02T10:01:00Z"}}
  ],
  daily_stats,
  category_parents:{{}}
}};
const rows=analysisCatalogRows(history,dates[0],dates.at(-1));
const codex=rows.find(row=>row.key==="app:chatgpt");
const neighbor=rows.find(row=>row.key==="app:chatgpt classic");
const categoryRow=rows.find(row=>row.key===`category:${{category}}`);
console.log(JSON.stringify({{
  codexDays:[...codex.days],
  neighborDays:[...neighbor.days],
  categoryDays:[...categoryRow.days],
  missingCodexDay
}}));
"""
        completed = subprocess.run(
            ["node", "-e", source], capture_output=True, text=True, check=True
        )
        result = json.loads(completed.stdout)

        self.assertEqual(len(result["codexDays"]), 30)
        self.assertNotIn(result["missingCodexDay"], result["codexDays"])
        self.assertEqual(len(result["neighborDays"]), 31)
        self.assertEqual(len(result["categoryDays"]), 31)

    def test_analysis_catalog_treats_midnight_end_as_exclusive_after_clipping(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        start = script.index("function catalogIntervalUnionSeconds")
        end = script.index("function analysisApplicationIsUnclassified", start)
        functions = script[start:end]
        source = f"""
const classificationCatalog=history=>({{usage:history.usage}});
const categoryLineage=()=>[];
const displayLabel=(key,label)=>label||key;
const isBareBrowserApplication=()=>false;
const browserNameForItem=()=>"";
const siteMatchesBrowser=()=>false;
const isLegacyBrowserSiteCategory=()=>false;
const localDay=value=>{{
  const date=new Date(value),year=date.getFullYear(),
    month=String(date.getMonth()+1).padStart(2,"0"),
    day=String(date.getDate()).padStart(2,"0");
  return `${{year}}-${{month}}-${{day}}`;
}};
{functions}
const history={{
  usage:[
    {{key:"app:boundary",label:"Boundary",seconds:1800}},
    {{key:"app:outside",label:"Outside",seconds:1800}}
  ],
  sessions:[
    {{kind:"active",key:"app:boundary",started_at:"2026-08-10T23:30:00",ended_at:"2026-08-11T00:00:00"}},
    {{kind:"active",key:"app:outside",started_at:"2026-08-09T23:30:00",ended_at:"2026-08-10T00:00:00"}}
  ],
  daily_stats:[],category_parents:{{}}
}};
const rows=analysisCatalogRows(history,"2026-08-10","2026-08-10");
const boundary=rows.find(row=>row.key==="app:boundary");
const outside=rows.find(row=>row.key==="app:outside");
console.log(JSON.stringify({{
  boundaryDays:[...boundary.days],outsideDays:[...outside.days],
  boundaryActive:boundary.active,outsideActive:outside.active
}}));
"""
        completed = subprocess.run(
            ["node", "-e", source], capture_output=True, text=True, check=True
        )
        self.assertEqual(json.loads(completed.stdout), {
            "boundaryDays": ["2026-08-10"], "outsideDays": [],
            "boundaryActive": 1800, "outsideActive": 0,
        })

    def test_analysis_catalog_counts_only_daily_bare_browser_residual(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        start = script.index("function catalogIntervalUnionSeconds")
        end = script.index("function analysisApplicationIsUnclassified", start)
        functions = script[start:end]
        source = f"""
const classificationCatalog=history=>({{usage:history.usage}});
const categoryLineage=()=>[];
const displayLabel=(key,label)=>label||key;
const isBareBrowserApplication=item=>item.key==="app:brave.exe";
const browserNameForItem=item=>String(item.key||"").split(":")[1]||"";
const siteMatchesBrowser=(item,browser)=>String(item.key||"").startsWith(`site:${{browser}}:`);
const isLegacyBrowserSiteCategory=()=>false;
const localDay=value=>new Date(value).toISOString().slice(0,10);
{functions}
const history={{
  usage:[
    {{key:"app:brave.exe",label:"Brave",seconds:250}},
    {{key:"site:brave.exe:example.test",label:"Example",seconds:200}}
  ],
  sessions:[],category_parents:{{}},
  daily_stats:[
    {{date:"2026-08-10",usage:[
      {{key:"app:brave.exe",seconds:100}},
      {{key:"site:brave.exe:example.test",seconds:100}}
    ],passive:[]}},
    {{date:"2026-08-11",usage:[
      {{key:"app:brave.exe",seconds:150}},
      {{key:"site:brave.exe:example.test",seconds:100}}
    ],passive:[]}}
  ]
}};
const browser=analysisCatalogRows(
  history,"2026-08-10","2026-08-11"
).find(row=>row.key==="app:brave.exe");
console.log(JSON.stringify({{days:[...browser.days],active:browser.active}}));
"""
        completed = subprocess.run(
            ["node", "-e", source], capture_output=True, text=True, check=True
        )
        self.assertEqual(json.loads(completed.stdout), {
            "days": ["2026-08-11"], "active": 50,
        })

    def test_analysis_cached_multi_pc_refresh_requests_one_forward_page_each(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        start = script.index("function analysisClippedIntervals")
        end = script.index("async function loadAnalysis(", start)
        functions = script[start:end]
        source = f"""
const remoteMode=true;
const encodeURIComponent=globalThis.encodeURIComponent;
const localDay=value=>new Date(value).toISOString().slice(0,10);
function catalogIntervalUnionSeconds(intervals){{const ordered=intervals.map(item=>[new Date(item.start).getTime(),new Date(item.end).getTime()]).filter(item=>item[1]>item[0]).sort((a,b)=>a[0]-b[0]);let total=0,start=0,end=0;for(const item of ordered){{if(!end||item[0]>end){{total+=Math.max(0,end-start);[start,end]=item}}else end=Math.max(end,item[1])}}return (total+Math.max(0,end-start))/1000}}
const calls=[];
async function api(path){{
  calls.push(path);
  const device=new URL("https://local.invalid"+path).searchParams.get("device_id");
  return {{
    delta_since:"2026-08-29",
    analysis_coverage:{{revision:"stable-history"}},
    sessions:[{{record_id:`new-${{device}}`,kind:"active",key:"app:kona",started_at:"2026-08-29T11:00:00+02:00",ended_at:"2026-08-29T11:01:00+02:00"}}],
    windows_sessions:[],system_events:[],daily_stats:[{{date:"2026-08-29",active:60}}],
    timeline:{{start:"2026-08-29",end:"2026-08-29"}},
    history_page:{{has_more:true,next_before:`delta-${{device}}`,since:"2026-08-29",complete:false}}
  }};
}}
const cached=device=>({{
  analysis_coverage:{{revision:"stable-history"}},
  sessions:[{{record_id:`cached-${{device}}`,kind:"active",key:"app:kona",started_at:"2026-08-29T10:00:00+02:00",ended_at:"2026-08-29T10:01:00+02:00"}}],
  windows_sessions:[],system_events:[],daily_stats:[{{date:"2026-08-29",active:60}}],
  timeline:{{start:"2026-08-29",end:"2026-08-29"}},
  history_page:{{has_more:true,next_before:`old-${{device}}`,since:"",complete:false}}
}});
{functions}
(async()=>{{
  const histories=await Promise.all(["pc-1","pc-2"].map(device=>loadAnalysisDeviceDelta(device,cached(device))));
  console.log(JSON.stringify({{
    calls,
    cursorCounts:histories.map(history=>analysisHistoryCursors(history).length),
    cursors:histories.map(history=>analysisHistoryCursors(history).map(item=>item.next_before))
  }}));
}})();
"""
        completed = subprocess.run(
            ["node", "-e", source], capture_output=True, text=True, check=True
        )
        result = json.loads(completed.stdout)

        self.assertEqual(len(result["calls"]), 2)
        self.assertTrue(all("before=" not in path for path in result["calls"]))
        self.assertEqual(
            sum("device_id=pc-1" in path for path in result["calls"]), 1,
        )
        self.assertEqual(
            sum("device_id=pc-2" in path for path in result["calls"]), 1,
        )
        self.assertEqual(result["cursorCounts"], [2, 2])
        self.assertEqual(result["cursors"], [
            ["delta-pc-1", "old-pc-1"],
            ["delta-pc-2", "old-pc-2"],
        ])

    def test_analysis_revision_change_reloads_a_backfilled_complete_summary(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        start = script.index("function analysisClippedIntervals")
        end = script.index("async function loadAnalysis(", start)
        functions = script[start:end]
        source = f"""
const encodeURIComponent=globalThis.encodeURIComponent;
const localDay=value=>new Date(value).toISOString().slice(0,10);
function catalogIntervalUnionSeconds(intervals){{const ordered=intervals.map(item=>[new Date(item.start).getTime(),new Date(item.end).getTime()]).filter(item=>item[1]>item[0]).sort((a,b)=>a[0]-b[0]);let total=0,start=0,end=0;for(const item of ordered){{if(!end||item[0]>end){{total+=Math.max(0,end-start);[start,end]=item}}else end=Math.max(end,item[1])}}return (total+Math.max(0,end-start))/1000}}
const calls=[];
const thunderbird=(date,seconds)=>({{date,active:seconds,usage:[{{key:"app:thunderbird.exe",label:"Thunderbird",seconds}}],passive:[]}});
async function api(path){{
  calls.push(path);
  const params=new URL("https://local.invalid"+path).searchParams;
  if(params.has("since"))return {{
    delta_since:"2026-08-23",analysis_coverage:{{revision:"rev-new",start:"2026-08-03"}},
    sessions:[],windows_sessions:[],system_events:[],daily_stats:[thunderbird("2026-08-23",300)],
    merge_candidates:[{{key:"app:thunderbird.exe",label:"Thunderbird"}}],
    timeline:{{start:"2026-08-23",end:"2026-09-03"}},
    history_page:{{has_more:true,next_before:"delta",since:"2026-08-23",complete:false}}
  }};
  return {{
    analysis_coverage:{{revision:"rev-new",start:"2026-08-03"}},
    sessions:[{{record_id:"full-new",kind:"active",key:"app:thunderbird.exe",started_at:"2026-09-03T10:00:00Z",ended_at:"2026-09-03T10:05:00Z"}}],
    windows_sessions:[],system_events:[],
    daily_stats:[thunderbird("2026-08-03",100),thunderbird("2026-08-22",200),thunderbird("2026-08-23",300)],
    merge_candidates:[{{key:"app:thunderbird.exe",label:"Thunderbird"}}],
    timeline:{{start:"2026-08-03",end:"2026-09-03"}},
    history_page:{{has_more:true,next_before:"restart",since:"",complete:false}}
  }};
}}
{functions}
const previous={{
  analysis_coverage:{{revision:"rev-old",start:"2026-08-22"}},
  sessions:[{{record_id:"loaded-old-page",kind:"active",key:"app:thunderbird.exe",started_at:"2026-08-22T10:00:00Z",ended_at:"2026-08-22T10:02:00Z"}}],
  windows_sessions:[],system_events:[],
  daily_stats:[thunderbird("2026-08-21",999),thunderbird("2026-08-22",20),thunderbird("2026-08-23",30)],
  merge_candidates:[{{key:"app:thunderbird.exe",label:"Thunderbird"}}],
  timeline:{{start:"2026-08-22",end:"2026-09-03"}},
  history_page:{{has_more:true,next_before:"already-advanced",since:"",complete:false}}
}};
(async()=>{{
  const history=await loadAnalysisDeviceDelta("pc-1",previous);
  console.log(JSON.stringify({{
    calls,dates:history.daily_stats.map(day=>day.date),
    thunderbirdDays:history.daily_stats.filter(day=>day.usage.some(item=>item.key==="app:thunderbird.exe"&&item.seconds>0)).length,
    aug22Seconds:history.daily_stats.find(day=>day.date==="2026-08-22")?.usage.find(item=>item.key==="app:thunderbird.exe")?.seconds,
    totalSeconds:history.usage.find(item=>item.key==="app:thunderbird.exe")?.seconds,
    timelineStart:history.timeline.start,coverage:history.analysis_coverage,
    records:history.sessions.map(item=>item.record_id),
    cursors:analysisHistoryCursors(history).map(item=>item.next_before)
  }}));
}})();
"""
        completed = subprocess.run(
            ["node", "-e", source], capture_output=True, text=True, check=True
        )
        result = json.loads(completed.stdout)

        self.assertEqual(len(result["calls"]), 2)
        self.assertIn("since=2026-08-23", result["calls"][0])
        self.assertNotIn("since=", result["calls"][1])
        self.assertEqual(result["dates"], [
            "2026-08-03", "2026-08-22", "2026-08-23",
        ])
        self.assertEqual(result["thunderbirdDays"], 3)
        self.assertEqual(result["aug22Seconds"], 200)
        self.assertEqual(result["totalSeconds"], 600)
        self.assertEqual(result["timelineStart"], "2026-08-03")
        self.assertEqual(result["coverage"], {
            "revision": "rev-new", "start": "2026-08-03",
        })
        self.assertNotIn("loaded-old-page", result["records"])
        self.assertIn("full-new", result["records"])
        self.assertEqual(result["cursors"], ["restart"])
        self.assertNotIn("already-advanced", result["cursors"])

    def test_analysis_explicit_older_action_consumes_one_page_only(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        start = script.index("async function loadOlderAnalysisPage")
        end = script.index("function mergeTimelineItems", start)
        function = script[start:end]
        source = f"""
let analysisOlderLoading=false;
const key="analysis-key",calls=[],button={{disabled:false,textContent:""}};
const previous={{history_page:{{has_more:true,next_before:"cursor-1",since:""}}}};
const entry={{key,deviceIds:["pc-1"],deviceHistories:{{"pc-1":previous}},history:{{}},savedAt:0}};
const analysisHistoryCache=new Map([[key,entry]]);
const analysisHistoryCacheKey=()=>key;
const analysisHistoryCursors=history=>[history?.history_page,...(history?.history_cursor_queue||[])].filter(item=>item?.has_more&&item?.next_before);
const updateAnalysisHistoryPagination=()=>{{}};
const $=selector=>selector==="#analysis-load-older"?button:null;
const loadAnalysisPage=async(deviceId,selection)=>{{calls.push({{deviceId,...selection}});return {{history_page:{{has_more:true,next_before:"cursor-2",since:""}}}}}};
const mergeAnalysisPage=(newer,older)=>({{...newer,...older}});
const withAnalysisHistoryCursors=(history,cursors)=>({{...history,history_page:cursors.filter(Boolean)[0]||{{has_more:false,next_before:""}}}});
const mergeAnalysisHistories=()=>({{scope:"all"}});
const writePersistentAnalysisCache=async()=>{{}};
const applyAnalysisHistory=()=>{{}};
const toast=message=>{{throw new Error(message)}};
{function}
(async()=>{{await loadOlderAnalysisPage();console.log(JSON.stringify({{calls,text:button.textContent}}))}})();
"""
        completed = subprocess.run(
            ["node", "-e", source], capture_output=True, text=True, check=True
        )
        result = json.loads(completed.stdout)

        self.assertEqual(result["calls"], [{
            "deviceId": "pc-1", "since": "", "before": "cursor-1",
        }])
        self.assertEqual(result["text"], "Charger une page plus ancienne")

    def test_analysis_pages_recompute_a_day_with_over_500_intervals(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        start = script.index("function analysisClippedIntervals")
        end = script.index("async function loadAnalysis(", start)
        functions = script[start:end]
        source = f"""
const remoteMode=true;
const encodeURIComponent=globalThis.encodeURIComponent;
const wait=()=>Promise.resolve();
const $=()=>null;
const localDay=value=>new Date(value).toISOString().slice(0,10);
function catalogIntervalUnionSeconds(intervals){{const ordered=intervals.map(item=>[new Date(item.start).getTime(),new Date(item.end).getTime()]).filter(item=>item[1]>item[0]).sort((a,b)=>a[0]-b[0]);let total=0,start=0,end=0;for(const item of ordered){{if(!end||item[0]>end){{total+=Math.max(0,end-start);[start,end]=item}}else end=Math.max(end,item[1])}}return (total+Math.max(0,end-start))/1000}}
const interval=index=>({{
  record_id:`record-${{index}}`,kind:"active",key:"app:kona",label:"Kona",
  started_at:new Date(Date.UTC(2026,7,29,10,0,index)).toISOString(),
  ended_at:new Date(Date.UTC(2026,7,29,10,0,index+1)).toISOString(),
  windows_sid:"S-1-5-21-1"
}});
const newer=Array.from({{length:300}},(_,index)=>interval(index+300));
const older=Array.from({{length:301}},(_,index)=>interval(index));
older[300]={{...older[300],record_id:"duplicate-other-transport"}};
const page=(sessions,hasMore,nextBefore)=>({{
  sessions,windows_sessions:[],system_events:[],
  merge_candidates:[{{key:"app:kona",label:"Kona",category:"Jeux"}}],
  daily_stats:[{{date:"2026-08-29",active:sessions.length,
    usage:[{{key:"app:kona",label:"Kona",seconds:sessions.length}}]}}],
  timeline:{{start:"2026-08-29",end:"2026-08-29"}},
  history_page:{{has_more:hasMore,next_before:nextBefore,since:"",complete:!hasMore}}
}});
{functions}
(async()=>{{const history=mergeAnalysisPage(page(newer,true,"older"),page(older,false,""));console.log(JSON.stringify({{
  rows:history.sessions.length,active:history.daily_stats[0].active,
  usage:history.daily_stats[0].usage[0].seconds,total:history.usage[0].seconds
}}))}})();
"""
        completed = subprocess.run(
            ["node", "-e", source], capture_output=True, text=True, check=True
        )
        result = json.loads(completed.stdout)

        self.assertEqual(result, {
            "rows": 600, "active": 600,
            "usage": 600, "total": 600,
        })

    def test_analysis_delta_replaces_tracking_gap_crossing_midnight(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        start = script.index("function analysisItemTouchesTail")
        end = script.index("function analysisPageRecordKey", start)
        functions = script[start:end]
        source = f"""
{functions}
const gap={{type:"tracking_gap",at:"2026-08-28T23:50:00+02:00",ended_at:"2026-08-29T00:10:00+02:00"}};
const cached={{system_events:[gap,{{type:"sleep",at:"2026-08-28T22:00:00+02:00"}}],sessions:[],windows_sessions:[],daily_stats:[],timeline:{{start:"2026-08-28",end:"2026-08-29"}}}};
const delta={{delta_since:"2026-08-29",system_events:[gap,{{type:"resume",at:"2026-08-29T00:11:00+02:00"}}],sessions:[],windows_sessions:[],daily_stats:[],timeline:{{start:"2026-08-29",end:"2026-08-29"}}}};
const merged=mergeAnalysisDelta(cached,delta);
console.log(JSON.stringify(merged.system_events));
"""
        completed = subprocess.run(
            ["node", "-e", source], capture_output=True, text=True, check=True
        )
        events = json.loads(completed.stdout)

        self.assertEqual(
            [item["type"] for item in events],
            ["sleep", "tracking_gap", "resume"],
        )
        self.assertEqual(
            sum(item["type"] == "tracking_gap" for item in events), 1,
        )

    def test_today_sessions_use_all_accessible_computers_and_ignore_stale_inventory(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        helpers_start = script.index("function todayDeviceIds")
        helpers_end = script.index("function rememberRemoteTodaySessionData", helpers_start)
        loader_start = script.index("async function loadRemoteTodaySessionRows")
        loader_end = script.index("async function completeRemoteTodaySessionRows", loader_start)
        functions = script[helpers_start:helpers_end] + script[loader_start:loader_end]
        source = f"""
let remoteMode=true;
const centralizedMode=()=>true;
const accessibleDevices=[{{device_id:"pc-1"}},{{device_id:"pc-2"}}];
const localDeviceId="local";
let remoteTodaySessionRows=[];
let remoteTodaySessionRowsAt=0;
let remoteTodaySessionRowsPromise=null;
let remoteTodaySessionRowsPromiseKey="";
let remoteTodaySessionRowsScopeKey="";
let resolvers=[];
let api=url=>new Promise(resolve=>resolvers.push({{url,resolve}}));
function remoteTodaySessionRow(device,data){{return {{device,data,sessions:data.sessions}}}}
function personalPolicyTimelineOverview(data){{return data}}
{functions}
(async()=>{{
  const stale=loadRemoteTodaySessionRows(true);
  await Promise.resolve();
  accessibleDevices.splice(1,1);
  for(const pending of resolvers)pending.resolve({{sessions:[{{started_at:"2026-08-27T10:00:00"}}]}});
  const staleRows=await stale;
  api=async url=>({{sessions:[{{started_at:"2026-08-27T11:00:00"}}]}});
  const currentRows=await loadRemoteTodaySessionRows(true);
  console.log(JSON.stringify({{
    stale:staleRows.map(row=>row.device.device_id),
    current:currentRows.map(row=>row.device.device_id),
    cached:remoteTodaySessionRows.map(row=>row.device.device_id),
    scope:remoteTodaySessionRowsScopeKey,
  }}));
}})();
"""
        completed = subprocess.run(
            ["node", "-e", source], check=True, capture_output=True, text=True
        )
        result = json.loads(completed.stdout)
        self.assertEqual(result["stale"], ["pc-1"])
        self.assertEqual(result["current"], ["pc-1"])
        self.assertEqual(result["cached"], ["pc-1"])
        self.assertEqual(result["scope"], "pc-1")

    def test_analysis_catalog_is_read_only_and_supports_requested_rankings(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")

        self.assertIn('data-analysis-type="catalog"', markup)
        self.assertNotIn('id="analysis-catalog-sort"', markup)
        self.assertNotIn('id="analysis-catalog-detail-sort"', markup)
        self.assertIn('id="analysis-loading"', markup)
        self.assertNotIn('id="analysis-history-pagination"', markup)
        self.assertNotIn('id="analysis-load-older"', markup)
        self.assertIn('data-analysis-sort-scope="${scope}"', script)
        self.assertIn('data-analysis-sort-key="${key}"', script)
        self.assertIn("function analysisCatalogRows", script)
        self.assertIn("function analysisCatalogHierarchy", script)
        self.assertIn("function analysisCatalogSummaryMarkup", script)
        self.assertIn("function analysisCatalogClassification", script)
        self.assertIn("Synthèse des catégories", script)
        self.assertIn("Détail ·", script)
        self.assertIn('id="analysis-catalog-hide-unclassified"', markup)
        self.assertIn('.analysis-catalog-unclassified input[type="checkbox"]', (root / "style.css").read_text(encoding="utf-8"))
        self.assertIn("min-height: 16px", (root / "style.css").read_text(encoding="utf-8"))
        self.assertNotIn("data-analysis-summary-toggle", script)
        self.assertIn("data-analysis-summary-select", script)
        self.assertIn('"Toutes les activités","summary:all"', script)
        self.assertIn('label:depth?`dont ${node.row.label}`', script)
        self.assertIn("function analysisCatalogRowsForSelection", script)
        self.assertIn("function renderAnalysisCatalogVolume", script)
        self.assertIn("analysisCatalogSort.summary", script)
        self.assertIn("analysisCatalogSort.detail", script)
        self.assertNotIn("analysisCatalogExpanded", script)
        self.assertNotIn("analysis-summary-leaf", script)
        self.assertIn("selectedRows=analysisCatalogRowsForSelection", script)
        self.assertIn("renderAnalysisCatalogVolume(selectedRows,start,end,selectionLabel)", script)
        self.assertIn('id="history-title"', markup)
        self.assertIn('classification:analysisCatalogClassification(row,analysisHistory)', script)
        self.assertIn('"site-category":"Catégorie de navigation"', script)
        self.assertIn("function analysisTypeBadge(row)", script)
        self.assertIn('row.kind==="multimedia"', script)
        self.assertNotIn('"summary","Multimédia","summary:multimedia"', script)
        self.assertIn('session.kind==="active"', script)
        self.assertIn('["program","web"].includes(session.kind)', script)
        self.assertIn('Math.min(100,active/open*100)', script)
        self.assertIn('openIntervals=[...recordedOpenIntervals,...activeIntervals]', script)
        self.assertIn("catalogIntervalUnionSeconds", script)
        self.assertIn('key==="days"&&!multiDay', script)
        self.assertIn('showAnalysisPanel("catalog")', script)
        self.assertIn('analysisHistoryCache = new Map()', script)
        self.assertIn('setHeavyViewLoading("#analysis",true)', script)
        self.assertIn('"Mise à jour de l’analyse…"', script)
        self.assertIn('analysisLoadingKey===key', script)
        self.assertNotIn('analysis-catalog-results" data-tree-item', markup)

    def test_uncategorized_sites_share_the_virtual_other_sites_branch(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        lines = script.splitlines()
        functions = "\n".join(
            next(line for line in lines if line.startswith(f"function {name}"))
            for name in (
                "siteTreeCategory", "browserNode", "timelineCategoryPath",
                "analysisCatalogRowsForSelection",
            )
        )
        source = f"""
const total=items=>(items||[]).reduce((sum,item)=>sum+Number(item.seconds||0),0);
const targetSiteHost=key=>String(key||"").split(":").slice(2).join(":");
const siteHostFrom=value=>String(value||"").toLowerCase();
const treeLeaf=(item,depth)=>({{id:`target:${{item.key}}`,kind:"target",label:item.label,seconds:item.seconds,depth,payload:{{target_key:item.key}},children:[]}});
const metadataForTarget=(data,key)=>data.metadata[key]||{{}};
const isLegacyBrowserSiteCategory=()=>false;
const isBrowserEntry=item=>item.category_scope!=="site";
const categoryLineage=(data,category)=>[category];
{functions}
const data={{site_categories:["Actualité"],usage:[{{key:"site:brave.exe:example.dev",category:"Programmation",category_scope:"site"}}],merge_candidates:[],other_sites:[{{browser:"brave.exe",host:"just4camper.fr",seconds:30}},{{browser:"brave.exe",host:"example.dev",seconds:60}}],metadata:{{
  "site:brave.exe:amazon.fr":{{}},
  "site:brave.exe:example.dev":{{category:"Programmation",category_scope:"site"}},
}}}};
const node=browserNode(data,[
  {{key:"site:brave.exe:amazon.fr",label:"amazon.fr",seconds:18}},
  {{key:"site:brave.exe:bbc.com",label:"bbc.com",seconds:10,site_category:"Actualité"}},
  {{key:"site:brave.exe:other-sites",label:"Autres sites",seconds:48}},
],0);
const other=node.children.find(child=>child.id==="other-sites:brave.exe");
const rows=[
  {{kind:"site",key:"site:brave.exe:amazon.fr",category_scope:"",site_category:""}},
  {{kind:"site",key:"site:brave.exe:bbc.com",category_scope:"",site_category:"Actualité"}},
  {{kind:"site",key:"site:brave.exe:example.dev",category_scope:"site",category:"Programmation",site_category:""}},
];
console.log(JSON.stringify({{
  branchLabels:node.children.map(child=>child.label),
  otherChildren:other.children.map(child=>child.label),
  timelineOther:timelineCategoryPath(data,{{key:"site:brave.exe:amazon.fr",label:"amazon.fr"}}),
  timelineGeneral:timelineCategoryPath(data,{{key:"site:brave.exe:example.dev",label:"example.dev"}}),
  selected:analysisCatalogRowsForSelection(rows,"summary:other-sites",data).map(row=>row.key),
}}));
"""
        completed = subprocess.run(
            ["node", "-e", source], capture_output=True, text=True, check=True
        )
        result = json.loads(completed.stdout)
        self.assertEqual(result["branchLabels"][-1], "Autres sites (2)")
        self.assertEqual(result["otherChildren"], ["amazon.fr", "just4camper.fr"])
        self.assertEqual(
            result["timelineOther"], ["Navigation Internet", "Autres sites"]
        )
        self.assertEqual(result["timelineGeneral"], ["Programmation"])
        self.assertEqual(
            result["selected"], ["site:brave.exe:amazon.fr"]
        )

    def test_other_site_analysis_uses_the_best_source_for_each_day(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        start = script.index("function analysisCatalogRows(")
        end = script.index("function analysisApplicationIsUnclassified", start)
        function = script[start:end]
        source = f"""
const classificationCatalog=history=>history;
const siteHostFrom=value=>String(value||"").toLowerCase();
const isBareBrowserApplication=()=>false;
const browserNameForItem=()=>"brave.exe";
const siteMatchesBrowser=()=>false;
const subtractCatalogIntervals=value=>value;
const catalogIntervalUnionSeconds=()=>0;
const catalogIntervalDays=()=>new Set();
const isLegacyBrowserSiteCategory=()=>false;
const displayLabel=(key,label)=>label||key;
const categoryLineage=()=>[];
const aggregateAnalysisRows=(rows,kind,label,key)=>({{kind,label,key,active:0,open:0,launches:0,days:new Set(),activeIntervals:[],openIntervals:[]}});
{function}
const history={{usage:[{{key:"site:brave.exe:amazon.fr",label:"amazon.fr",category_scope:""}}],sessions:[],category_parents:{{}},daily_stats:[
  {{date:"2026-08-01",usage:[{{key:"site:brave.exe:amazon.fr",seconds:10}}],other_sites:[]}},
  {{date:"2026-08-02",usage:[],other_sites:[{{browser:"brave.exe",host:"amazon.fr",seconds:20}}]}},
]}};
const row=analysisCatalogRows(history,"2026-08-01","2026-08-02").find(item=>item.key==="site:brave.exe:amazon.fr");
console.log(JSON.stringify({{active:row.active,days:[...row.days]}}));
"""
        completed = subprocess.run(
            ["node", "-e", source], capture_output=True, text=True, check=True
        )
        result = json.loads(completed.stdout)
        self.assertEqual(result["active"], 30)
        self.assertEqual(result["days"], ["2026-08-01", "2026-08-02"])
    def test_mobile_analysis_session_summary_and_readonly_toggles_are_explicit(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")
        style = (root / "style.css").read_text(encoding="utf-8")

        self.assertIn("function setSessionMetric", script)
        self.assertNotIn('id="passive-time"', markup)
        self.assertNotIn('id="passive-share"', markup)
        self.assertIn("function timelineItemLimited", script)
        self.assertIn("limited-activity", script)
        self.assertIn("readonly", script)
        self.assertIn('disabled aria-disabled="true"', script)
        self.assertIn(".run-row.limited-activity .run-present", style)
        self.assertIn(".session-total-legend span[hidden]", style)
        self.assertIn(".analysis-catalog-table { width: 100%; min-width: 0; max-width: 100%; overflow-x: auto", style)
        self.assertIn('class="progressive-action panel-action-menu" hidden', markup)
        catalog = markup.split('id="analysis-catalog-panel"', 1)[1].split("</section>", 1)[0]
        self.assertNotIn('data-analysis-back="types"', catalog)

    def test_whole_computer_limit_uses_the_same_card_vocabulary(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )

        computer_renderer = script.split("renderLimits=function(data)", 1)[1].split(
            "function renderNotifications", 1
        )[0]
        self.assertIn('title=String(block.name||"").trim()||"Ordinateur complet"', computer_renderer)
        self.assertIn("<h3>${esc(title)}</h3>", computer_renderer)
        self.assertNotIn("<h3>Limitation de l’usage de l’ordinateur</h3>", computer_renderer)
        self.assertIn("usage=durationDaily?", computer_renderer)
        self.assertIn('durationDaily?limitDetail("Utilisation",usage):""', computer_renderer)
        self.assertIn('permanentDaily=["schedule","daily_duration"].includes(block.mode)', computer_renderer)

    def test_limit_editor_distinguishes_quota_from_time_slot_blocking(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")

        self.assertIn('<select id="limit-editor-basis"><option value="duration">Durée</option><option value="date">Créneau</option></select>', markup)
        self.assertIn('<select id="limit-editor-validity-mode"><option value="permanent">Tous les jours</option><option value="period">Période</option><option value="one-time">Une seule fois</option></select>', markup)
        self.assertIn('id="limit-editor-delete-after-row"', markup)
        self.assertIn('id="limit-editor-delete-after" type="checkbox" checked', markup)
        self.assertIn('id="limit-editor-schedule-title"', markup)
        self.assertIn("Créneau interdit quotidien", script)
        self.assertIn("Fenêtre de comptage quotidienne (facultative)", script)
        self.assertIn('class="complete-editor-grid limit-editor-compact-grid"', markup)
        self.assertNotIn('id="limit-editor-progress"', markup)
        self.assertNotIn('id="limit-editor-next"', markup)
        self.assertNotIn('id="limit-editor-back"', markup)
        self.assertNotIn('data-limit-editor-choice="enforcement-action"', markup)
        self.assertNotIn('data-limit-editor-choice=', markup)
        self.assertNotIn('id="limit-editor-subtitle"', markup)
        self.assertNotIn("Tous les réglages sont réunis dans cette fenêtre.", markup)
        self.assertNotIn("Personne et ordinateurs", markup)
        self.assertNotIn("Personne à limiter<select", markup)
        self.assertNotIn("limitEditorSteps", script)
        self.assertNotIn("moveLimitEditorStep", script)
        self.assertIn("refreshCompleteLimitEditor();", script)

    def test_permanent_computer_schedules_have_no_usage_row(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        start = script.index("function limitRuleAutomaticName")
        end = script.index("function renderNotifications", start)
        renderer = script[start:end]
        source = f"""
let renderLimits,state={{}};
let rendered="";
const nodes={{
  "#limit-create":{{hidden:false}},
  "#limits-list":{{innerHTML:""}},
}};
const $=selector=>nodes[selector];
const esc=value=>String(value);
const renderApplicationLimits=()=>{{}};
const hasAccess=()=>false;
const canManageRequestedLimit=()=>false;
const pwaLocale=()=>"fr-FR";
const duration=value=>`${{Number(value)}} s`;
const limitStateControls=()=>"";
const stateToggle=()=>"";
const limitDetail=(label,value)=>value?`<dt>${{label}}</dt><dd>${{value}}</dd>`:"";
const limitAuthor=()=>"";
const limitAffectedScope=()=>"";
const renderLimitDeviceLinks=()=>"";
const isLimitTimeAlert=()=>false;
const limitExpired=()=>false;
const limitValidity=()=>"Permanente";
const displayLabel=key=>key;
{renderer}
renderLimits({{computer_block:{{mode:"schedule",enabled:true,active:false,pending:true,started_at:"2026-08-28T17:18:00+02:00",ends_at:"2026-08-28T17:20:00+02:00",daily_start:"17:18",daily_end:"17:20",valid_from:"",valid_until:""}}}});
const schedule=nodes["#limits-list"].innerHTML;
renderLimits({{computer_block:{{mode:"daily_duration",enabled:true,active:false,pending:true,started_at:"2026-08-28T00:00:00+02:00",ends_at:"2026-08-29T00:00:00+02:00",limit_seconds:3600,seconds:20,valid_from:"",valid_until:""}}}});
console.log(JSON.stringify({{schedule,quota:nodes["#limits-list"].innerHTML}}));
"""
        completed = subprocess.run(
            ["node", "-e", source], capture_output=True, text=True, check=True
        )
        result = json.loads(completed.stdout)
        self.assertIn("Permanente", result["schedule"])
        self.assertNotIn("Utilisation", result["schedule"])
        self.assertIn("17:18", result["schedule"])
        self.assertIn("17:20", result["schedule"])
        self.assertIn("Permanente", result["quota"])
        self.assertIn("Utilisation", result["quota"])

    def test_computer_block_v2_groups_two_rules_under_one_computer_card(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        start = script.index("function limitRuleAutomaticName")
        end = script.index("function renderNotifications", start)
        renderer = script[start:end]
        source = f"""
let renderLimits,state={{}};
let rendered="";
const nodes={{
  "#limit-create":{{hidden:false}},
  "#limits-list":{{innerHTML:""}},
}};
const $=selector=>nodes[selector];
const esc=value=>String(value);
const renderApplicationLimits=()=>{{}};
const hasAccess=()=>true;
const canManageRequestedLimit=()=>true;
const pwaLocale=()=>"fr-FR";
const duration=value=>`${{Number(value)}} s`;
const limitStateControls=()=>"";
const stateToggle=(kind,key)=>`toggle:${{kind}}:${{key}}`;
const limitDetail=(label,value)=>value?`<dt>${{label}}</dt><dd>${{value}}</dd>`:"";
const limitAuthor=()=>"";
const limitAffectedScope=()=>"";
const renderLimitDeviceLinks=()=>"";
const isLimitTimeAlert=()=>false;
const limitExpired=()=>false;
const limitValidity=()=>"Permanente";
const displayLabel=key=>key;
{renderer}
renderLimits({{computer_blocks:[
  {{block_id:"night",name:"Nuit",mode:"schedule",enabled:true,active:false,pending:true,started_at:"2026-08-28T22:30:00+02:00",ends_at:"2026-08-29T05:00:00+02:00",start_time:"22:30",end_time:"05:00"}},
  {{block_id:"short",name:"Test court",mode:"schedule",enabled:true,active:true,pending:false,started_at:"2026-08-28T19:30:00+02:00",ends_at:"2026-08-28T19:32:00+02:00",start_time:"19:30",end_time:"19:32"}},
]}});
console.log(nodes["#limits-list"].innerHTML);
"""
        completed = subprocess.run(
            ["node", "-e", source], capture_output=True, text=True, check=True
        )

        self.assertEqual(completed.stdout.count("limit-group-card"), 1)
        self.assertEqual(completed.stdout.count("computer-block-card"), 2)
        self.assertIn("Nuit", completed.stdout)
        self.assertIn("Test court", completed.stdout)
        self.assertIn("computer%3Anight", completed.stdout)
        self.assertIn("computer%3Ashort", completed.stdout)

    def test_limit_list_groups_every_rule_by_canonical_target(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        start = script.index("function limitListGroups")
        end = script.index("renderLimits=function(data)", start)
        grouping = script[start:end]
        source = f"""
const displayLabel=(key,label)=>label||key;
const computerBlockItems=data=>data.computer_blocks||[];
const pwaLocale=()=>"fr-FR";
{grouping}
const groups=limitListGroups({{
  limits:[
    {{key:"category:Programmation#daily",target_key:"category:Programmation",label:"Programmation"}},
    {{key:"category:Programmation#morning",target_key:"category:Programmation",label:"Programmation"}},
    {{key:"category:Divertissement",target_key:"category:Divertissement",label:"Divertissement"}},
  ],
  computer_blocks:[{{block_id:"warn",mode:"schedule"}},{{block_id:"night",mode:"schedule"}}],
}});
console.log(JSON.stringify(groups.map(group=>[group.targetKey,group.rules.length])));
"""
        completed = subprocess.run(
            ["node", "-e", source], capture_output=True, text=True, check=True
        )

        self.assertEqual(
            json.loads(completed.stdout),
            [
                ["category:Divertissement", 1],
                ["category:Programmation", 2],
                ["computer:all", 2],
            ],
        )

    def test_computer_block_v2_commands_carry_the_selected_block_id(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )

        self.assertIn(
            'form.dataset.blockId=String(current?.block_id||current?.id||"")',
            script,
        )
        self.assertIn(
            'action:"set_computer_block_enabled",...(block_id?{block_id}:{})',
            script,
        )
        self.assertIn(
            'action:"clear_computer_block",...(block_id?{block_id}:{})',
            script,
        )
        self.assertIn(
            'action:"set_computer_block",...identity,name', script,
        )

    def test_remote_permanent_schedule_tracks_the_daily_occurrence(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        lines = script.splitlines()
        functions = "\n".join(
            next(line for line in lines if line.startswith(f"function {name}"))
            for name in (
                "dailyComputerBlockOccurrence",
                "computerBlockFromPolicy",
            )
        )
        source = f"""
process.env.TZ="Europe/Paris";
const policyDeviceLinks=()=>[];
{functions}
const policy={{updated_at:"2026-08-28T17:00:00+02:00",actor:"admin",block:{{mode:"schedule",start_time:"18:18",end_time:"18:20",valid_from:"",valid_until:""}}}};
const before=computerBlockFromPolicy(policy,new Date("2026-08-28T18:17:00+02:00"));
const during=computerBlockFromPolicy(policy,new Date("2026-08-28T18:18:30+02:00"));
const after=computerBlockFromPolicy(policy,new Date("2026-08-28T18:20:01+02:00"));
const overnight={{...policy,block:{{...policy.block,start_time:"23:00",end_time:"02:00"}}}};
const night=computerBlockFromPolicy(overnight,new Date("2026-08-29T01:00:00+02:00"));
console.log(JSON.stringify({{before,during,after,night}}));
"""
        completed = subprocess.run(
            ["node", "-e", source], capture_output=True, text=True, check=True
        )
        result = json.loads(completed.stdout)

        self.assertTrue(result["before"]["pending"])
        self.assertFalse(result["before"]["active"])
        self.assertTrue(result["during"]["active"])
        self.assertFalse(result["during"]["pending"])
        self.assertTrue(result["after"]["pending"])
        self.assertIn("2026-08-29T16:18:00.000Z", result["after"]["started_at"])
        self.assertTrue(result["night"]["active"])
        self.assertIn("2026-08-28T21:00:00.000Z", result["night"]["started_at"])

    def test_optional_limit_name_is_available_persisted_and_rendered(self):
        root = Path(__file__).parents[1]
        markup = (root / "pwa" / "index.html").read_text(encoding="utf-8")
        script = (root / "pwa" / "app.js").read_text(encoding="utf-8")
        translations = (root / "pwa" / "i18n.js").read_text(encoding="utf-8")

        self.assertIn('id="limit-editor-name"', markup)
        self.assertIn('maxlength="120"', markup)
        self.assertIn('name:String(current?.name||"").trim()', script)
        self.assertIn('settings:{name,enabled:', script)
        self.assertIn('title=String(item.name||"").trim()||displayLabel', script)
        self.assertIn('title=String(block.name||"").trim()||"Ordinateur complet"', script)
        self.assertIn('"Nom de la limitation": "Limitation name"', translations)

    def test_local_editor_submits_an_unbounded_daily_block_as_schedule(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        start = script.index("async function submitCompleteLimit")
        end = script.index("function notificationKindLabel", start)
        submitter = script[start:end]
        source = f"""
const fields={{
  "#limit-editor-name":{{value:"  Nuit  "}},
  "#limit-editor-target":{{value:"computer:all"}},
  "#limit-editor-periodicity":{{value:"permanent"}},
  "#limit-editor-basis":{{value:"date"}},
  "#limit-editor-person":{{value:"nicklaus"}},
  "#limit-editor-valid-from":{{value:""}},
  "#limit-editor-valid-from-time":{{value:""}},
  "#limit-editor-valid-until":{{value:""}},
  "#limit-editor-valid-until-time":{{value:""}},
  "#limit-editor-schedule-start":{{value:"17:18"}},
  "#limit-editor-schedule-end":{{value:"17:20"}},
  "#limit-editor-duration-value":{{value:"1"}},
  "#limit-editor-duration-unit":{{value:"hours"}},
  "#limit-editor-extension-value":{{value:"15"}},
  "#limit-editor-extension-unit":{{value:"minutes"}},
  "#limit-editor-dialog":{{close:()=>{{}}}},
}};
const $=selector=>fields[selector];
const durationFieldsSeconds=()=>3600;
const completeEditorError=()=>{{}};
const action=command=>command;
const state={{settings:{{default_limit_warning_seconds:300}}}};
const limitDraft={{}};
const limitEditorUsername="nicklaus";
const localDeviceId="pc-local";
const selectedLimitEditorDeviceIds=()=>["pc-local"];
{submitter}
(async()=>{{
  const form={{reportValidity:()=>true,dataset:{{limitKey:""}}}};
  const command=await submitCompleteLimit({{preventDefault:()=>{{}},currentTarget:form}});
  console.log(JSON.stringify(command));
}})();
"""
        completed = subprocess.run(
            ["node", "-e", source], capture_output=True, text=True, check=True
        )
        command = json.loads(completed.stdout)
        self.assertEqual(command["mode"], "schedule")
        self.assertEqual(command["name"], "Nuit")
        self.assertEqual(command["start_time"], "17:18")
        self.assertEqual(command["end_time"], "17:20")
        self.assertEqual(command["valid_from"], "")
        self.assertEqual(command["valid_until"], "")

    def test_remote_warning_limit_carries_dialog_person_and_device_scope(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        start = script.index("async function submitCompleteLimit")
        end = script.index("function notificationKindLabel", start)
        submitter = script[start:end]
        source = f"""
const fields={{
  "#limit-editor-name":{{value:"Avertir divertissement"}},
  "#limit-editor-target":{{value:"category:Divertissement"}},
  "#limit-editor-periodicity":{{value:"permanent"}},
  "#limit-editor-basis":{{value:"duration"}},
  "#limit-editor-enforcement-action":{{value:"warn"}},
  "#limit-editor-person":{{value:"nicklaus"}},
  "#limit-editor-valid-from":{{value:""}},
  "#limit-editor-valid-from-time":{{value:""}},
  "#limit-editor-valid-until":{{value:""}},
  "#limit-editor-valid-until-time":{{value:""}},
  "#limit-editor-schedule-start":{{value:""}},
  "#limit-editor-schedule-end":{{value:""}},
  "#limit-editor-cutoff":{{value:""}},
  "#limit-editor-duration-value":{{value:"3"}},
  "#limit-editor-duration-unit":{{value:"hours"}},
  "#limit-editor-extension-value":{{value:"15"}},
  "#limit-editor-extension-unit":{{value:"minutes"}},
  "#limit-editor-dialog":{{close:()=>{{}}}},
}};
const $=selector=>fields[selector];
const durationFieldsSeconds=(value,unit)=>Number(value)*(unit==="hours"?3600:60);
const completeEditorError=()=>{{}};
const action=command=>command;
const state={{settings:{{default_limit_warning_seconds:300}}}};
const limitDraft={{}};
const remoteMode=true;
const limitEditorUsername="nicklaus";
const selectedLimitEditorDeviceIds=()=>["nuc","x20w"];
{submitter}
(async()=>{{
  const form={{reportValidity:()=>true,dataset:{{limitKey:""}}}};
  const command=await submitCompleteLimit({{preventDefault:()=>{{}},currentTarget:form}});
  console.log(JSON.stringify(command));
}})();
"""
        completed = subprocess.run(
            ["node", "-e", source], capture_output=True, text=True, check=True
        )
        command = json.loads(completed.stdout)

        self.assertEqual(command["action"], "set_limit")
        self.assertEqual(command["_policy_username"], "nicklaus")
        self.assertEqual(command["_device_ids"], ["nuc", "x20w"])
        self.assertEqual(command["settings"]["enforcement_action"], "warn")
        self.assertEqual(command["settings"]["limit_seconds"], 10800)
        self.assertEqual(command["settings"]["extension_seconds"], 0)


if __name__ == "__main__":
    unittest.main()
