from html.parser import HTMLParser
import json
from pathlib import Path
import unittest


class _ButtonParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.buttons = []

    def handle_starttag(self, tag, attrs):
        if tag == "button":
            self.buttons.append(dict(attrs))


class PwaDialogTest(unittest.TestCase):
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
        self.assertIn('$("#today").classList.contains("active"))load("scope=session",{live:true})', script)
        self.assertIn('$("#analysis").classList.contains("active"))refreshAnalysisActivity()', script)
        self.assertIn("function refreshTreeValues", script)
        self.assertIn('if(!live)renderRunTimeline(data,"#today-sessions")', script)
        self.assertIn("analysisHistory={...analysisHistory", script)
        self.assertNotIn("renderSelectedAnalysis({...analysisHistory,current:latest.current", script)

    def test_today_timeline_uses_usage_guard_start_as_zero(self):
        script = (Path(__file__).parents[1] / "pwa" / "app.js").read_text(
            encoding="utf-8"
        )
        self.assertIn("function renderRunTimeline", script)
        self.assertIn("Usage Guard démarre", script)
        self.assertIn("présent à 0 s", script)
        self.assertIn('data-tree-item="${timelineItemData(item)}"', script)
        self.assertIn("Ouvert, non actif", script)
        self.assertIn("Usage actif comptabilisé", script)
        self.assertIn('item.kind==="active"', script)

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

    def test_session_summary_is_one_stacked_bar_and_admin_is_manageable_locally(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")
        self.assertEqual(markup.count('class="session-total-track"'), 1)
        self.assertNotIn('class="session-measure', markup)
        self.assertIn('id="today-date" hidden', markup)
        self.assertIn('class="session-summary-head"', markup)
        self.assertIn('id="session-end"', markup)
        self.assertIn('moment(started)', script)
        self.assertIn('moment(ended)', script)
        self.assertIn('data-manage-user=', script)
        self.assertIn('/access`', script)
        self.assertIn('Chronologie ·', script)

    def test_analysis_requires_explicit_session_and_classification(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")
        self.assertNotIn("analysis-by-date", markup)
        self.assertIn('id="analysis-session-menu"', markup)
        self.assertIn('id="analysis-classification-menu"', markup)
        self.assertNotIn('id="analysis-session"', markup)
        self.assertNotIn('id="analysis-classification"', markup)
        self.assertIn("renderSelectedAnalysis", script)

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
        self.assertIn("return orderTreeByUsage(roots,data)", script)
        self.assertIn('reorderSlots(ordered,"category",data.category_order)', script)
        self.assertIn('if(data.site_category_order_manual)', script)
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
        self.assertIn('$("#general-settings-section").hidden=remoteMode', script)
        self.assertIn('$("#users-settings-section").hidden=remoteMode&&!isRemoteAdmin', script)
        self.assertIn('$("#defaults-settings-section").hidden=remoteMode', script)
        self.assertIn('$("#remote-account").hidden=!isRemoteAdmin', script)

    def test_web_targets_use_a_badge_instead_of_a_duplicate_browser_category(self):
        root = Path(__file__).parents[1] / "pwa"
        script = (root / "app.js").read_text(encoding="utf-8")
        style = (root / "style.css").read_text(encoding="utf-8")

        self.assertIn('web:item.web||String(item.key||"").startsWith("site:")', script)
        self.assertIn('<span class="web-badge">Web</span>', script)
        self.assertIn(".web-badge", style)

    def test_live_activity_highlight_does_not_pulse(self):
        style = (Path(__file__).parents[1] / "pwa" / "style.css").read_text(
            encoding="utf-8"
        )
        self.assertIn(".tree-row.current-activity", style)
        self.assertNotIn("current-activity-pulse", style)

    def test_analysis_keeps_apps_inside_their_windows_session(self):
        root = Path(__file__).parents[1] / "pwa"
        script = (root / "app.js").read_text(encoding="utf-8")
        style = (root / "style.css").read_text(encoding="utf-8")
        self.assertIn("sessionsInWindowsSession", script)
        self.assertIn("opened<start", script)
        self.assertIn("opened>=end", script)
        self.assertIn("closed>end", script)
        self.assertIn("group.periods.sort", script)
        self.assertNotIn("renderEventTimeline", script)
        self.assertIn("renderAllRunTimeline(prepared.data,selector)", script)
        self.assertNotIn("renderEventTimeline", script)
        self.assertIn("current-activity", script)
        self.assertIn("currentActivityMatches(item.key,item.label)", script)
        self.assertIn("state.current.site_host||state.current.url", script)
        self.assertIn("targetSiteHost(targetKey)", script)
        self.assertIn("refreshAnalysisActivity()", script)
        self.assertIn("*130", script)
        self.assertRegex(script, r'service-worker\.js\?v=\d+\.\d{3}')
        self.assertIn('scopeDuplicateIds(node,parentId)', script)
        self.assertIn('Sites spécifiques inactifs', script)
        self.assertIn('refreshBrowserTotals(node)', script)
        self.assertIn('function updateDragScroll(clientY)', script)
        self.assertIn('requestAnimationFrame(dragScrollStep)', script)
        self.assertIn('updateDragScroll(event.clientY)', script)
        self.assertIn('item.kind==="other-sites"&&item.target_keys', script)
        self.assertIn('target_keys:[other[0].key,...sites.map', script)
        self.assertIn('action:"reorder_category"', script)
        self.assertIn('draggedCategoryBefore', script)
        self.assertIn('drop-before', script)
        self.assertIn('data-category-position=', script)
        self.assertIn('data-site-category-position=', script)
        self.assertIn('Déplacer la catégorie', script)
        self.assertIn('function categoryPositionDialog(category)', script)
        self.assertIn('function siteCategoryPositionDialog(category)', script)
        self.assertIn('action:"reorder_site_category"', script)
        self.assertIn('Choisir la position…', script)
        self.assertIn('Avant « ${destination} »', script)
        self.assertIn('Après « ${destination} »', script)
        self.assertIn(".tree-row.branch { grid-template-columns: 22px 22px", style)
        self.assertIn("font-variant-numeric: tabular-nums; white-space: nowrap", style)
        self.assertIn('Monter dans l’affichage', script)
        self.assertIn('Descendre dans l’affichage', script)
        self.assertNotIn('function categoryMoveDialog', script)
        self.assertIn('translateY(${localDelta}px)', script)
        self.assertIn('style="height:${height}px"', script)
        self.assertIn('style="left:${left}%;width:${width}%"', script)

    def test_notification_center_offers_the_requested_events(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")
        style = (root / "style.css").read_text(encoding="utf-8")
        self.assertIn('data-tab="notifications"', markup)
        self.assertIn('id="notifications-list"', markup)
        for kind in (
            "limited_app_start", "limit_change", "limit_warning",
            "computer_block_change",
            "pwa_login", "usage_threshold",
        ):
            self.assertIn(f'data-notification-type="{kind}"', markup)
        self.assertNotIn('data-notification-type="computer_block_warning"', markup)
        self.assertNotIn('id="notification-status-menu"', markup)
        self.assertNotIn('data-notification-status=', markup)
        self.assertIn('notificationDraft.target_key="";saveNotificationDraft(true)', script)
        self.assertNotIn('data-notification-type="startup_reminder"', markup)
        self.assertIn('set_notification_warning', script)
        self.assertIn('manage_notifications', script)
        self.assertNotIn('name="warning"', script)
        self.assertIn('id="limit-target-menu"', markup)
        self.assertIn('startTargetSelector("limit")', script)
        self.assertIn('function targetHierarchy()', script)
        self.assertIn('data-target-select="computer:all"', script)
        self.assertIn('Choisir toute cette catégorie', script)
        self.assertIn('key.endsWith(":other-sites")', script)
        self.assertIn('Ouvrir les sites et leurs catégories', script)
        self.assertIn('data-limit-validity="permanent"', markup)
        self.assertIn('data-limit-validity="period"', markup)
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
        self.assertIn('stateToggle("computer-block","computer:all",enabled,canManage)', script)
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
        self.assertIn('id="new-limit" class="primary"', markup)
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
        self.assertNotIn("Annuler", markup)
        self.assertNotIn("Annuler", script)
        self.assertGreaterEqual(markup.count("Retour"), 10)
        self.assertNotIn('class="workflow-toolbar"', markup)
        self.assertIn('data-target-tree-back', script)

    def test_duration_inputs_are_direct_and_internal_root_is_hidden(self):
        root = Path(__file__).parents[1] / "pwa"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")

        self.assertIn("Tout l’ordinateur", script)
        self.assertIn("Choisir dans l’arborescence", script)
        self.assertIn("Validité permanente", markup)
        self.assertIn("Définir une période", markup)
        self.assertIn("Heure de début", markup)
        self.assertIn("Heure de fin", markup)
        self.assertNotIn('id="computer-block-duration"', markup)
        self.assertNotIn('data-limit-duration="30"', markup + script)
        self.assertNotIn('data-limit-extension="5"', markup + script)
        self.assertNotIn('data-limit-warning="5"', markup + script)
        self.assertIn('filter(category=>category!=="__root__")', script)
        self.assertIn('id="limit-cutoff-time"', markup)
        self.assertIn('blocked_after:limitDraft.blocked_after', script)
        self.assertNotIn('id="limit-schedule-date"', markup)
        self.assertIn('id="limit-valid-from"', markup)
        self.assertIn('id="limit-valid-until"', markup)
        self.assertIn('id="limit-schedule-start"', markup)
        self.assertIn('id="limit-schedule-end"', markup)
        self.assertIn('valid_from:limitDraft.valid_from', script)
        self.assertIn('valid_until:limitDraft.valid_until', script)
        self.assertIn('Durée quotidienne', markup + script)
        self.assertIn('Temps autorisé par jour', markup + script)
        self.assertIn('id="limit-custom-unit"', markup)
        self.assertNotIn('Aucune limite. Ajoutez-en une pour commencer.', script)


if __name__ == "__main__":
    unittest.main()
