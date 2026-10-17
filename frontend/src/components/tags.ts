// Dependency-free tag class constants, shared by ui.tsx and FixPlanPanel.tsx.
// Kept out of ui.tsx so FixPlanPanel can evaluate them at module load without
// an import cycle (ui.tsx imports FixPlanPanel).
export const TAG = 'inline-flex items-center px-2 py-0.5 rounded text-style-tag'
export const TAG_REVIEW = `${TAG} bg-status-review/12 text-status-review-text`
export const TAG_MUTED = `${TAG} bg-muted text-muted-foreground`
// Mirrors design-system.html .badge--pass (status-pass at 15% + status-pass-text).
export const TAG_PASS = `${TAG} bg-status-pass/15 text-status-pass-text`
