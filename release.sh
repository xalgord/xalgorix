#!/usr/bin/env bash
set -euo pipefail

# ─── Xalgorix Release Script ───
# Usage:
#   ./release.sh                  # auto-bump patch (4.2.10 → 4.2.11)
#   ./release.sh 4.3.0            # explicit version
#   ./release.sh --minor          # bump minor (4.2.10 → 4.3.0)
#   ./release.sh --major          # bump major (4.2.10 → 5.0.0)
#
# The version bump is committed on a dedicated release/vX.Y.Z branch (never
# directly on main), so the PR merges cleanly without version-string conflicts.

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
MAIN_GO="$REPO_ROOT/cmd/xalgorix/main.go"
MAKEFILE="$REPO_ROOT/Makefile"
README="$REPO_ROOT/README.md"
BUILD_DIR="/tmp/xalgorix-release"

# ─── Colors ───
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[•]${NC} $*"; }
ok()    { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
die()   { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

# ─── Pre-flight checks ───
command -v go >/dev/null  || die "go not found"
command -v gh >/dev/null  || die "gh CLI not found (install: https://cli.github.com)"
command -v git >/dev/null || die "git not found"

cd "$REPO_ROOT"

# Ensure clean working tree
if [[ -n "$(git status --porcelain)" ]]; then
    die "Working tree is dirty. Commit or stash changes first."
fi

# ─── Step 0: Sync main with origin to avoid divergence ───
ORIGINAL_BRANCH="$(git branch --show-current)"
if [[ "$ORIGINAL_BRANCH" != "main" ]]; then
    info "Switching to main..."
    git checkout main
fi
info "Syncing main with origin/main..."
git pull --ff-only origin main 2>/dev/null || {
    warn "Fast-forward pull failed — trying rebase..."
    git pull --rebase origin main || die "Cannot sync main with origin. Resolve manually."
}
ok "main is in sync with origin"

# ─── Determine current version ───
CURRENT=$(grep -oP 'var version = "\K[^"]+' "$MAIN_GO")
[[ -z "$CURRENT" ]] && die "Could not parse current version from $MAIN_GO"

IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT"
info "Current version: ${CYAN}v$CURRENT${NC}"

# ─── Determine new version ───
if [[ $# -eq 0 ]]; then
    # Auto-bump patch
    NEW_VERSION="$MAJOR.$MINOR.$((PATCH + 1))"
elif [[ "$1" == "--minor" ]]; then
    NEW_VERSION="$MAJOR.$((MINOR + 1)).0"
elif [[ "$1" == "--major" ]]; then
    NEW_VERSION="$((MAJOR + 1)).0.0"
elif [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    NEW_VERSION="$1"
else
    die "Invalid argument: $1\nUsage: $0 [version|--minor|--major]"
fi

info "New version:     ${GREEN}v$NEW_VERSION${NC}"
echo ""

# ─── Confirm ───
read -rp "Proceed with release v$NEW_VERSION? [y/N] " confirm
[[ "$confirm" =~ ^[Yy]$ ]] || { warn "Aborted."; exit 0; }
echo ""

# ─── Step 1: Create release branch from main ───
RELEASE_BRANCH="release/v$NEW_VERSION"
if git rev-parse --verify --quiet "$RELEASE_BRANCH" >/dev/null; then
    warn "Branch $RELEASE_BRANCH already exists locally — refusing to overwrite. Delete it and rerun if intentional."
    die "release branch collision"
fi
info "Creating branch $RELEASE_BRANCH from main..."
git checkout -b "$RELEASE_BRANCH"
ok "On branch $RELEASE_BRANCH"

# ─── Step 2: Bump version in source (on release branch) ───
info "Bumping version in main.go..."
sed -i "s/var version = \"$CURRENT\"/var version = \"$NEW_VERSION\"/" "$MAIN_GO"
if [[ -f "$MAKEFILE" ]]; then
    sed -i "s/^VERSION=.*/VERSION=$NEW_VERSION/" "$MAKEFILE"
fi
if [[ -f "$README" ]]; then
    sed -i "s/assets\\/banner\\.png?v=$CURRENT/assets\\/banner.png?v=$NEW_VERSION/g" "$README"
fi
ok "Version bumped: $CURRENT → $NEW_VERSION"

# ─── Step 3: Build & verify ───
info "Building and verifying..."
if ! go build ./cmd/xalgorix/; then
    warn "Build failed — reverting version bump and deleting release branch"
    git checkout -- "$MAIN_GO" "$MAKEFILE" "$README"
    git checkout main
    git branch -D "$RELEASE_BRANCH"
    die "Build failed (version bump reverted, release branch deleted)"
fi
ok "Build successful"

# ─── Step 4: Build release binary ───
info "Building linux/amd64 release binary..."
mkdir -p "$BUILD_DIR"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags "-s -w -X main.version=$NEW_VERSION" \
    -o "$BUILD_DIR/xalgorix-linux-amd64" \
    ./cmd/xalgorix/
ok "Binary built: $BUILD_DIR/xalgorix-linux-amd64"

# ─── Step 5: Generate changelog (commits since last tag) ───
info "Generating changelog..."
CHANGELOG=$(git log --oneline "v$CURRENT"..HEAD 2>/dev/null | sed 's/^/- /' || echo "- Release v$NEW_VERSION")
if [[ -z "$CHANGELOG" ]]; then
    CHANGELOG="- Release v$NEW_VERSION"
fi
echo "$CHANGELOG"
echo ""

# ─── Step 6: Commit & tag (on release branch) ───
info "Committing and tagging..."
git add -A
git commit -m "release: v$NEW_VERSION"
git tag "v$NEW_VERSION"
ok "Tagged v$NEW_VERSION"

# ─── Step 7: Push release branch & tag ───
info "Pushing $RELEASE_BRANCH and tag..."
git push -u origin "$RELEASE_BRANCH"
git push origin "v$NEW_VERSION"
ok "Pushed $RELEASE_BRANCH and tag v$NEW_VERSION"

# ─── Step 8: Open PR against main ───
info "Opening PR against main..."
PR_BODY="### Changes

$CHANGELOG"
PR_URL="$(gh pr create --base main --head "$RELEASE_BRANCH" \
    --title "release: v$NEW_VERSION" \
    --body "$PR_BODY" 2>/dev/null || true)"
if [[ -z "$PR_URL" ]]; then
    warn "PR creation failed or PR already exists; check GitHub manually."
else
    ok "PR opened: $PR_URL"
fi

# ─── Step 9: Create GitHub Release ───
info "Creating GitHub Release..."
gh release create "v$NEW_VERSION" \
    "$BUILD_DIR/xalgorix-linux-amd64" \
    --title "v$NEW_VERSION" \
    --notes "### Changes

$CHANGELOG"
ok "GitHub Release created"

# ─── Step 10: Switch back to main ───
info "Switching back to main..."
git checkout main
ok "Back on main (clean — version bump lives only on $RELEASE_BRANCH)"

# ─── Cleanup ───
rm -rf "$BUILD_DIR"

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  ✅ Released v$NEW_VERSION successfully!${NC}"
echo -e "${GREEN}  https://github.com/xalgord/xalgorix/releases/tag/v$NEW_VERSION${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
